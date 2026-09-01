"""Compliance and best-practice checks for DNS records.

The engine turns a ``DomainResult`` into a ``ComplianceReport`` by running each
configured check against ``DomainResult.unique_records``. Checks are registered
in a name -> function registry (``CHECK_REGISTRY``) so new ones can be added by
decorating a function with ``@register("name")``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from datetime import datetime, timezone

from dnstool.config import DEFAULT_CHECKS
from dnstool.dns_engine import DNSClient, DNSEngineError
from dnstool.models import (
    CheckResult,
    CheckSeverity,
    ComplianceReport,
    DNSRecord,
    DNSServerStatus,
    DomainResult,
    RecordType,
    ServerResponse,
)

CheckFn = Callable[[DomainResult], CheckResult]

#: Registry mapping a check name to its implementation ``(DomainResult) -> CheckResult``.
CHECK_REGISTRY: dict[str, CheckFn] = {}

#: DKIM selectors probed when a domain is queried fresh (best-effort coverage).
DEFAULT_DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "selector3",
    "google",
    "k1",
    "s1",
    "s2",
    "dkim",
    "mail",
]


class UnknownCheckError(ValueError):
    """Raised when a configured check name is not in the registry."""


def register(name: str) -> Callable[[CheckFn], CheckFn]:
    """Decorator that registers a check function under ``name``."""

    def deco(fn: CheckFn) -> CheckFn:
        CHECK_REGISTRY[name] = fn
        return fn

    return deco


def _fqdn(name: str) -> str:
    return f"{name.rstrip('.')}.".lower()


def _records(result: DomainResult, rtype: RecordType) -> list[DNSRecord]:
    return result.unique_records.get(rtype, [])


def _txt_records(result: DomainResult) -> list[DNSRecord]:
    return _records(result, RecordType.TXT)


def _txt_value(record: DNSRecord) -> str:
    return record.value.replace('"', "").strip()


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.rstrip("."))
    except ValueError:
        return False
    return True


def _mx_host(record: DNSRecord) -> str:
    parts = record.value.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].isdigit():
        return parts[1]
    return record.value.strip()


def _result(
    name: str,
    severity: CheckSeverity,
    message: str,
    *,
    details: str | None = None,
    record_type: RecordType | None = None,
) -> CheckResult:
    return CheckResult(
        name=name,
        severity=severity,
        message=message,
        details=details,
        record_type=record_type,
    )


def _semicolon_tags(value: str) -> dict[str, str]:
    """Parse ``key=value; key2=value2`` style tags (DMARC/DKIM) into a dict."""
    tags: dict[str, str] = {}
    for part in value.split(";"):
        key, _, val = part.partition("=")
        if key.strip():
            tags[key.strip().lower()] = val.strip().lower()
    return tags


def _spf_all_qualifier(value: str) -> str | None:
    match = re.search(r"(?:\s|^)([+-~?]?)all\s*$", value, re.IGNORECASE)
    if not match:
        return None
    return match.group(1) or "+"


@register("dmarc")
def check_dmarc(result: DomainResult) -> CheckResult:
    """DMARC: presence and enforcement policy of the ``_dmarc`` record."""
    target = f"_dmarc.{_fqdn(result.domain)}"
    matching = [r for r in _txt_records(result) if _fqdn(r.name) == target]

    if not matching:
        return _result(
            "dmarc",
            CheckSeverity.CRITICAL,
            "No DMARC record found; domain is vulnerable to email spoofing.",
            record_type=RecordType.TXT,
        )

    record = matching[0]
    tags = _semicolon_tags(_txt_value(record))
    details = f"Record: {record.value}"
    policy = tags.get("p")

    if policy is None:
        return _result(
            "dmarc",
            CheckSeverity.WARNING,
            "DMARC record is missing a p= policy tag.",
            details=details,
            record_type=RecordType.TXT,
        )

    if policy == "none":
        return _result(
            "dmarc",
            CheckSeverity.WARNING,
            "DMARC policy is 'none' (monitoring only); consider quarantine or reject.",
            details=details,
            record_type=RecordType.TXT,
        )

    pct = tags.get("pct", "100")
    if pct != "100":
        return _result(
            "dmarc",
            CheckSeverity.WARNING,
            f"DMARC policy '{policy}' only applies to {pct}% of messages.",
            details=details,
            record_type=RecordType.TXT,
        )

    return _result(
        "dmarc",
        CheckSeverity.PASS,
        f"DMARC policy '{policy}' found and enforced.",
        details=details,
        record_type=RecordType.TXT,
    )


def _is_dkim_key(value: str) -> bool:
    return "v=dkim1" in value.lower() or "p=" in value.lower()


@register("dkim")
def check_dkim(result: DomainResult) -> CheckResult:
    """DKIM: presence of a ``<selector>._domainkey.<domain>`` public key record.

    Only keys published under the checked domain's own ``_domainkey`` zone are
    counted; records on other hosts (e.g. a third-party mail provider's
    domainkey host) are not treated as this domain's DKIM signing keys.
    """
    suffix = f"._domainkey.{_fqdn(result.domain)}"
    matching = [r for r in _txt_records(result) if r.name.endswith(suffix)]

    if not matching:
        return _result(
            "dkim",
            CheckSeverity.WARNING,
            f"No DKIM records found for {result.domain}; signed email cannot be verified.",
            record_type=RecordType.TXT,
        )

    keys = [r for r in matching if _is_dkim_key(_txt_value(r))]
    if not keys:
        return _result(
            "dkim",
            CheckSeverity.WARNING,
            f"Found DKIM-looking record(s) for {result.domain} "
            "but none contain a valid public key.",
            record_type=RecordType.TXT,
        )

    selectors = sorted({r.name.split("._domainkey.", 1)[0] for r in keys})
    message = f"DKIM configured ({len(keys)} key(s)); selectors: {', '.join(selectors)}."
    return _result(
        "dkim",
        CheckSeverity.PASS,
        message,
        record_type=RecordType.TXT,
    )


@register("spf")
def check_spf(result: DomainResult) -> CheckResult:
    """SPF: presence at the zone apex and strictness of the ``all`` mechanism."""
    fqdn = _fqdn(result.domain)
    spf_records = [
        r
        for r in _txt_records(result)
        if _fqdn(r.name) == fqdn and _txt_value(r).lower().startswith("v=spf1")
    ]

    if not spf_records:
        return _result(
            "spf",
            CheckSeverity.CRITICAL,
            "No SPF record found; mail from this domain can be spoofed.",
            record_type=RecordType.TXT,
        )

    record = spf_records[0]
    value = _txt_value(record)
    details = f"Record: {record.value}"
    qualifier = _spf_all_qualifier(value)

    if qualifier == "-":
        return _result(
            "spf",
            CheckSeverity.PASS,
            "SPF record uses '-all' (hard fail).",
            details=details,
            record_type=RecordType.TXT,
        )
    if qualifier == "~":
        return _result(
            "spf",
            CheckSeverity.WARNING,
            "SPF record uses '~all' (soft fail); consider hardening to '-all'.",
            details=details,
            record_type=RecordType.TXT,
        )
    if qualifier == "?":
        return _result(
            "spf",
            CheckSeverity.WARNING,
            "SPF record uses '?all' (neutral); consider hardening to '-all'.",
            details=details,
            record_type=RecordType.TXT,
        )
    if qualifier == "+":
        return _result(
            "spf",
            CheckSeverity.CRITICAL,
            "SPF record uses '+all' — anyone may send mail as this domain.",
            details=details,
            record_type=RecordType.TXT,
        )
    return _result(
        "spf",
        CheckSeverity.CRITICAL,
        "SPF record has no 'all' mechanism; it cannot reject unauthorized senders.",
        details=details,
        record_type=RecordType.TXT,
    )


@register("dnssec")
def check_dnssec(result: DomainResult) -> CheckResult:
    """DNSSEC: presence of DNSKEY (signed zone) or DS (chain of trust)."""
    dnskey = _records(result, RecordType.DNSKEY)
    if dnskey:
        return _result(
            "dnssec",
            CheckSeverity.PASS,
            f"DNSSEC is enabled ({len(dnskey)} DNSKEY record(s) at the zone apex).",
            record_type=RecordType.DNSKEY,
        )

    ds = _records(result, RecordType.DS)
    if ds:
        return _result(
            "dnssec",
            CheckSeverity.PASS,
            "DNSSEC is enabled (DS records published at the parent zone).",
            record_type=RecordType.DS,
        )

    return _result(
        "dnssec",
        CheckSeverity.WARNING,
        "DNSSEC is not enabled; responses are not cryptographically validated.",
    )


@register("mx_best_practices")
def check_mx_best_practices(result: DomainResult) -> CheckResult:
    """MX: presence, canonical hostnames, and distinct priorities."""
    mxs = sorted(_records(result, RecordType.MX), key=lambda r: r.priority or 0)

    if not mxs:
        return _result(
            "mx_best_practices",
            CheckSeverity.INFO,
            "No MX records found; the domain does not receive email.",
            record_type=RecordType.MX,
        )

    issues: list[str] = []
    for record in mxs:
        host = _mx_host(record)
        if _is_ip_address(host):
            issues.append(f"MX target {host!r} is an IP literal; a hostname is required")
        elif not host.endswith("."):
            issues.append(f"MX target {host!r} is not canonical (missing trailing dot)")

    priorities = [r.priority for r in mxs]
    if len(priorities) != len(set(priorities)):
        issues.append("multiple MX records share the same priority (defeats failover)")

    if issues:
        return _result(
            "mx_best_practices",
            CheckSeverity.WARNING,
            f"{len(mxs)} MX record(s) with issues.",
            details="; ".join(issues),
            record_type=RecordType.MX,
        )

    return _result(
        "mx_best_practices",
        CheckSeverity.PASS,
        f"{len(mxs)} canonical MX record(s) with distinct priorities.",
        record_type=RecordType.MX,
    )


@register("soa_best_practices")
def check_soa_best_practices(result: DomainResult) -> CheckResult:
    """SOA: sensible timer values (refresh/retry/expire/minimum) and metadata."""
    soas = _records(result, RecordType.SOA)

    if not soas:
        return _result(
            "soa_best_practices",
            CheckSeverity.WARNING,
            "No SOA record found; zone metadata is missing.",
            record_type=RecordType.SOA,
        )

    soa = soas[0]
    issues: list[str] = []
    if soa.mname is None or not soa.mname.endswith("."):
        issues.append("mname is not a canonical hostname")
    if soa.serial is None or soa.serial <= 0:
        issues.append("serial is missing or zero")

    refresh, retry = soa.refresh or 0, soa.retry or 0
    expire, minimum = soa.expire or 0, soa.minimum or 0

    if refresh <= 0:
        issues.append("refresh must be positive")
    elif refresh > 86400:
        issues.append(f"refresh ({refresh}s) exceeds the 24h recommended maximum")
    if retry <= 0:
        issues.append("retry must be positive")
    elif refresh > 0 and retry >= refresh:
        issues.append("retry should be less than refresh")
    if expire < 604800:
        issues.append(f"expire ({expire}s) is below the 7-day recommended minimum")
    if minimum <= 0:
        issues.append("minimum (negative TTL) must be positive")
    elif minimum > 86400:
        issues.append(f"minimum ({minimum}s) exceeds the 24h recommended maximum")

    if issues:
        return _result(
            "soa_best_practices",
            CheckSeverity.WARNING,
            f"{len(issues)} SOA parameter issue(s).",
            details="; ".join(issues),
            record_type=RecordType.SOA,
        )

    return _result(
        "soa_best_practices",
        CheckSeverity.PASS,
        "SOA parameters are within recommended ranges.",
        record_type=RecordType.SOA,
    )


@register("ns_best_practices")
def check_ns_best_practices(result: DomainResult) -> CheckResult:
    """NS: presence, canonical hostnames, and redundancy."""
    nss = _records(result, RecordType.NS)

    if not nss:
        return _result(
            "ns_best_practices",
            CheckSeverity.CRITICAL,
            "No NS records found; the zone delegation is broken.",
            record_type=RecordType.NS,
        )

    hosts = [ns.value.strip().lower() for ns in nss]
    issues: list[str] = []
    for host in hosts:
        if _is_ip_address(host):
            issues.append(f"NS {host!r} is an IP literal; a hostname is required")
        elif not host.endswith("."):
            issues.append(f"NS {host!r} is not canonical (missing trailing dot)")
    if len(set(hosts)) == 1:
        issues.append("single nameserver; consider adding redundancy")

    if issues:
        return _result(
            "ns_best_practices",
            CheckSeverity.WARNING,
            f"{len(nss)} NS record(s) with issues.",
            details="; ".join(issues),
            record_type=RecordType.NS,
        )

    return _result(
        "ns_best_practices",
        CheckSeverity.PASS,
        f"{len(nss)} canonical NS record(s) with redundancy.",
        record_type=RecordType.NS,
    )


@register("caa_best_practices")
def check_caa_best_practices(result: DomainResult) -> CheckResult:
    """CAA: presence and tags restricting certificate issuance."""
    caas = _records(result, RecordType.CAA)

    if not caas:
        return _result(
            "caa_best_practices",
            CheckSeverity.WARNING,
            "No CAA records found; any certificate authority may issue for this domain.",
            record_type=RecordType.CAA,
        )

    tags = [c.tag for c in caas]
    if "issue" not in tags:
        return _result(
            "caa_best_practices",
            CheckSeverity.INFO,
            "CAA records exist but no 'issue' tag restricts certificate issuance.",
            record_type=RecordType.CAA,
        )

    return _result(
        "caa_best_practices",
        CheckSeverity.PASS,
        "CAA records restrict which certificate authorities may issue.",
        record_type=RecordType.CAA,
    )


@register("txt_best_practices")
def check_txt_best_practices(result: DomainResult) -> CheckResult:
    """TXT: records within RFC 1035 string size limits.

    RFC 1035 caps each TXT character-string at 255 bytes. A host may split a
    long value across multiple character-strings in a single TXT record, so the
    limit is applied per-string (``DNSRecord.txt_strings``) rather than to the
    joined value.
    """
    txts = _txt_records(result)

    if not txts:
        return _result(
            "txt_best_practices",
            CheckSeverity.INFO,
            "No TXT records found.",
            record_type=RecordType.TXT,
        )

    violations: list[tuple[DNSRecord, list[tuple[int, int]]]] = []
    for record in txts:
        strings = record.txt_strings or [record.value]
        oversized = [(i, len(s)) for i, s in enumerate(strings) if len(s) > 255]
        if oversized:
            violations.append((record, oversized))

    if violations:
        names = ", ".join(sorted({r.name for r, _ in violations}))
        return _result(
            "txt_best_practices",
            CheckSeverity.WARNING,
            f"{len(violations)} TXT record(s) contain character-strings "
            f"exceeding 255 bytes.",
            details=f"Records at: {names}",
            record_type=RecordType.TXT,
        )

    return _result(
        "txt_best_practices",
        CheckSeverity.PASS,
        f"{len(txts)} TXT record(s) within RFC 1035 string size limits.",
        record_type=RecordType.TXT,
    )


def _compliance_probe_queries(domain: str) -> list[tuple[str, list[RecordType]]]:
    """Extra queries needed to answer checks not covered by a plain domain query."""
    probes: list[tuple[str, list[RecordType]]] = [
        (f"_dmarc.{domain}", [RecordType.TXT]),
    ]
    for selector in DEFAULT_DKIM_SELECTORS:
        probes.append((f"{selector}._domainkey.{domain}", [RecordType.TXT]))
    return probes


def with_compliance_probes(
    result: DomainResult, client: DNSClient | None = None
) -> DomainResult:
    """Return a copy of ``result`` augmented with best-effort compliance probes.

    Adds ``_dmarc``/``_domainkey`` TXT lookups plus root TXT and DNSSEC records
    (DNSKEY/DS) when they were not part of the original query. Probe failures are
    non-fatal.
    """
    client = client or DNSClient()
    domain = result.domain
    seen = set(result.unique_records)

    probes = _compliance_probe_queries(domain)
    if RecordType.TXT not in seen:
        probes.append((domain, [RecordType.TXT]))
    missing_dnssec = [
        rt for rt in (RecordType.DNSKEY, RecordType.DS) if rt not in seen
    ]
    if missing_dnssec:
        probes.append((domain, missing_dnssec))

    extra: list[ServerResponse] = []
    for probe_domain, probe_types in probes:
        try:
            probe_result = client.query_domain(probe_domain, probe_types)
        except (DNSEngineError, ValueError):
            continue
        # Keep only answers for the name we actually asked about. This filters
        # out stray/aliased responses so foreign keys (e.g. a sendgrid CNAME
        # target) never leak into the unique record set shown to the user.
        owner = _fqdn(probe_domain)
        filtered_responses = []
        for resp in probe_result.server_responses:
            keep = [r for r in resp.records if _fqdn(r.name) == owner]
            if resp.status == DNSServerStatus.OK and keep:
                filtered_responses.append(
                    ServerResponse(
                        server=resp.server,
                        status=resp.status,
                        records=keep,
                        response_time_ms=resp.response_time_ms,
                        error=resp.error,
                    )
                )
        extra.extend(filtered_responses)

    return DomainResult(
        domain=domain,
        queried_at=result.queried_at,
        server_responses=[*result.server_responses, *extra],
    )


def run_checks(
    result: DomainResult, check_names: Iterable[str] | None = None
) -> ComplianceReport:
    """Run the named (or default) checks against a ``DomainResult``."""
    names = check_names if check_names is not None else list(DEFAULT_CHECKS)
    check_results: list[CheckResult] = []
    for name in names:
        fn = CHECK_REGISTRY.get(name)
        if fn is None:
            available = ", ".join(sorted(CHECK_REGISTRY))
            raise UnknownCheckError(f"unknown check {name!r}; available: {available}")
        check_results.append(fn(result))

    return ComplianceReport(
        domain=result.domain,
        checked_at=datetime.now(timezone.utc),
        checks=check_results,
    )


def run_compliance(
    domain: str | DomainResult,
    client: DNSClient | None = None,
    check_names: Iterable[str] | None = None,
) -> ComplianceReport:
    """Compliance report for a fresh domain query or an existing ``DomainResult``."""
    if isinstance(domain, DomainResult):
        result = with_compliance_probes(domain, client)
    else:
        client = client or DNSClient()
        result = client.query_domain(domain)
        result = with_compliance_probes(result, client)
    return run_checks(result, check_names)
