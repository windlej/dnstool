"""Tests for the compliance checks engine."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from dnstool.checks import (
    CHECK_REGISTRY,
    DEFAULT_DKIM_SELECTORS,
    UnknownCheckError,
    run_checks,
    run_compliance,
    with_compliance_probes,
)
from dnstool.config import DEFAULT_CHECKS, Config
from dnstool.dns_engine import DNSClient
from dnstool.models import (
    DNSRecord,
    DNSServerStatus,
    DomainResult,
    RecordType,
    ServerResponse,
)

TXT = RecordType.TXT


def _rec(
    rtype: RecordType,
    name: str,
    value: str,
    **kwargs: object,
) -> DNSRecord:
    return DNSRecord(type=rtype, name=name, ttl=300, value=value, **kwargs)  # type: ignore[arg-type]


def make_result(domain: str, *records: DNSRecord) -> DomainResult:
    return DomainResult(
        domain=domain,
        queried_at=datetime.now(timezone.utc),
        server_responses=[
            ServerResponse(server="1.1.1.1", status=DNSServerStatus.OK, records=list(records))
        ],
    )


class TestDmarc:
    def test_missing_is_critical(self) -> None:
        result = make_result("example.com")
        assert run_checks(result, ["dmarc"]).checks[0].severity.value == "critical"

    def test_policy_none_is_warning(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "_dmarc.example.com.", '"v=DMARC1; p=none"'),
        )
        check = run_checks(result, ["dmarc"]).checks[0]
        assert check.severity.value == "warning"
        assert "none" in check.message

    def test_policy_reject_is_pass(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "_dmarc.example.com.", '"v=DMARC1; p=reject"'),
        )
        check = run_checks(result, ["dmarc"]).checks[0]
        assert check.severity.value == "pass"

    def test_quarantine_with_partial_pct_is_warning(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "_dmarc.example.com.", '"v=DMARC1; p=quarantine; pct=50"'),
        )
        check = run_checks(result, ["dmarc"]).checks[0]
        assert check.severity.value == "warning"
        assert "50%" in check.message

    def test_missing_policy_is_warning(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "_dmarc.example.com.", '"v=DMARC1; rua=mailto:dmarc@example.com"'),
        )
        check = run_checks(result, ["dmarc"]).checks[0]
        assert check.severity.value == "warning"


class TestDkim:
    def test_missing_is_warning(self) -> None:
        result = make_result("example.com")
        assert run_checks(result, ["dkim"]).checks[0].severity.value == "warning"

    def test_valid_key_is_pass(self) -> None:
        result = make_result(
            "example.com",
            _rec(
                TXT,
                "google._domainkey.example.com.",
                '"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4"',
            ),
        )
        check = run_checks(result, ["dkim"]).checks[0]
        assert check.severity.value == "pass"
        assert "google" in check.message

    def test_record_without_key_is_warning(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "google._domainkey.example.com.", '"k=rsa"'),
        )
        assert run_checks(result, ["dkim"]).checks[0].severity.value == "warning"

    def test_foreign_domainkey_not_counted(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "s1.domainkey.u24.w1201.sendgrid.net.", '"v=DKIM1; p=abc"'),
        )
        check = run_checks(result, ["dkim"]).checks[0]
        assert check.severity.value == "warning"
        assert "example.com" in check.message


class TestSpf:
    def test_missing_is_critical(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "example.com.", '"google-site-verification=abc123"'),
        )
        assert run_checks(result, ["spf"]).checks[0].severity.value == "critical"

    def test_hardfail_is_pass(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "example.com.", '"v=spf1 -all"'),
        )
        assert run_checks(result, ["spf"]).checks[0].severity.value == "pass"

    def test_softfail_is_warning(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "example.com.", '"v=spf1 include:_spf.example.com ~all"'),
        )
        check = run_checks(result, ["spf"]).checks[0]
        assert check.severity.value == "warning"

    def test_neutral_is_warning(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "example.com.", '"v=spf1 ?all"'),
        )
        assert run_checks(result, ["spf"]).checks[0].severity.value == "warning"

    def test_plus_all_is_critical(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "example.com.", '"v=spf1 +all"'),
        )
        assert run_checks(result, ["spf"]).checks[0].severity.value == "critical"

    def test_no_all_mechanism_is_critical(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "example.com.", '"v=spf1 ip4:192.0.2.1"'),
        )
        assert run_checks(result, ["spf"]).checks[0].severity.value == "critical"


class TestDnssec:
    def test_dnskey_is_pass(self) -> None:
        result = make_result(
            "example.com",
            _rec(RecordType.DNSKEY, "example.com.", "257 3 8 AwEAAaetbp6lk..."),
        )
        check = run_checks(result, ["dnssec"]).checks[0]
        assert check.severity.value == "pass"

    def test_ds_is_pass(self) -> None:
        result = make_result(
            "example.com",
            _rec(RecordType.DS, "example.com.", "12345 8 2 4b984c967e6d..."),
        )
        assert run_checks(result, ["dnssec"]).checks[0].severity.value == "pass"

    def test_missing_is_warning(self) -> None:
        result = make_result("example.com")
        assert run_checks(result, ["dnssec"]).checks[0].severity.value == "warning"


class TestMxBestPractices:
    def test_missing_is_info(self) -> None:
        result = make_result("example.com")
        assert run_checks(result, ["mx_best_practices"]).checks[0].severity.value == "info"

    def test_canonical_distinct_is_pass(self) -> None:
        result = make_result(
            "example.com",
            _rec(RecordType.MX, "example.com.", "10 mail.example.com.", priority=10),
            _rec(RecordType.MX, "example.com.", "20 mail2.example.com.", priority=20),
        )
        assert run_checks(result, ["mx_best_practices"]).checks[0].severity.value == "pass"

    def test_non_canonical_is_warning(self) -> None:
        result = make_result(
            "example.com",
            _rec(RecordType.MX, "example.com.", "10 mail.example.com", priority=10),
        )
        check = run_checks(result, ["mx_best_practices"]).checks[0]
        assert check.severity.value == "warning"
        assert "not canonical" in check.details or "not canonical" in check.message

    def test_ip_literal_is_warning(self) -> None:
        result = make_result(
            "example.com",
            _rec(RecordType.MX, "example.com.", "10 192.0.2.1.", priority=10),
        )
        check = run_checks(result, ["mx_best_practices"]).checks[0]
        assert check.severity.value == "warning"
        assert "IP literal" in check.details

    def test_equal_priority_distinct_hosts_is_pass(self) -> None:
        result = make_result(
            "example.com",
            _rec(RecordType.MX, "example.com.", "10 mail.example.com.", priority=10),
            _rec(RecordType.MX, "example.com.", "10 mail2.example.com.", priority=10),
        )
        check = run_checks(result, ["mx_best_practices"]).checks[0]
        assert check.severity.value == "pass"

    def test_redundant_mx_target_is_warning(self) -> None:
        # Same (priority, host) written with different casing survives the
        # record dedup and must be flagged as redundant.
        result = make_result(
            "example.com",
            _rec(RecordType.MX, "example.com.", "10 mail.example.com.", priority=10),
            _rec(RecordType.MX, "example.com.", "10 MAIL.EXAMPLE.COM.", priority=10),
        )
        check = run_checks(result, ["mx_best_practices"]).checks[0]
        assert check.severity.value == "warning"
        assert "duplicate" in check.details


class TestSoaBestPractices:
    def _soa(self, **kwargs: object) -> DNSRecord:
        fields = {
            "mname": "ns1.example.com.",
            "rname": "hostmaster.example.com.",
            "serial": 2024090101,
            "refresh": 7200,
            "retry": 3600,
            "expire": 1209600,
            "minimum": 3600,
            "value": "ns1.example.com. hostmaster.example.com. "
            "2024090101 7200 3600 1209600 3600",
        }
        fields.update(kwargs)
        return DNSRecord(type=RecordType.SOA, name="example.com.", ttl=300, **fields)  # type: ignore[arg-type]

    def test_missing_is_warning(self) -> None:
        result = make_result("example.com")
        assert run_checks(result, ["soa_best_practices"]).checks[0].severity.value == "warning"

    def test_good_soa_is_pass(self) -> None:
        result = make_result("example.com", self._soa())
        assert run_checks(result, ["soa_best_practices"]).checks[0].severity.value == "pass"

    def test_bad_timers_is_warning(self) -> None:
        result = make_result(
            "example.com",
            self._soa(refresh=90000, retry=95000, expire=3600, minimum=172800),
        )
        check = run_checks(result, ["soa_best_practices"]).checks[0]
        assert check.severity.value == "warning"
        assert check.details is not None

    def test_non_canonical_mname_is_warning(self) -> None:
        result = make_result("example.com", self._soa(mname="ns1.local"))
        assert run_checks(result, ["soa_best_practices"]).checks[0].severity.value == "warning"


class TestNsBestPractices:
    def test_missing_is_critical(self) -> None:
        result = make_result("example.com")
        assert run_checks(result, ["ns_best_practices"]).checks[0].severity.value == "critical"

    def test_canonical_redundant_is_pass(self) -> None:
        result = make_result(
            "example.com",
            _rec(RecordType.NS, "example.com.", "ns1.example.com."),
            _rec(RecordType.NS, "example.com.", "ns2.example.com."),
        )
        assert run_checks(result, ["ns_best_practices"]).checks[0].severity.value == "pass"

    def test_single_ns_is_warning(self) -> None:
        result = make_result(
            "example.com",
            _rec(RecordType.NS, "example.com.", "ns1.example.com."),
        )
        check = run_checks(result, ["ns_best_practices"]).checks[0]
        assert check.severity.value == "warning"
        assert "redundancy" in check.details

    def test_non_canonical_is_warning(self) -> None:
        result = make_result(
            "example.com",
            _rec(RecordType.NS, "example.com.", "ns1.example.com"),
            _rec(RecordType.NS, "example.com.", "ns2.example.com."),
        )
        check = run_checks(result, ["ns_best_practices"]).checks[0]
        assert check.severity.value == "warning"
        assert "not canonical" in check.details

    def test_ip_literal_is_warning(self) -> None:
        result = make_result(
            "example.com",
            _rec(RecordType.NS, "example.com.", "192.0.2.1."),
            _rec(RecordType.NS, "example.com.", "192.0.2.2."),
        )
        check = run_checks(result, ["ns_best_practices"]).checks[0]
        assert check.severity.value == "warning"
        assert "IP literal" in check.details


class TestCaaBestPractices:
    def test_missing_is_info(self) -> None:
        result = make_result("example.com")
        assert run_checks(result, ["caa_best_practices"]).checks[0].severity.value == "info"

    def test_issue_tag_is_pass(self) -> None:
        result = make_result(
            "example.com",
            _rec(
                RecordType.CAA,
                "example.com.",
                '0 issue "letsencrypt.org"',
                flags=0,
                tag="issue",
            ),
        )
        assert run_checks(result, ["caa_best_practices"]).checks[0].severity.value == "pass"

    def test_no_issue_tag_is_info(self) -> None:
        result = make_result(
            "example.com",
            _rec(
                RecordType.CAA,
                "example.com.",
                '0 iodef "mailto:security@example.com"',
                flags=0,
                tag="iodef",
            ),
        )
        assert run_checks(result, ["caa_best_practices"]).checks[0].severity.value == "info"


class TestTxtBestPractices:
    def test_missing_is_info(self) -> None:
        result = make_result("example.com")
        assert run_checks(result, ["txt_best_practices"]).checks[0].severity.value == "info"

    def test_within_limits_is_pass(self) -> None:
        result = make_result(
            "example.com",
            _rec(TXT, "example.com.", '"v=spf1 -all"'),
        )
        assert run_checks(result, ["txt_best_practices"]).checks[0].severity.value == "pass"

    def test_too_long_is_warning(self) -> None:
        long_value = '"' + "a" * 300 + '"'
        result = make_result("example.com", _rec(TXT, "example.com.", long_value))
        check = run_checks(result, ["txt_best_practices"]).checks[0]
        assert check.severity.value == "warning"
        assert "255" in check.message

    def test_split_into_strings_each_under_limit_is_pass(self) -> None:
        record = _rec(TXT, "example.com.", '"' + "a" * 200 + '" "' + "b" * 200 + '"')
        record.txt_strings = ["a" * 200, "b" * 200]
        result = make_result("example.com", record)
        check = run_checks(result, ["txt_best_practices"]).checks[0]
        assert check.severity.value == "pass"

    def test_one_string_over_limit_is_warning(self) -> None:
        record = _rec(TXT, "example.com.", '"' + "a" * 100 + '" "' + "b" * 300 + '"')
        record.txt_strings = ["a" * 100, "b" * 300]
        result = make_result("example.com", record)
        check = run_checks(result, ["txt_best_practices"]).checks[0]
        assert check.severity.value == "warning"
        assert "255" in check.message


class TestRegistry:
    def test_covers_all_default_checks(self) -> None:
        assert set(CHECK_REGISTRY) == set(DEFAULT_CHECKS)

    def test_unknown_check_raises(self) -> None:
        result = make_result("example.com")
        with pytest.raises(UnknownCheckError, match="unknown check"):
            run_checks(result, ["does_not_exist"])


class TestRunChecks:
    def test_default_checks_in_config_order(self) -> None:
        result = make_result("example.com")
        report = run_checks(result)
        assert [c.name for c in report.checks] == DEFAULT_CHECKS

    def test_report_metadata(self) -> None:
        result = make_result("example.com")
        report = run_checks(result)
        assert report.domain == "example.com"
        assert report.checked_at.tzinfo is not None
        assert report.critical_issues  # everything missing
        assert report.score == 0.0

    def test_score_counts_passes(self) -> None:
        records = [
            _rec(TXT, "_dmarc.example.com.", '"v=DMARC1; p=reject"'),
            _rec(TXT, "google._domainkey.example.com.", '"v=DKIM1; k=rsa; p=abc"'),
            _rec(TXT, "example.com.", '"v=spf1 -all"'),
            _rec(RecordType.DNSKEY, "example.com.", "257 3 8 AwEAAaetbp6lk..."),
            _rec(RecordType.MX, "example.com.", "10 mail.example.com.", priority=10),
            self._soa(),
            _rec(RecordType.NS, "example.com.", "ns1.example.com."),
            _rec(RecordType.NS, "example.com.", "ns2.example.com."),
            _rec(RecordType.CAA, "example.com.", '0 issue "letsencrypt.org"', flags=0, tag="issue"),
            _rec(TXT, "example.com.", '"v=spf1 -all"'),
        ]
        result = make_result("example.com", *records)
        report = run_checks(result)
        assert report.score == 100.0

    @staticmethod
    def _soa() -> DNSRecord:
        return _rec(
            RecordType.SOA,
            "example.com.",
            "ns1.example.com. hostmaster.example.com. "
            "2024090101 7200 3600 1209600 3600",
            mname="ns1.example.com.",
            rname="hostmaster.example.com.",
            serial=2024090101,
            refresh=7200,
            retry=3600,
            expire=1209600,
            minimum=3600,
        )


def _probe_client(monkeypatch: pytest.MonkeyPatch) -> DNSClient:
    client = DNSClient(
        Config(use_system_resolver=False), nameservers=["1.1.1.1"]
    )

    def fqdn(name: str) -> str:
        return name if name.endswith(".") else f"{name}."

    def fake_query(
        self, domain: str, record_types: list[RecordType] | None = None
    ) -> DomainResult:
        if domain == "example.com":
            if RecordType.TXT in (record_types or []):
                return make_result(domain, _rec(TXT, "example.com.", '"v=spf1 -all"'))
            return make_result(
                domain,
                _rec(RecordType.DNSKEY, "example.com.", "257 3 8 AwEAAaetbp6lk..."),
            )
        if domain == "_dmarc.example.com":
            return make_result(domain, _rec(TXT, fqdn(domain), '"v=DMARC1; p=reject"'))
        if domain == "google._domainkey.example.com":
            return make_result(domain, _rec(TXT, fqdn(domain), '"v=DKIM1; k=rsa; p=abc"'))
        return make_result(domain)

    monkeypatch.setattr(DNSClient, "query_domain", fake_query)
    return client


class TestProbes:
    def test_with_compliance_probes_adds_missing_lookups(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _probe_client(monkeypatch)
        base = make_result(
            "example.com",
            _rec(RecordType.MX, "example.com.", "10 mail.example.com.", priority=10),
        )

        augmented = with_compliance_probes(base, client)
        txt_names = {r.name for r in augmented.unique_records.get(TXT, [])}
        assert "_dmarc.example.com." in txt_names
        assert "google._domainkey.example.com." in txt_names
        assert "example.com." in txt_names
        assert RecordType.DNSKEY in augmented.unique_records

    def test_with_compliance_probes_skips_existing_types(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _probe_client(monkeypatch)
        base = make_result(
            "example.com",
            _rec(TXT, "example.com.", '"v=spf1 -all"'),
            _rec(RecordType.DNSKEY, "example.com.", "257 3 8 AwEAAaetbp6lk..."),
            _rec(RecordType.DS, "example.com.", "12345 8 2 4b984c967e6d..."),
        )

        augmented = with_compliance_probes(base, client)
        assert "example.com." in {r.name for r in augmented.unique_records.get(TXT, [])}

    def test_run_compliance_fresh_query(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _probe_client(monkeypatch)
        report = run_compliance("example.com", client=client)
        severities = {c.name: c.severity.value for c in report.checks}
        assert severities["dmarc"] == "pass"
        assert severities["dkim"] == "pass"
        assert severities["spf"] == "pass"
        assert severities["dnssec"] == "pass"

    def test_dkim_selectors_present(self) -> None:
        expected = {
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
        }
        assert "google" in DEFAULT_DKIM_SELECTORS
        assert set(DEFAULT_DKIM_SELECTORS) == expected

    def test_probe_cname_dmarc_attributed_to_query_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_query(self: object, domain: str, record_types=None) -> DomainResult:
            if domain == "_dmarc.example.com":
                return make_result(
                    domain,
                    _rec(
                        RecordType.CNAME,
                        "_dmarc.example.com.",
                        "dmarc.alias.example.net.",
                    ),
                    _rec(TXT, "dmarc.alias.example.net.", '"v=DMARC1; p=reject"'),
                )
            return make_result(domain)

        client = DNSClient(Config(use_system_resolver=False))
        monkeypatch.setattr(DNSClient, "query_domain", fake_query)
        base = make_result("example.com", _rec(TXT, "example.com.", '"v=spf1 -all"'))

        augmented = with_compliance_probes(base, client)
        dmarc_records = [
            r
            for r in augmented.unique_records.get(TXT, [])
            if r.name == "_dmarc.example.com."
        ]
        assert len(dmarc_records) == 1
        assert "easydmarc" not in dmarc_records[0].name
        report = run_checks(augmented, ["dmarc"])
        assert report.checks[0].severity.value == "pass"

    def test_probe_cname_dkim_attributed_to_query_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_query(self: object, domain: str, record_types=None) -> DomainResult:
            if domain == "selector1._domainkey.example.com":
                return make_result(
                    domain,
                    _rec(
                        RecordType.CNAME,
                        "selector1._domainkey.example.com.",
                        "selector1-example-com._domainkey.example.onmicrosoft.com.",
                    ),
                    _rec(
                        TXT,
                        "selector1-example-com._domainkey.example.onmicrosoft.com.",
                        '"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4"',
                    ),
                )
            if domain == "_dmarc.example.com":
                return make_result(
                    domain, _rec(TXT, "_dmarc.example.com.", '"v=DMARC1; p=reject"')
                )
            return make_result(domain)

        client = DNSClient(Config(use_system_resolver=False))
        monkeypatch.setattr(DNSClient, "query_domain", fake_query)
        base = make_result("example.com")

        augmented = with_compliance_probes(base, client)
        report = run_checks(augmented, ["dkim"])
        assert report.checks[0].severity.value == "pass"
        assert "selector1" in report.checks[0].message

    def test_probe_foreign_txt_without_cname_link_is_dropped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_query(self: object, domain: str, record_types=None) -> DomainResult:
            if domain == "s1._domainkey.example.com":
                # A bare foreign TXT with no CNAME tying it to the query name.
                return make_result(
                    domain,
                    _rec(
                        TXT,
                        "s1.domainkey.u24.w1201.sendgrid.net.",
                        '"v=DKIM1; p=abc"',
                    ),
                )
            return make_result(domain)

        client = DNSClient(Config(use_system_resolver=False))
        monkeypatch.setattr(DNSClient, "query_domain", fake_query)
        base = make_result("example.com")

        augmented = with_compliance_probes(base, client)
        txt_records = augmented.unique_records.get(TXT, [])
        assert all(
            r.name != "s1._domainkey.example.com."
            for r in txt_records
        )
