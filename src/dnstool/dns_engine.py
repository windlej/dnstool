"""DNS query engine.

Parallel queries across multiple name servers with response-time tracking,
built on top of dnspython's transport- and message-level primitives.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import dns.exception
import dns.flags
import dns.inet
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from dnstool.config import Config, NameserverConfig
from dnstool.models import DNSRecord, DNSServerStatus, DomainResult, RecordType, ServerResponse

# Internal signals returned alongside query records.
_SIG_TIMEOUT = "timeout"
_SIG_REFUSED = "refused"
_SIG_NXDOMAIN = "nxdomain"


class DNSEngineError(Exception):
    """Base exception for the DNS engine."""


class NoNameserversError(DNSEngineError):
    """Raised when a query is attempted with no nameservers to use."""


def validate_domain(domain: str) -> dns.name.Name:
    """Validate a domain name and return it as an absolute ``dns.name.Name``."""
    try:
        name = dns.name.from_text(domain)
    except dns.exception.DNSException as exc:
        raise ValueError(f"invalid domain name {domain!r}: {exc}") from exc
    if not name.is_absolute():
        name = name.concatenate(dns.name.root)
    return name


def coerce_record_types(record_types: Iterable[str | RecordType]) -> list[RecordType]:
    """Coerce strings or ``RecordType`` values into a list of ``RecordType``."""
    out: list[RecordType] = []
    for rt in record_types:
        if isinstance(rt, RecordType):
            out.append(rt)
            continue
        try:
            out.append(RecordType(str(rt).upper()))
        except ValueError as exc:
            valid = ", ".join(t.value for t in RecordType)
            raise ValueError(f"unknown record type {rt!r}; valid types: {valid}") from exc
    return out


def _as_nameserver_config(ns: str | NameserverConfig) -> NameserverConfig:
    """Normalize a nameserver into a ``NameserverConfig``."""
    if isinstance(ns, NameserverConfig):
        return ns
    return NameserverConfig(ip=ns, label=ns)


def _query_udp(query: dns.message.Message, server: str, timeout: float) -> dns.message.Message:
    return dns.query.udp(query, server, timeout=timeout)


def _query_tcp(query: dns.message.Message, server: str, timeout: float) -> dns.message.Message:
    return dns.query.tcp(query, server, timeout=timeout)


def _rdata_to_record(rtype: RecordType, owner: str, ttl: int, rdata: Any) -> DNSRecord:
    """Convert dnspython rdata into a ``DNSRecord``, mapping type-specific fields."""
    kwargs: dict[str, Any] = {}
    if rtype is RecordType.MX:
        kwargs["priority"] = int(rdata.preference)
    elif rtype is RecordType.SRV:
        kwargs["priority"] = int(rdata.priority)
        kwargs["weight"] = int(rdata.weight)
        kwargs["port"] = int(rdata.port)
        kwargs["target"] = str(rdata.target)
    elif rtype is RecordType.SOA:
        kwargs["mname"] = str(rdata.mname)
        kwargs["rname"] = str(rdata.rname)
        kwargs["serial"] = int(rdata.serial)
        kwargs["refresh"] = int(rdata.refresh)
        kwargs["retry"] = int(rdata.retry)
        kwargs["expire"] = int(rdata.expire)
        kwargs["minimum"] = int(rdata.minimum)
    elif rtype is RecordType.CAA:
        kwargs["flags"] = int(rdata.flags)
        kwargs["tag"] = rdata.tag.decode("utf-8")
    elif rtype is RecordType.TXT:
        kwargs["txt_strings"] = [s.decode("utf-8", errors="replace") for s in rdata.strings]
    return DNSRecord(type=rtype, name=owner, ttl=int(ttl), value=rdata.to_text(), **kwargs)


class DNSClient:
    """Query DNS records across multiple nameservers, running queries in parallel."""

    def __init__(
        self,
        config: Config | None = None,
        *,
        nameservers: Sequence[str | NameserverConfig] | None = None,
        timeout: float | None = None,
    ) -> None:
        self.config = config or Config()
        self.timeout = timeout if timeout is not None else self.config.timeout
        self._nameserver_override: list[NameserverConfig] | None = None
        if nameservers is not None:
            self._nameserver_override = [_as_nameserver_config(ns) for ns in nameservers]

    def nameservers_for(self, domain: str) -> list[NameserverConfig]:
        """Nameservers to use for a domain, honoring per-domain config and overrides."""
        if self._nameserver_override is not None:
            servers: list[NameserverConfig] = self._nameserver_override
        else:
            domain_cfg = self.config.domains.get(domain)
            if domain_cfg and domain_cfg.nameservers:
                servers = domain_cfg.nameservers
            else:
                servers = self.config.nameservers

        merged: list[NameserverConfig] = []
        seen: set[str] = set()
        for ns in servers:
            cfg = _as_nameserver_config(ns)
            if cfg.ip not in seen:
                seen.add(cfg.ip)
                merged.append(cfg)

        if self.config.use_system_resolver:
            for ip in self._system_nameserver_ips():
                if ip not in seen:
                    seen.add(ip)
                    merged.append(
                        NameserverConfig(ip=ip, label="System resolver", timeout=self.timeout)
                    )
        return merged

    @staticmethod
    def _system_nameserver_ips() -> list[str]:
        """IPs of the platform's system nameservers, if any."""
        try:
            resolver = dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration:
            return []
        out: list[str] = []
        for ns in resolver.nameservers:
            ip = str(ns)
            if dns.inet.is_address(ip):
                out.append(ip)
        return out

    def record_types_for(self, domain: str | None = None) -> list[RecordType]:
        """Record types to query for a domain, falling back to global config."""
        domain_cfg = self.config.domains.get(domain) if domain else None
        if domain_cfg and domain_cfg.record_types:
            return list(domain_cfg.record_types)
        return list(self.config.record_types)

    def query_domain(
        self,
        domain: str,
        record_types: Iterable[RecordType] | None = None,
    ) -> DomainResult:
        """Query every configured nameserver for a domain, in parallel (sync API)."""
        validate_domain(domain)
        types = self.record_types_for(domain) if record_types is None else list(record_types)
        servers = self.nameservers_for(domain)
        if not servers:
            raise NoNameserversError(f"no nameservers configured for {domain}")

        with ThreadPoolExecutor(
            max_workers=len(servers), thread_name_prefix="dnstool-dns"
        ) as executor:
            responses = list(
                executor.map(
                    lambda ns: self.query_nameserver(domain, ns, types),
                    servers,
                )
            )
        return self._build_result(domain, responses)

    async def query_domain_async(
        self,
        domain: str,
        record_types: Iterable[RecordType] | None = None,
    ) -> DomainResult:
        """Query every configured nameserver for a domain, in parallel (async API)."""
        validate_domain(domain)
        types = self.record_types_for(domain) if record_types is None else list(record_types)
        servers = self.nameservers_for(domain)
        if not servers:
            raise NoNameserversError(f"no nameservers configured for {domain}")

        responses = await asyncio.gather(
            *(asyncio.to_thread(self.query_nameserver, domain, ns, types) for ns in servers)
        )
        return self._build_result(domain, list(responses))

    async def query_domains_async(
        self,
        domains: Iterable[str],
        record_types: Iterable[RecordType] | None = None,
        max_concurrency: int = 8,
    ) -> list[DomainResult]:
        """Query multiple domains in parallel, bounding concurrent work per domain."""
        semaphore = asyncio.Semaphore(max_concurrency)

        async def _query(domain: str) -> DomainResult:
            async with semaphore:
                return await self.query_domain_async(domain, record_types)

        return list(await asyncio.gather(*(_query(domain) for domain in domains)))

    def query_nameserver(
        self,
        domain: str,
        ns: NameserverConfig,
        record_types: Iterable[RecordType],
    ) -> ServerResponse:
        """Query one nameserver for several record types, tracking total response time."""
        qname = validate_domain(domain)
        timeout = max(0.05, ns.timeout or self.timeout)
        start = time.perf_counter()
        deadline = start + timeout

        records: list[DNSRecord] = []
        timed_out = False
        refused = False
        failures: list[str] = []

        for rtype in record_types:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                timed_out = True
                break
            new_records, signal = self._query_one_type(qname, rtype, ns.ip, remaining)
            records.extend(new_records)
            if signal == _SIG_TIMEOUT:
                timed_out = True
                break
            if signal == _SIG_REFUSED:
                refused = True
                failures.append(dns.rcode.to_text(dns.rcode.REFUSED))
                continue
            if signal == _SIG_NXDOMAIN:
                elapsed = (time.perf_counter() - start) * 1000.0
                return ServerResponse(
                    server=ns.label or ns.ip,
                    status=DNSServerStatus.ERROR,
                    response_time_ms=round(elapsed, 3),
                    error=f"NXDOMAIN: {domain} does not exist",
                )
            if signal:
                failures.append(signal)

        response_time_ms = round((time.perf_counter() - start) * 1000.0, 3)
        if records:
            status = DNSServerStatus.OK
            error = None
        elif timed_out:
            status = DNSServerStatus.TIMEOUT
            error = "no response within timeout"
        elif refused:
            status = DNSServerStatus.REFUSED
            error = "; ".join(failures) or "query refused by server"
        else:
            status = DNSServerStatus.ERROR
            error = "; ".join(failures) or "no records returned"

        return ServerResponse(
            server=ns.label or ns.ip,
            status=status,
            records=records,
            response_time_ms=response_time_ms,
            error=error,
        )

    def _query_one_type(
        self,
        qname: dns.name.Name,
        rtype: RecordType,
        server: str,
        timeout: float,
    ) -> tuple[list[DNSRecord], str | None]:
        """Query a single record type via UDP (falling back to TCP on truncation)."""
        rdtype = dns.rdatatype.from_text(rtype.value)
        query = dns.message.make_query(qname, rdtype, dns.rdataclass.IN)

        try:
            response = _query_udp(query, server, timeout)
        except dns.exception.Timeout:
            return [], _SIG_TIMEOUT
        except OSError as exc:
            return [], f"connection error: {exc}"

        if response is None:
            return [], "empty response"
        if response.rcode() == dns.rcode.NXDOMAIN:
            return [], _SIG_NXDOMAIN
        if response.flags & dns.flags.TC:
            try:
                response = _query_tcp(query, server, timeout)
            except dns.exception.Timeout:
                return [], _SIG_TIMEOUT
            except OSError as exc:
                return [], f"connection error: {exc}"

        rcode = response.rcode()
        if rcode == dns.rcode.REFUSED:
            return [], _SIG_REFUSED
        if rcode != dns.rcode.NOERROR:
            return [], f"server returned {dns.rcode.to_text(rcode)}"

        records: list[DNSRecord] = []
        for rrset in response.answer:
            if rrset.rdtype != rdtype:
                continue
            owner = str(rrset.name)
            ttl = int(rrset.ttl)
            for rdata in rrset:
                records.append(_rdata_to_record(rtype, owner, ttl, rdata))
        return records, None

    @staticmethod
    def _build_result(
        domain: str,
        responses: list[ServerResponse],
    ) -> DomainResult:
        """Assemble a ``DomainResult``, preserving nameserver ordering."""
        return DomainResult(
            domain=domain,
            queried_at=datetime.now(timezone.utc),
            server_responses=responses,
        )


def query_domain(
    domain: str,
    record_types: Iterable[str | RecordType] | None = None,
    nameservers: Sequence[str | NameserverConfig] | None = None,
    timeout: float | None = None,
    config: Config | None = None,
) -> DomainResult:
    """Convenience wrapper for one-shot domain queries against multiple nameservers."""
    types = coerce_record_types(record_types) if record_types is not None else None
    client = DNSClient(config, nameservers=nameservers, timeout=timeout)
    return client.query_domain(domain, types)
