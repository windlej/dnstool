"""Tests for the DNS query engine."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype as dt
import dns.rrset
import pytest

from dnstool import dns_engine
from dnstool.config import Config, NameserverConfig
from dnstool.dns_engine import (
    DNSClient,
    NoNameserversError,
    coerce_record_types,
    validate_domain,
)
from dnstool.models import DNSRecord, DNSServerStatus, RecordType, ServerResponse

Message = dns.message.Message
UdpFn = Callable[[Message, str, float], Message]


def _make_response(
    domain: str,
    answer: Sequence[dns.rrset.RRset] | None = None,
    rcode: dns.rcode.Rcode | None = None,
    flags: int = 0,
    rdtype: str = "A",
) -> Message:
    query = dns.message.make_query(dns.name.from_text(domain), rdtype)
    resp = dns.message.make_response(query)
    if rcode is not None:
        resp.set_rcode(rcode)
    for rrset in answer or []:
        resp.answer.append(rrset)
    resp.flags |= flags
    return resp


def _rrset(domain: str, rdtype: str, ttl: int = 300, *values: str) -> dns.rrset.RRset:
    return dns.rrset.from_text(f"{domain}.", ttl, "IN", rdtype, *values)


class TestClientInit:
    def _no_system_client(
        self,
        *,
        nameservers: Sequence[str | NameserverConfig] | None = None,
        timeout: float | None = None,
    ) -> DNSClient:
        config = Config(use_system_resolver=False)
        return DNSClient(config, nameservers=nameservers, timeout=timeout)

    def test_default_nameservers_from_config(self) -> None:
        config = Config(use_system_resolver=False)
        config.nameservers = [
            NameserverConfig(ip="1.1.1.1"),
            NameserverConfig(ip="8.8.8.8"),
        ]
        client = DNSClient(config, nameservers=[])
        assert client.nameservers_for("example.com") == []

    def test_nameserver_override(self) -> None:
        client = self._no_system_client(
            nameservers=["9.9.9.9", "1.1.1.1"]
        )
        nameservers = client.nameservers_for("example.com")
        assert [ns.ip for ns in nameservers] == ["9.9.9.9", "1.1.1.1"]

    def test_dedup_overlapping_nameservers(self) -> None:
        config = Config(use_system_resolver=False)
        config.nameservers = [
            NameserverConfig(ip="1.1.1.1"),
            NameserverConfig(ip="1.1.1.1"),
            NameserverConfig(ip="8.8.8.8"),
        ]
        client = DNSClient(config)
        assert [ns.ip for ns in client.nameservers_for("example.com")] == [
            "1.1.1.1",
            "8.8.8.8",
        ]

    def test_system_resolver_included(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = Config(use_system_resolver=True)
        config.nameservers = [NameserverConfig(ip="1.1.1.1")]
        monkeypatch.setattr(
            DNSClient,
            "_system_nameserver_ips",
            staticmethod(lambda: ["9.9.9.9"]),
        )
        client = DNSClient(config)
        nameservers = client.nameservers_for("example.com")
        assert [ns.ip for ns in nameservers] == ["1.1.1.1", "9.9.9.9"]
        assert nameservers[1].label == "System resolver"

    def test_system_resolver_dedup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = Config(use_system_resolver=True)
        config.nameservers = [
            NameserverConfig(ip="1.1.1.1"),
            NameserverConfig(ip="8.8.8.8"),
        ]
        monkeypatch.setattr(
            DNSClient,
            "_system_nameserver_ips",
            staticmethod(lambda: ["1.1.1.1"]),
        )
        client = DNSClient(config)
        assert [ns.ip for ns in client.nameservers_for("example.com")] == [
            "1.1.1.1",
            "8.8.8.8",
        ]

    def test_no_nameservers_raises(self) -> None:
        client = self._no_system_client(nameservers=[])
        with pytest.raises(NoNameserversError):
            client.query_domain("example.com")


def _resolve_type(result: ServerResponse, rtype: RecordType) -> DNSRecord:
    return next(r for r in result.records if r.type == rtype)


class TestQueryNameserver:
    def test_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = _make_response(
            "example.com",
            rdtype="A",
            answer=[_rrset("example.com", "A", 300, "1.2.3.4", "1.2.3.5")],
        )

        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            return resp

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        client = DNSClient(Config(use_system_resolver=False))
        result = client.query_nameserver(
            "example.com",
            NameserverConfig(ip="1.1.1.1"),
            [RecordType.A],
        )
        assert result.status == DNSServerStatus.OK
        assert result.server == "1.1.1.1"
        assert result.error is None
        assert result.response_time_ms > 0
        assert [r.value for r in result.records] == [
            "1.2.3.4",
            "1.2.3.5",
        ]
        assert all(r.type == RecordType.A for r in result.records)
        assert all(r.ttl == 300 for r in result.records)

    def test_specialized_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answers: dict[RecordType, dns.rrset.RRset] = {
            RecordType.MX: _rrset(
                "example.com", "MX", 300, "10 mail.example.com."
            ),
            RecordType.SRV: _rrset(
                "example.com", "SRV", 300, "1 5 443 srv.example.com."
            ),
            RecordType.SOA: _rrset(
                "example.com",
                "SOA",
                300,
                "ns1.example.com. admin.example.com."
                " 2024090101 7200 3600 1209600 3600",
            ),
            RecordType.CAA: _rrset(
                "example.com",
                "CAA",
                300,
                '0 issue "letsencrypt.org"',
            ),
        }

        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            rdtype = query.question[0].rdtype
            rtype = RecordType(dt.to_text(rdtype))
            return _make_response(
                "example.com", answer=[answers[rtype]], rdtype=rtype.value
            )

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        client = DNSClient(Config(use_system_resolver=False))
        result = client.query_nameserver(
            "example.com",
            NameserverConfig(ip="1.1.1.1"),
            [RecordType.MX, RecordType.SRV, RecordType.SOA, RecordType.CAA],
        )

        mx = _resolve_type(result, RecordType.MX)
        assert mx.priority == 10
        assert mx.value == "10 mail.example.com."

        srv = _resolve_type(result, RecordType.SRV)
        assert (srv.priority, srv.weight, srv.port, srv.target) == (
            1,
            5,
            443,
            "srv.example.com.",
        )

        soa = _resolve_type(result, RecordType.SOA)
        assert (soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum) == (
            2024090101,
            7200,
            3600,
            1209600,
            3600,
        )
        assert soa.mname == "ns1.example.com."
        assert soa.rname == "admin.example.com."

        caa = _resolve_type(result, RecordType.CAA)
        assert caa.flags == 0
        assert caa.tag == "issue"

    def test_nodata_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        resp = _make_response("example.com", rdtype="A")

        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            return resp

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        client = DNSClient(Config(use_system_resolver=False))
        result = client.query_nameserver(
            "example.com",
            NameserverConfig(ip="1.1.1.1"),
            [RecordType.A],
        )
        assert result.records == []
        assert result.status == DNSServerStatus.ERROR

    def test_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        resp = _make_response("example.com", rcode=dns.rcode.REFUSED)

        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            return resp

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        client = DNSClient(Config(use_system_resolver=False))
        result = client.query_nameserver(
            "example.com",
            NameserverConfig(ip="1.1.1.1"),
            [RecordType.A],
        )
        assert result.status == DNSServerStatus.REFUSED
        assert result.error and "REFUSED" in result.error
        assert result.records == []

    def test_nxdomain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            return _make_response(
                "example.com", rcode=dns.rcode.NXDOMAIN
            )

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        client = DNSClient(Config(use_system_resolver=False))
        result = client.query_nameserver(
            "example.com",
            NameserverConfig(ip="1.1.1.1"),
            [RecordType.A],
        )
        assert result.status == DNSServerStatus.ERROR
        assert result.error and "NXDOMAIN" in result.error
        assert result.response_time_ms > 0

    def test_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            raise dns.exception.Timeout

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        client = DNSClient(Config(use_system_resolver=False))
        result = client.query_nameserver(
            "example.com",
            NameserverConfig(ip="1.1.1.1"),
            [RecordType.A],
        )
        assert result.status == DNSServerStatus.TIMEOUT
        assert result.error == "no response within timeout"

    def test_connection_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            raise OSError("network unreachable")

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        client = DNSClient(Config(use_system_resolver=False))
        result = client.query_nameserver(
            "example.com",
            NameserverConfig(ip="1.1.1.1"),
            [RecordType.A],
        )
        assert result.status == DNSServerStatus.ERROR
        assert result.error and "connection error" in result.error

    def test_truncated_falls_back_to_tcp(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        truncated = _make_response(
            "example.com", rdtype="TXT", flags=dns.flags.TC
        )
        full = _make_response(
            "example.com",
            rdtype="TXT",
            answer=[_rrset("example.com", "TXT", 60, '"hello world"')],
        )

        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            return truncated

        def fake_tcp(
            query: Message, server: str, timeout: float
        ) -> Message:
            return full

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        monkeypatch.setattr(dns_engine, "_query_tcp", fake_tcp)
        client = DNSClient(Config(use_system_resolver=False))
        result = client.query_nameserver(
            "example.com",
            NameserverConfig(ip="1.1.1.1"),
            [RecordType.TXT],
        )
        assert result.status == DNSServerStatus.OK
        assert [r.value for r in result.records] == ['"hello world"']

    def test_cname_chain_only_keeps_queried_type(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cname = _rrset(
            "www.example.com", "CNAME", 60, "host.example.com."
        )
        a = _rrset("host.example.com", "A", 60, "10.0.0.1")
        resp = _make_response(
            "www.example.com", rdtype="A", answer=[cname, a]
        )

        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            return resp

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        client = DNSClient(Config(use_system_resolver=False))
        result = client.query_nameserver(
            "www.example.com",
            NameserverConfig(ip="1.1.1.1"),
            [RecordType.A],
        )
        assert [r.type for r in result.records] == [RecordType.A]
        assert result.records[0].name == "host.example.com."

    def test_invalid_domain(self) -> None:
        with pytest.raises(ValueError):
            validate_domain("bad..domain")


class TestQueryDomain:
    def test_parallel_collects_all_servers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = DNSClient(
            Config(use_system_resolver=False),
            nameservers=["1.1.1.1", "8.8.8.8"],
        )
        answers = {"1.1.1.1": "1.2.3.4", "8.8.8.8": "5.6.7.8"}

        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            return _make_response(
                "example.com",
                rdtype="A",
                answer=[_rrset("example.com", "A", 60, answers[server])],
            )

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        result = client.query_domain("example.com", [RecordType.A])

        assert result.domain == "example.com"
        assert result.queried_at.tzinfo is not None
        assert len(result.server_responses) == 2
        assert [r.server for r in result.server_responses] == [
            "1.1.1.1",
            "8.8.8.8",
        ]
        assert all(
            r.status == DNSServerStatus.OK for r in result.server_responses
        )
        assert result.server_responses[0].response_time_ms > 0

    def test_server_label_matches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = Config(use_system_resolver=False)
        config.nameservers = [
            NameserverConfig(ip="1.1.1.1", label="Cloudflare")
        ]
        client = DNSClient(config)

        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            return _make_response(
                "example.com",
                rdtype="A",
                answer=[_rrset("example.com", "A", 60, "1.2.3.4")],
            )

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        result = client.query_domain("example.com", [RecordType.A])
        assert result.server_responses[0].server == "Cloudflare"

    def test_record_types_from_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = Config(use_system_resolver=False)
        config.record_types = [RecordType.A, RecordType.MX]
        client = DNSClient(config, nameservers=["1.1.1.1"])
        seen: list[RecordType] = []

        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            rdtype = query.question[0].rdtype
            rtype = RecordType(dt.to_text(rdtype))
            seen.append(rtype)
            answer = (
                [_rrset("example.com", "A", 60, "1.2.3.4")]
                if rtype is RecordType.A
                else [_rrset("example.com", "MX", 60, "10 mail.example.com.")]
            )
            return _make_response(
                "example.com", rdtype=rtype.value, answer=answer
            )

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)
        client.query_domain("example.com")
        assert seen == [RecordType.A, RecordType.MX]


class TestAsync:
    def test_query_domain_async(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = DNSClient(
            Config(use_system_resolver=False), nameservers=["1.1.1.1"]
        )

        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            return _make_response(
                "example.com",
                rdtype="A",
                answer=[_rrset("example.com", "A", 60, "1.2.3.4")],
            )

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)

        result = asyncio.run(
            client.query_domain_async(
                "example.com", [RecordType.A]
            )
        )
        assert result.server_responses[0].status == DNSServerStatus.OK
        assert result.server_responses[0].records[0].value == "1.2.3.4"

    def test_query_domains_async(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = DNSClient(
            Config(use_system_resolver=False), nameservers=["1.1.1.1"]
        )

        def fake_udp(
            query: Message, server: str, timeout: float
        ) -> Message:
            domain = str(query.question[0].name)
            assert domain.endswith(".")
            return _make_response(
                domain,
                rdtype="A",
                answer=[_rrset(domain[:-1], "A", 60, "1.2.3.4")],
            )

        monkeypatch.setattr(dns_engine, "_query_udp", fake_udp)

        results = asyncio.run(
            client.query_domains_async(
                ["example.com", "test.com"],
                max_concurrency=2,
            )
        )
        assert [r.domain for r in results] == [
            "example.com",
            "test.com",
        ]


class TestHelpers:
    def test_coerce_record_types(self) -> None:
        assert coerce_record_types(
            ["a", RecordType.MX, "SRV"]
        ) == [RecordType.A, RecordType.MX, RecordType.SRV]

    def test_coerce_record_types_invalid(self) -> None:
        with pytest.raises(ValueError, match="unknown record type"):
            coerce_record_types(["FOOBAR"])

    def test_validate_domain_absolute(self) -> None:
        name = validate_domain("example.com")
        assert name.is_absolute()
        assert str(name).endswith(".")
