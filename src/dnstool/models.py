"""Data models for dnstool."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class RecordType(str, Enum):
    """DNS record types we support."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    SRV = "SRV"
    CAA = "CAA"
    PTR = "PTR"
    DNSKEY = "DNSKEY"
    DS = "DS"
    RRSIG = "RRSIG"
    TLSA = "TLSA"


class CheckSeverity(str, Enum):
    """Severity levels for compliance checks."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    PASS = "pass"


class DNSServerStatus(str, Enum):
    """Status of a DNS server query."""

    OK = "ok"
    TIMEOUT = "timeout"
    ERROR = "error"
    REFUSED = "refused"


@dataclass
class DNSRecord:
    """A single DNS record."""

    type: RecordType
    name: str
    ttl: int
    value: str
    # TXT-specific: each individual character-string (RFC 1035 255-byte limit)
    txt_strings: list[str] | None = None
    # MX-specific
    priority: int | None = None
    # SRV-specific
    weight: int | None = None
    port: int | None = None
    target: str | None = None
    # SOA-specific
    mname: str | None = None
    rname: str | None = None
    serial: int | None = None
    refresh: int | None = None
    retry: int | None = None
    expire: int | None = None
    minimum: int | None = None
    # CAA-specific
    flags: int | None = None
    tag: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class ServerResponse:
    """Response from a single DNS server."""

    server: str
    status: DNSServerStatus
    records: list[DNSRecord] = field(default_factory=list)
    response_time_ms: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["records"] = [r.to_dict() for r in self.records]
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class DomainResult:
    """Combined results for a domain across all servers."""

    domain: str
    queried_at: datetime
    server_responses: list[ServerResponse] = field(default_factory=list)

    @property
    def unique_records(self) -> dict[RecordType, list[DNSRecord]]:
        """Get deduplicated records by type across all servers."""
        seen: dict[str, DNSRecord] = {}
        result: dict[RecordType, list[DNSRecord]] = {}

        for resp in self.server_responses:
            if resp.status != DNSServerStatus.OK:
                continue
            for record in resp.records:
                key = f"{record.type}:{record.name}:{record.value}"
                if key not in seen:
                    seen[key] = record
                    result.setdefault(record.type, []).append(record)

        return result

    @property
    def server_differences(self) -> list[DNSRecord]:
        """Find records that differ between servers."""
        if len(self.server_responses) < 2:
            return []

        record_sets: list[set[str]] = []
        for resp in self.server_responses:
            if resp.status == DNSServerStatus.OK:
                record_sets.append(
                    {f"{r.type}:{r.value}" for r in resp.records}
                )

        if not record_sets:
            return []

        all_records: dict[str, DNSRecord] = {}
        for resp in self.server_responses:
            if resp.status == DNSServerStatus.OK:
                for r in resp.records:
                    all_records[f"{r.type}:{r.value}"] = r

        unified = record_sets[0]
        for rs in record_sets[1:]:
            unified = unified.symmetric_difference(rs)

        return [all_records[key] for key in unified if key in all_records]

    @property
    def average_response_time(self) -> float:
        """Average response time across all successful servers."""
        times = [
            r.response_time_ms
            for r in self.server_responses
            if r.status == DNSServerStatus.OK and r.response_time_ms > 0
        ]
        return sum(times) / len(times) if times else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "queried_at": self.queried_at.isoformat(),
            "server_responses": [r.to_dict() for r in self.server_responses],
        }


@dataclass
class CheckResult:
    """Result of a single compliance/best-practice check."""

    name: str
    severity: CheckSeverity
    message: str
    details: str | None = None
    record_type: RecordType | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        if self.record_type:
            d["record_type"] = self.record_type.value
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class ComplianceReport:
    """Full compliance report for a domain."""

    domain: str
    checked_at: datetime
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Compliance score 0-100."""
        if not self.checks:
            return 0.0
        passed = sum(1 for c in self.checks if c.severity == CheckSeverity.PASS)
        return (passed / len(self.checks)) * 100

    @property
    def critical_issues(self) -> list[CheckResult]:
        return [c for c in self.checks if c.severity == CheckSeverity.CRITICAL]

    @property
    def warnings(self) -> list[CheckResult]:
        return [c for c in self.checks if c.severity == CheckSeverity.WARNING]

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "checked_at": self.checked_at.isoformat(),
            "score": self.score,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class DomainSnapshot:
    """Point-in-time backup of all records for a domain."""

    domain: str
    captured_at: datetime
    records: dict[RecordType, list[DNSRecord]] = field(default_factory=dict)
    raw_json: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "captured_at": self.captured_at.isoformat(),
            "records": {
                rt.value: [r.to_dict() for r in recs]
                for rt, recs in self.records.items()
            },
        }

    def save(self, path: str) -> None:
        """Save snapshot to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> DomainSnapshot:
        """Load snapshot from JSON file."""
        with open(path) as f:
            data = json.load(f)

        records: dict[RecordType, list[DNSRecord]] = {}
        for rt_str, recs in data.get("records", {}).items():
            rt = RecordType(rt_str)
            records[rt] = [
                DNSRecord(type=RecordType(r["type"]), **{k: v for k, v in r.items() if k != "type"})
                for r in recs
            ]

        return cls(
            domain=data["domain"],
            captured_at=datetime.fromisoformat(data["captured_at"]),
            records=records,
        )


@dataclass
class DomainDiff:
    """Difference between two snapshots."""

    domain: str
    old_snapshot: DomainSnapshot
    new_snapshot: DomainSnapshot
    added: list[DNSRecord] = field(default_factory=list)
    removed: list[DNSRecord] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def compare(cls, old: DomainSnapshot, new: DomainSnapshot) -> DomainDiff:
        """Compare two snapshots and compute diff."""
        old_records: dict[str, DNSRecord] = {}
        for recs in old.records.values():
            for r in recs:
                key = f"{r.type}:{r.name}:{r.value}"
                old_records[key] = r

        new_records: dict[str, DNSRecord] = {}
        for recs in new.records.values():
            for r in recs:
                key = f"{r.type}:{r.name}:{r.value}"
                new_records[key] = r

        old_keys = set(old_records.keys())
        new_keys = set(new_records.keys())

        added = [new_records[k] for k in new_keys - old_keys]
        removed = [old_records[k] for k in old_keys - new_keys]

        changed = []
        for key in old_keys & new_keys:
            old_r = old_records[key]
            new_r = new_records[key]
            diffs = {}
            old_d = old_r.to_dict()
            new_d = new_r.to_dict()
            for field_name in set(old_d.keys()) | set(new_d.keys()):
                if old_d.get(field_name) != new_d.get(field_name):
                    diffs[field_name] = {"old": old_d.get(field_name), "new": new_d.get(field_name)}
            if diffs:
                changed.append({"record_key": key, "changes": diffs})

        return cls(
            domain=old.domain,
            old_snapshot=old,
            new_snapshot=new,
            added=added,
            removed=removed,
            changed=changed,
        )

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "old_snapshot": self.old_snapshot.to_dict(),
            "new_snapshot": self.new_snapshot.to_dict(),
            "added": [r.to_dict() for r in self.added],
            "removed": [r.to_dict() for r in self.removed],
            "changed": self.changed,
            "has_changes": self.has_changes,
        }
