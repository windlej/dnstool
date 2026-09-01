"""Snapshot store: on-disk backups of per-domain DNS records.

Phase 4 decision on compliance reports: snapshots deliberately store records
only. Producing a ``ComplianceReport`` requires its own extra DNS queries (the
``_dmarc``/``_domainkey`` probes in ``checks.with_compliance_probes``) and both
``DomainSnapshot`` and ``DomainDiff`` are purely record-oriented models.
Attaching reports would complicate the model and the on-disk format with no
consumer yet, so it is skipped. Compliance history gets its own home under
``HISTORY_DIR`` in a later phase.

On-disk layout: ``<BACKUPS_DIR>/<domain>/<YYYYMMDDTHHMMSS>.json``. Multiple
snapshots captured within the same second get ``_1``, ``_2``, ... suffixes.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from dnstool.config import BACKUPS_DIR, Config
from dnstool.dns_engine import DNSClient
from dnstool.models import DomainDiff, DomainSnapshot, RecordType

_TIMESTAMP_FMT = "%Y%m%dT%H%M%S"


def normalize_domain(domain: str) -> str:
    """Lowercase a domain and strip a trailing root dot for consistent keys."""
    normalized = domain.strip().lower()
    return normalized[:-1] if normalized.endswith(".") else normalized


def _normalize_ts(value: str) -> str:
    """Collapse a (possibly partial) timestamp string into a comparable form."""
    return (
        value.strip()
        .lower()
        .replace("-", "")
        .replace(":", "")
        .replace(".", "")
        .replace("z", "")
        .replace("+", "")
        .replace(" ", "t")
    )


@dataclass(frozen=True)
class SnapshotInfo:
    """Metadata for a single on-disk snapshot."""

    domain: str
    captured_at: datetime
    path: Path
    record_count: int


class SnapshotError(Exception):
    """Base exception for snapshot store failures."""


class NoSnapshotsError(SnapshotError):
    """Raised when a domain has no snapshots (or too few to diff)."""


class SnapshotNotFoundError(SnapshotError):
    """Raised when no snapshot matches a requested timestamp."""


class SnapshotStore:
    """Persist and retrieve per-domain snapshots under one base directory."""

    def __init__(
        self,
        config: Config | None = None,
        base_dir: Path | None = None,
    ) -> None:
        self.config = config or Config()
        self.base_dir = base_dir or BACKUPS_DIR

    def dir_for(self, domain: str) -> Path:
        """Directory holding snapshots for ``domain``."""
        return self.base_dir / normalize_domain(domain)

    def max_snapshots_for(self, domain: str) -> int:
        """Max snapshots to keep for ``domain``, honoring per-domain backup config."""
        domain_cfg = self.config.domains.get(normalize_domain(domain))
        if domain_cfg:
            return domain_cfg.backup.max_snapshots
        return self.config.max_snapshots

    def backup_record_types_for(self, domain: str) -> list[RecordType]:
        """Record types to back up, preferring per-domain backup overrides."""
        domain_cfg = self.config.domains.get(normalize_domain(domain))
        if domain_cfg:
            if domain_cfg.backup.record_types:
                return list(domain_cfg.backup.record_types)
            if domain_cfg.record_types:
                return list(domain_cfg.record_types)
        return list(self.config.record_types)

    def save(self, snapshot: DomainSnapshot) -> Path:
        """Write a snapshot JSON, avoiding filename collisions within a second."""
        domain_dir = self.dir_for(snapshot.domain)
        domain_dir.mkdir(parents=True, exist_ok=True)
        base = snapshot.captured_at.astimezone(timezone.utc).strftime(_TIMESTAMP_FMT)
        path = domain_dir / f"{base}.json"
        suffix = 1
        while path.exists():
            path = domain_dir / f"{base}_{suffix}.json"
            suffix += 1
        snapshot.save(str(path))
        return path

    def list_snapshots(self, domain: str) -> list[SnapshotInfo]:
        """Return snapshot metadata for a domain, oldest first.

        Corrupt files (unreadable JSON, missing keys) are skipped rather than
        failing the whole listing.
        """
        domain_dir = self.dir_for(domain)
        if not domain_dir.is_dir():
            return []
        errors = (json.JSONDecodeError, KeyError, ValueError)
        infos: list[SnapshotInfo] = []
        for path in domain_dir.glob("*.json"):
            try:
                snap = DomainSnapshot.load(str(path))
            except errors:
                continue
            infos.append(
                SnapshotInfo(
                    domain=normalize_domain(domain),
                    captured_at=snap.captured_at,
                    path=path,
                    record_count=sum(len(recs) for recs in snap.records.values()),
                )
            )
        infos.sort(key=lambda info: (info.captured_at, info.path.name))
        return infos

    def list_domains(self) -> list[str]:
        """Sorted list of domains that have at least one snapshot."""
        if not self.base_dir.is_dir():
            return []
        return sorted(p.name for p in self.base_dir.iterdir() if p.is_dir())

    def find_snapshot(self, domain: str, timestamp: str) -> SnapshotInfo | None:
        """Find a snapshot by exact ISO timestamp or by (unique) prefix."""
        infos = self.list_snapshots(domain)
        if not infos:
            return None

        needle = _normalize_ts(timestamp)
        for info in infos:
            if _normalize_ts(info.captured_at.isoformat()) == needle:
                return info

        matches = [
            info
            for info in infos
            if info.path.stem.split("_")[0].lower().startswith(needle)
        ]
        if matches:
            return max(matches, key=lambda info: info.captured_at)
        return None

    def get(self, domain: str, timestamp: str) -> DomainSnapshot:
        """Load a snapshot by timestamp string."""
        info = self.find_snapshot(domain, timestamp)
        if info is None:
            raise SnapshotNotFoundError(
                f"no snapshot for {normalize_domain(domain)} matching timestamp {timestamp!r}"
            )
        return DomainSnapshot.load(str(info.path))

    def latest(self, domain: str) -> DomainSnapshot:
        """Load the most recent snapshot for a domain."""
        infos = self.list_snapshots(domain)
        if not infos:
            raise NoSnapshotsError(f"no snapshots for {normalize_domain(domain)}")
        return DomainSnapshot.load(str(infos[-1].path))

    def saved_path(self, snapshot: DomainSnapshot) -> Path:
        """Path on disk for an already-saved snapshot."""
        infos = self.list_snapshots(snapshot.domain)
        for info in reversed(infos):
            if info.captured_at == snapshot.captured_at:
                return info.path
        raise SnapshotError(
            f"no saved snapshot for {snapshot.domain} at {snapshot.captured_at.isoformat()}"
        )

    def capture(
        self,
        domain: str,
        client: DNSClient | None = None,
        *,
        record_types: Iterable[RecordType] | None = None,
        max_snapshots: int | None = None,
        captured_at: datetime | None = None,
    ) -> DomainSnapshot:
        """Query a domain and persist a snapshot, then prune old ones."""
        domain = normalize_domain(domain)
        client = client or DNSClient()
        types = (
            list(record_types)
            if record_types is not None
            else self.backup_record_types_for(domain)
        )
        result = client.query_domain(domain, types)
        snapshot = DomainSnapshot(
            domain=domain,
            captured_at=captured_at or datetime.now(timezone.utc),
            records=result.unique_records,
        )
        self.save(snapshot)
        self.prune(domain, max_snapshots)
        return snapshot

    def prune(self, domain: str, max_snapshots: int | None = None) -> list[Path]:
        """Delete the oldest snapshots beyond the keep limit.

        ``max_snapshots`` falls back to the per-domain backup config when None.
        Returns the paths removed.
        """
        limit = (
            max_snapshots
            if max_snapshots is not None
            else self.max_snapshots_for(domain)
        )
        infos = self.list_snapshots(domain)
        excess = infos[: -limit] if limit > 0 else infos
        removed: list[Path] = []
        for info in excess:
            with contextlib.suppress(FileNotFoundError):
                info.path.unlink()
            removed.append(info.path)
        return removed

    def resolve_pair(
        self,
        domain: str,
        timestamp1: str | None = None,
        timestamp2: str | None = None,
    ) -> tuple[DomainSnapshot, DomainSnapshot]:
        """Resolve the old/new snapshots for a diff.

        When neither timestamp is given, the two most recent snapshots are
        used. When only one is given, it is paired with the other extreme
        (latest for ``timestamp1``, oldest for ``timestamp2``).
        """
        infos = self.list_snapshots(domain)
        if len(infos) < 2:
            raise NoSnapshotsError(
                f"need at least two snapshots for {normalize_domain(domain)}; have {len(infos)}"
            )

        if timestamp1 and timestamp2:
            old = self.get(domain, timestamp1)
            new = self.get(domain, timestamp2)
        elif timestamp1:
            old = self.get(domain, timestamp1)
            new = self.latest(domain)
        else:
            old = self.latest(domain)
            if timestamp2:
                new = self.get(domain, timestamp2)
            else:
                old = DomainSnapshot.load(str(infos[-2].path))
                new = DomainSnapshot.load(str(infos[-1].path))

        if old.captured_at > new.captured_at:
            old, new = new, old
        return old, new

    def diff(
        self,
        domain: str,
        timestamp1: str | None = None,
        timestamp2: str | None = None,
    ) -> DomainDiff:
        """Diff two snapshots of a domain (defaults to the latest two)."""
        old, new = self.resolve_pair(domain, timestamp1, timestamp2)
        return DomainDiff.compare(old, new)
