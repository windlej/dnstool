"""Tracked-domains registry.

Each tracked domain is a small JSON file under ``<TRACKED_DIR>/<domain>.json``
carrying the domain, when it was added, and the per-domain ``ScheduleConfig``
snapshot it was registered with (sourced from ``config.toml`` at add time).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dnstool.config import TRACKED_DIR, ScheduleConfig
from dnstool.snapshots import normalize_domain


@dataclass
class TrackedDomain:
    """A domain in the tracking registry."""

    domain: str
    added_at: datetime
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "added_at": self.added_at.isoformat(),
            "schedule": asdict(self.schedule),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrackedDomain:
        schedule = data.get("schedule", {})
        return cls(
            domain=normalize_domain(data["domain"]),
            added_at=datetime.fromisoformat(data["added_at"]),
            schedule=ScheduleConfig(
                enabled=bool(schedule.get("enabled", False)),
                cron=str(schedule.get("cron", "")),
                notify_on_change=bool(schedule.get("notify_on_change", True)),
            ),
        )


class TrackedError(Exception):
    """Base exception for the tracking registry."""


class DomainNotTrackedError(TrackedError):
    """Raised when removing a domain that is not tracked."""


class TrackedRegistry:
    """Persist and query the tracked-domains list under ``TRACKED_DIR``."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or TRACKED_DIR

    def path_for(self, domain: str) -> Path:
        return self.base_dir / f"{normalize_domain(domain)}.json"

    def add(
        self, domain: str, schedule: ScheduleConfig | None = None
    ) -> TrackedDomain:
        """Track a domain.

        Re-tracking an existing domain is idempotent: the original ``added_at``
        is preserved while the schedule is refreshed.
        """
        domain = normalize_domain(domain)
        existing = self.get(domain)
        entry = TrackedDomain(
            domain=domain,
            added_at=existing.added_at if existing else datetime.now(timezone.utc),
            schedule=schedule or (existing.schedule if existing else ScheduleConfig()),
        )
        self.base_dir.mkdir(parents=True, exist_ok=True)
        with open(self.path_for(domain), "w") as f:
            json.dump(entry.to_dict(), f, indent=2)
        return entry

    def remove(self, domain: str) -> TrackedDomain:
        """Untrack a domain, returning the removed entry."""
        domain = normalize_domain(domain)
        entry = self.get(domain)
        if entry is None:
            raise DomainNotTrackedError(f"{domain} is not tracked")
        self.path_for(domain).unlink()
        return entry

    def get(self, domain: str) -> TrackedDomain | None:
        """Look up a single tracked domain by name."""
        path = self.path_for(domain)
        if not path.exists():
            return None
        return self._load(path)

    def list(self) -> list[TrackedDomain]:
        """All tracked domains, sorted alphabetically by domain.

        Corrupt files (unreadable JSON, missing keys) are skipped rather than
        failing the whole listing.
        """
        if not self.base_dir.is_dir():
            return []
        entries: list[TrackedDomain] = []
        errors = (json.JSONDecodeError, KeyError, ValueError)
        for path in sorted(self.base_dir.glob("*.json")):
            try:
                entries.append(self._load(path))
            except errors:
                continue
        entries.sort(key=lambda entry: entry.domain)
        return entries

    @staticmethod
    def _load(path: Path) -> TrackedDomain:
        with open(path) as f:
            return TrackedDomain.from_dict(json.load(f))
