"""Tests for the tracked-domains registry."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from dnstool.config import Config, DomainConfig, ScheduleConfig
from dnstool.tracking import (
    DomainNotTrackedError,
    TrackedDomain,
    TrackedRegistry,
)


def _registry(tmp_path: Path) -> TrackedRegistry:
    return TrackedRegistry(base_dir=tmp_path / "tracked")


class TestAdd:
    def test_add_writes_entry_and_get_roundtrips(self, tmp_path: Path) -> None:
        registry = _registry(tmp_path)

        entry = registry.add("Example.COM.")

        assert entry.domain == "example.com"
        assert entry.added_at.tzinfo is not None
        assert entry.schedule == ScheduleConfig()
        loaded = registry.get("example.com")
        assert loaded is not None
        assert loaded.domain == "example.com"
        assert loaded.added_at == entry.added_at

    def test_add_honors_schedule_config(self, tmp_path: Path) -> None:
        schedule = ScheduleConfig(enabled=True, cron="*/6 * * * *")
        registry = _registry(tmp_path)

        entry = registry.add("example.com", schedule)

        assert entry.schedule == schedule
        assert registry.get("example.com") is not None

    def test_add_looks_up_per_domain_schedule_from_config(self, tmp_path: Path) -> None:
        config = Config(use_system_resolver=False)
        config.domains["example.com"] = DomainConfig(
            schedule=ScheduleConfig(enabled=True, cron="0 3 * * *")
        )
        registry = _registry(tmp_path)

        entry = registry.add("example.com", config.domains["example.com"].schedule)

        assert entry.schedule.enabled is True
        assert entry.schedule.cron == "0 3 * * *"

    def test_retracking_updates_schedule_but_keeps_added_at(self, tmp_path: Path) -> None:
        registry = _registry(tmp_path)
        first = registry.add("example.com")
        original = first.added_at

        second = registry.add("example.com", ScheduleConfig(enabled=True, cron="* * * * *"))

        assert second.added_at == original
        assert second.schedule.cron == "* * * * *"


class TestRemove:
    def test_remove_deletes_entry_and_reports_it(self, tmp_path: Path) -> None:
        registry = _registry(tmp_path)
        registry.add("example.com")

        removed = registry.remove("example.com")

        assert removed.domain == "example.com"
        assert registry.get("example.com") is None
        assert registry.list() == []

    def test_remove_untracked_raises(self, tmp_path: Path) -> None:
        registry = _registry(tmp_path)
        with pytest.raises(DomainNotTrackedError, match="not tracked"):
            registry.remove("example.com")


class TestList:
    def test_list_sorted_by_domain(self, tmp_path: Path) -> None:
        registry = _registry(tmp_path)
        registry.add("zeta.com")
        registry.add("alpha.com")
        registry.add("beta.com")

        assert [e.domain for e in registry.list()] == [
            "alpha.com",
            "beta.com",
            "zeta.com",
        ]

    def test_list_empty_when_nothing_tracked(self, tmp_path: Path) -> None:
        assert _registry(tmp_path).list() == []

    def test_list_skips_corrupt_files(self, tmp_path: Path) -> None:
        registry = _registry(tmp_path)
        registry.add("alpha.com")
        (tmp_path / "tracked/broken.json").write_text("{not json")

        assert [e.domain for e in registry.list()] == ["alpha.com"]


class TestTrackedDomain:
    def test_to_dict_from_dict_roundtrip(self) -> None:
        entry = TrackedDomain(
            domain="example.com",
            added_at=datetime(2026, 9, 1, 12, 0, 0),
            schedule=ScheduleConfig(enabled=True, cron="*/6 * * * *"),
        )

        restored = TrackedDomain.from_dict(entry.to_dict())

        assert restored == entry

    def test_from_dict_defaults_missing_schedule(self) -> None:
        restored = TrackedDomain.from_dict(
            {"domain": "example.com", "added_at": "2026-09-01T12:00:00+00:00"}
        )

        assert restored.schedule == ScheduleConfig()
        assert restored.schedule.notify_on_change is True
