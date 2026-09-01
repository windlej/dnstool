"""Tests for the append-only per-domain change log."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from dnstool.config import Config
from dnstool.history import (
    ChangeStatus,
    HistoryEntry,
    last_entry,
    log_run,
    parse_entry,
    path_for,
)
from dnstool.models import DNSRecord, DomainSnapshot, RecordType
from dnstool.snapshots import SnapshotStore

A = RecordType.A


def _rec(
    rtype: RecordType,
    name: str,
    value: str,
    **kwargs: object,
) -> DNSRecord:
    return DNSRecord(type=rtype, name=name, ttl=300, value=value, **kwargs)


def _seed_snapshot(day: int, *records: DNSRecord) -> DomainSnapshot:
    return DomainSnapshot(
        domain="example.com",
        captured_at=datetime(2000, 1, day, 12, 0, 0, tzinfo=timezone.utc),
        records={A: list(records)},
    )


def _store(tmp_path: Path) -> SnapshotStore:
    return SnapshotStore(
        Config(use_system_resolver=False),
        base_dir=tmp_path / "backups",
    )


def _history_dir(tmp_path: Path) -> Path:
    return tmp_path / "history"


class TestPathFor:
    def test_uses_normalized_domain_log(self, tmp_path: Path) -> None:
        assert path_for("Example.COM.", tmp_path) == tmp_path / "example.com.log"


class TestParseEntry:
    def test_parses_no_change(self) -> None:
        entry = parse_entry("2026-09-01T21:00:00Z NO_CHANGE")
        assert entry == HistoryEntry(
            timestamp=datetime(2026, 9, 1, 21, 0, 0, tzinfo=timezone.utc),
            status=ChangeStatus.NO_CHANGE,
        )

    def test_parses_changed_counts(self) -> None:
        entry = parse_entry("2026-09-01T21:00:00Z CHANGED added=2 removed=1 changed=1")
        assert entry.added == 2
        assert entry.removed == 1
        assert entry.changed == 1

    def test_roundtrip(self) -> None:
        entry = HistoryEntry(
            timestamp=datetime(2026, 9, 1, 21, 0, 0, tzinfo=timezone.utc),
            status=ChangeStatus.CHANGED,
            added=2,
            removed=1,
            changed=1,
        )
        assert parse_entry(entry.line) == entry


class TestLogRun:
    def test_initial_on_first_snapshot(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.save(_seed_snapshot(1, _rec(A, "example.com.", "1.2.3.4")))

        entry = log_run(store, "example.com", base_dir=_history_dir(tmp_path))

        assert entry.status is ChangeStatus.INITIAL
        assert last_entry("example.com", base_dir=_history_dir(tmp_path)) == entry

    def test_no_change_when_snapshots_match(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.save(_seed_snapshot(1, _rec(A, "example.com.", "1.2.3.4")))
        store.save(_seed_snapshot(2, _rec(A, "example.com.", "1.2.3.4")))

        entry = log_run(store, "example.com", base_dir=_history_dir(tmp_path))

        assert entry.status is ChangeStatus.NO_CHANGE
        assert (entry.added, entry.removed, entry.changed) == (0, 0, 0)

    def test_changed_reports_record_counts(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.save(
            _seed_snapshot(
                1,
                _rec(A, "example.com.", "1.2.3.4"),
                _rec(A, "example.com.", "1.2.3.6"),
                DNSRecord(type=A, name="example.com.", ttl=300, value="1.2.3.7"),
            )
        )
        store.save(
            _seed_snapshot(
                2,
                _rec(A, "example.com.", "1.2.3.4"),
                _rec(A, "example.com.", "1.2.3.5"),
                DNSRecord(type=A, name="example.com.", ttl=600, value="1.2.3.7"),
            )
        )

        entry = log_run(store, "example.com", base_dir=_history_dir(tmp_path))

        assert entry.status is ChangeStatus.CHANGED
        assert (entry.added, entry.removed, entry.changed) == (1, 1, 1)

    def test_log_is_append_only(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        base = _history_dir(tmp_path)

        log_run(store, "example.com", base_dir=base)
        log_run(store, "example.com", base_dir=base)

        lines = path_for("example.com", base).read_text().splitlines()
        assert len(lines) == 2
        assert last_entry("example.com", base_dir=base) == parse_entry(lines[-1])

    def test_no_snapshots_yields_initial_without_error(self, tmp_path: Path) -> None:
        store = _store(tmp_path)

        entry = log_run(store, "example.com", base_dir=_history_dir(tmp_path))

        assert entry.status is ChangeStatus.INITIAL


class TestLastEntry:
    def test_none_when_log_missing(self, tmp_path: Path) -> None:
        assert last_entry("example.com", base_dir=_history_dir(tmp_path)) is None

    def test_none_when_log_empty(self, tmp_path: Path) -> None:
        path = path_for("example.com", _history_dir(tmp_path))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n")
        assert last_entry("example.com", base_dir=_history_dir(tmp_path)) is None
