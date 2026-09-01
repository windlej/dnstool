"""Tests for the snapshot store."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from dnstool.config import BackupConfig, Config, DomainConfig
from dnstool.dns_engine import DNSClient
from dnstool.models import (
    DNSRecord,
    DNSServerStatus,
    DomainResult,
    DomainSnapshot,
    RecordType,
    ServerResponse,
)
from dnstool.snapshots import (
    NoSnapshotsError,
    SnapshotNotFoundError,
    SnapshotStore,
    normalize_domain,
)

A = RecordType.A
MX = RecordType.MX
TXT = RecordType.TXT


def _rec(
    rtype: RecordType,
    name: str,
    value: str,
    **kwargs: object,
) -> DNSRecord:
    return DNSRecord(type=rtype, name=name, ttl=300, value=value, **kwargs)  # type: ignore[arg-type]


def _result(domain: str, *records: DNSRecord) -> DomainResult:
    return DomainResult(
        domain=domain,
        queried_at=datetime.now(timezone.utc),
        server_responses=[
            ServerResponse(
                server="1.1.1.1",
                status=DNSServerStatus.OK,
                records=list(records),
            )
        ],
    )


def _fake_query(
    records_by: dict[str, list[DNSRecord]],
) -> object:
    def fake(
        self: DNSClient, domain: str, record_types: object | None = None
    ) -> DomainResult:
        return _result(domain, *records_by.get(domain, []))

    return fake


def _ts(day: int, hour: int = 12, minute: int = 0, microsecond: int = 0) -> datetime:
    return datetime(2026, 9, day, hour, minute, 0, microsecond, tzinfo=timezone.utc)


def _store(tmp_path: Path, config: Config | None = None) -> SnapshotStore:
    return SnapshotStore(
        config or Config(use_system_resolver=False),
        base_dir=tmp_path / "backups",
    )


class TestNormalizeDomain:
    def test_lowercases_and_strips_root_dot(self) -> None:
        assert normalize_domain("Example.COM.") == "example.com"

    def test_keeps_plain_input(self) -> None:
        assert normalize_domain("example.com") == "example.com"


class TestCapture:
    def test_capture_writes_json_and_returns_snapshot(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        records = [_rec(A, "example.com.", "1.2.3.4")]
        monkeypatch.setattr(DNSClient, "query_domain", _fake_query({"example.com": records}))
        store = _store(tmp_path)

        snapshot = store.capture("example.com", captured_at=_ts(1))

        assert snapshot.domain == "example.com"
        assert snapshot.records[A] == records
        assert snapshot.captured_at == _ts(1)
        saved = tmp_path / "backups/example.com/20260901T120000.json"
        assert saved.exists()
        assert DomainSnapshot.load(str(saved)).to_dict() == snapshot.to_dict()

    def test_capture_dedups_records_across_servers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        record = _rec(A, "example.com.", "1.2.3.4")

        def fake_dedup(
            self: DNSClient, domain: str, record_types: object | None = None
        ) -> DomainResult:
            return DomainResult(
                domain=domain,
                queried_at=datetime.now(timezone.utc),
                server_responses=[
                    ServerResponse("1.1.1.1", DNSServerStatus.OK, [record]),
                    ServerResponse("8.8.8.8", DNSServerStatus.OK, [record]),
                ],
            )

        monkeypatch.setattr(DNSClient, "query_domain", fake_dedup)
        store = _store(tmp_path)

        snapshot = store.capture("example.com", captured_at=_ts(1))

        assert len(snapshot.records[A]) == 1

    def test_capture_honors_record_types(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[object] = []

        def fake_spy(
            self: DNSClient, domain: str, record_types: object | None = None
        ) -> DomainResult:
            seen.append(record_types)
            return _result(domain, _rec(A, domain + ".", "1.2.3.4"))

        monkeypatch.setattr(DNSClient, "query_domain", fake_spy)
        store = _store(tmp_path)

        store.capture("example.com", record_types=[A], captured_at=_ts(1))

        assert seen == [[A]]

    def test_capture_prefers_per_domain_backup_record_types(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = Config(use_system_resolver=False)
        config.record_types = [A, MX, TXT]
        config.domains["example.com"] = DomainConfig(
            backup=BackupConfig(record_types=[MX])
        )
        seen: list[object] = []

        def fake_spy(
            self: DNSClient, domain: str, record_types: object | None = None
        ) -> DomainResult:
            seen.append(record_types)
            return _result(domain)

        monkeypatch.setattr(DNSClient, "query_domain", fake_spy)
        store = _store(tmp_path, config)

        store.capture("example.com", captured_at=_ts(1))

        assert seen == [[MX]]

    def test_same_second_saves_use_suffix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            DNSClient,
            "query_domain",
            _fake_query({"example.com": [_rec(A, "example.com.", "1.2.3.4")]}),
        )
        store = _store(tmp_path)

        store.capture("example.com", captured_at=_ts(1, microsecond=100))
        store.capture("example.com", captured_at=_ts(1, microsecond=900))

        files = sorted((tmp_path / "backups/example.com").glob("*.json"))
        assert [f.name for f in files] == [
            "20260901T120000.json",
            "20260901T120000_1.json",
        ]


class TestPrune:
    def test_prune_deletes_oldest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            DNSClient, "query_domain", _fake_query({"d.com": [_rec(A, "d.com.", "1.2.3.4")]})
        )
        store = _store(tmp_path)

        for minute in range(4):
            store.capture("d.com", max_snapshots=2, captured_at=_ts(1, 12, minute))

        infos = store.list_snapshots("d.com")
        assert [info.captured_at.minute for info in infos] == [2, 3]
        assert [i.path.name for i in infos] == [
            "20260901T120200.json",
            "20260901T120300.json",
        ]

    def test_max_snapshots_zero_keeps_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            DNSClient, "query_domain", _fake_query({"d.com": [_rec(A, "d.com.", "1.2.3.4")]})
        )
        store = _store(tmp_path)
        store.capture("d.com", max_snapshots=0, captured_at=_ts(1))
        assert store.list_snapshots("d.com") == []

    def test_per_domain_backup_config_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = Config(use_system_resolver=False, max_snapshots=1)
        config.domains["d.com"] = DomainConfig(backup=BackupConfig(max_snapshots=3))
        store = _store(tmp_path, config)
        monkeypatch.setattr(
            DNSClient, "query_domain", _fake_query({"d.com": [_rec(A, "d.com.", "1.2.3.4")]})
        )

        for hour in range(12, 15):
            store.capture("d.com", captured_at=_ts(1, hour))

        assert len(store.list_snapshots("d.com")) == 3
        assert store.max_snapshots_for("d.com") == 3

    def test_global_max_snapshots_fallback(self, tmp_path: Path) -> None:
        config = Config(use_system_resolver=False, max_snapshots=7)
        store = _store(tmp_path, config)
        assert store.max_snapshots_for("untracked.com") == 7
        assert store.backup_record_types_for("untracked.com") == config.record_types


class TestListing:
    def test_list_snapshots_sorted_oldest_first(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            DNSClient, "query_domain", _fake_query({"d.com": [_rec(A, "d.com.", "1.2.3.4")]})
        )
        store = _store(tmp_path)
        store.capture("d.com", captured_at=_ts(1, 12))
        store.capture("d.com", captured_at=_ts(3, 12))

        infos = store.list_snapshots("d.com")
        assert [i.captured_at.day for i in infos] == [1, 3]
        assert infos[0].record_count == 1
        assert infos[0].domain == "d.com"

    def test_list_snapshots_skips_corrupt_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            DNSClient, "query_domain", _fake_query({"d.com": [_rec(A, "d.com.", "1.2.3.4")]})
        )
        store = _store(tmp_path)
        store.capture("d.com", captured_at=_ts(1))
        (tmp_path / "backups/d.com/garbage.json").write_text("{not json")

        assert len(store.list_snapshots("d.com")) == 1

    def test_list_domains(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(DNSClient, "query_domain", _fake_query({}))
        store = _store(tmp_path)
        store.capture("b.com", captured_at=_ts(1))
        store.capture("a.com", captured_at=_ts(1))

        assert store.list_domains() == ["a.com", "b.com"]

    def test_latest(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            DNSClient, "query_domain", _fake_query({"d.com": [_rec(A, "d.com.", "1.2.3.4")]})
        )
        store = _store(tmp_path)
        store.capture("d.com", captured_at=_ts(1))
        store.capture("d.com", captured_at=_ts(3))

        assert store.latest("d.com").captured_at == _ts(3)

    def test_latest_missing_raises(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        with pytest.raises(NoSnapshotsError, match="no snapshots"):
            store.latest("d.com")


class TestLoadByTimestamp:
    def _two_snapshots(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            DNSClient, "query_domain", _fake_query({"d.com": [_rec(A, "d.com.", "1.2.3.4")]})
        )
        store = _store(tmp_path)
        store.capture("d.com", captured_at=_ts(1, 12, 0))
        store.capture("d.com", captured_at=_ts(2, 13, 30))

    def test_get_by_exact_compact_timestamp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._two_snapshots(tmp_path, monkeypatch)
        store = _store(tmp_path)
        snapshot = store.get("d.com", "20260902T133000")
        assert snapshot.captured_at == _ts(2, 13, 30)

    def test_get_by_iso_timestamp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._two_snapshots(tmp_path, monkeypatch)
        store = _store(tmp_path)
        snapshot = store.get("d.com", _ts(1, 12, 0).isoformat())
        assert snapshot.captured_at == _ts(1, 12, 0)

    def test_get_by_date_prefix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._two_snapshots(tmp_path, monkeypatch)
        store = _store(tmp_path)
        snapshot = store.get("d.com", "2026-09-02")
        assert snapshot.captured_at == _ts(2, 13, 30)

    def test_get_missing_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._two_snapshots(tmp_path, monkeypatch)
        store = _store(tmp_path)
        with pytest.raises(SnapshotNotFoundError, match="no snapshot"):
            store.get("d.com", "1999-01-01")


class TestDiff:
    def _seed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> SnapshotStore:
        old_records = [
            _rec(A, "d.com.", "1.2.3.4"),
            _rec(MX, "d.com.", "10 mail.d.com.", priority=10),
        ]
        new_records = [
            _rec(A, "d.com.", "1.2.3.4"),
            _rec(A, "d.com.", "1.2.3.5"),
        ]

        def fake(self: DNSClient, domain: str, record_types: object | None = None) -> DomainResult:
            return _result(domain, *old_records)

        def fake2(self: DNSClient, domain: str, record_types: object | None = None) -> DomainResult:
            return _result(domain, *new_records)

        store = _store(tmp_path)
        monkeypatch.setattr(DNSClient, "query_domain", fake)
        store.capture("d.com", captured_at=_ts(1))
        monkeypatch.setattr(DNSClient, "query_domain", fake2)
        store.capture("d.com", captured_at=_ts(2))
        return store

    @staticmethod
    def _values(records: list[DNSRecord]) -> list[str]:
        return sorted(r.value for r in records)

    def test_diff_defaults_to_latest_two(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = self._seed(tmp_path, monkeypatch)

        diff = store.diff("d.com")

        assert diff.old_snapshot.captured_at == _ts(1)
        assert diff.new_snapshot.captured_at == _ts(2)
        assert self._values(diff.added) == ["1.2.3.5"]
        assert self._values(diff.removed) == ["10 mail.d.com."]
        assert diff.changed == []
        assert diff.has_changes

    def test_diff_with_explicit_timestamps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = self._seed(tmp_path, monkeypatch)

        diff = store.diff("d.com", "2026-09-01", "2026-09-02")

        assert self._values(diff.added) == ["1.2.3.5"]

    def test_diff_reorders_out_of_order_timestamps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = self._seed(tmp_path, monkeypatch)

        diff = store.diff("d.com", "2026-09-02", "2026-09-01")

        assert diff.old_snapshot.captured_at == _ts(1)
        assert diff.new_snapshot.captured_at == _ts(2)

    def test_diff_single_timestamp_pairs_with_latest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = self._seed(tmp_path, monkeypatch)

        diff = store.diff("d.com", "2026-09-01")

        assert diff.new_snapshot.captured_at == _ts(2)

    def test_diff_requires_at_least_two_snapshots(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            DNSClient,
            "query_domain",
            _fake_query({"d.com": [_rec(A, "d.com.", "1.2.3.4")]}),
        )
        store = _store(tmp_path)
        store.capture("d.com", captured_at=_ts(1))

        with pytest.raises(NoSnapshotsError, match="at least two"):
            store.diff("d.com")

    def test_no_changes_when_identical(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        records = [_rec(A, "d.com.", "1.2.3.4")]
        monkeypatch.setattr(DNSClient, "query_domain", _fake_query({"d.com": records}))
        store = _store(tmp_path)
        store.capture("d.com", captured_at=_ts(1))
        store.capture("d.com", captured_at=_ts(2))

        diff = store.diff("d.com")

        assert not diff.has_changes
        assert diff.added == []
        assert diff.removed == []


class TestDiffToDict:
    def test_to_dict_serializes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        records = [_rec(A, "d.com.", "1.2.3.4")]
        records_new = records + [_rec(A, "d.com.", "1.2.3.5")]

        def fake(self: DNSClient, domain: str, record_types: object | None = None) -> DomainResult:
            return _result(domain, *records)

        def fake2(self: DNSClient, domain: str, record_types: object | None = None) -> DomainResult:
            return _result(domain, *records_new)

        monkeypatch.setattr(DNSClient, "query_domain", fake)
        store = _store(tmp_path)
        store.capture("d.com", captured_at=_ts(1))
        monkeypatch.setattr(DNSClient, "query_domain", fake2)
        store.capture("d.com", captured_at=_ts(2))

        payload = store.diff("d.com").to_dict()
        json.dumps(payload)
        assert payload["added"][0]["value"] == "1.2.3.5"
        assert payload["changed"] == []
        assert payload["has_changes"] is True
