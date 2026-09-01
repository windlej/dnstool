"""Tests for the CLI commands (backup, diff, track)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

import dnstool.config as config_module
import dnstool.history as history_module
import dnstool.snapshots as snapshots_module
import dnstool.tracking as tracking_module
from dnstool.__main__ import app
from dnstool.config import Config
from dnstool.dns_engine import DNSClient, DNSEngineError
from dnstool.history import ChangeStatus, last_entry
from dnstool.models import (
    DNSRecord,
    DNSServerStatus,
    DomainResult,
    DomainSnapshot,
    RecordType,
    ServerResponse,
)
from dnstool.snapshots import SnapshotStore

runner = CliRunner()

A = RecordType.A
MX = RecordType.MX


def _rec(rtype: RecordType, name: str, value: str, **kwargs: object) -> DNSRecord:
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


def _fake_query(records_by: dict[str, list[DNSRecord]]) -> object:
    def fake(
        self: DNSClient, domain: str, record_types: object | None = None
    ) -> DomainResult:
        return _result(domain, *records_by.get(domain, []))

    return fake


@pytest.fixture
def isolated_dirs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> dict[str, Path]:
    """Point every dnstool data directory at an isolated tmp_path."""
    config_dir = tmp_path / "config"
    dirs = {
        "config": config_dir,
        "tracked": config_dir / "tracked",
        "backups": config_dir / "backups",
        "history": config_dir / "history",
    }
    monkeypatch.setattr(config_module, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(config_module, "CONFIG_FILE", config_dir / "config.toml")
    monkeypatch.setattr(config_module, "TRACKED_DIR", dirs["tracked"])
    monkeypatch.setattr(config_module, "BACKUPS_DIR", dirs["backups"])
    monkeypatch.setattr(config_module, "HISTORY_DIR", dirs["history"])
    monkeypatch.setattr(snapshots_module, "BACKUPS_DIR", dirs["backups"])
    monkeypatch.setattr(tracking_module, "TRACKED_DIR", dirs["tracked"])
    monkeypatch.setattr(history_module, "HISTORY_DIR", dirs["history"])
    return dirs


class TestTrackCommand:
    def test_add_list_remove_cycle(
        self, isolated_dirs: dict[str, Path]
    ) -> None:
        result = runner.invoke(app, ["track", "example.com"])
        assert result.exit_code == 0
        assert "Now tracking example.com" in result.stdout

        result = runner.invoke(app, ["track", "--list"])
        assert result.exit_code == 0
        assert "example.com" in result.stdout

        result = runner.invoke(app, ["track", "example.com", "--remove"])
        assert result.exit_code == 0
        assert "Removed example.com" in result.stdout

        result = runner.invoke(app, ["track", "--list"])
        assert "No tracked domains." in result.stdout

    def test_remove_untracked_fails(self, isolated_dirs: dict[str, Path]) -> None:
        result = runner.invoke(app, ["track", "nope.com", "--remove"])
        assert result.exit_code == 1
        assert "not tracked" in result.stderr

    def test_list_json(self, isolated_dirs: dict[str, Path]) -> None:
        runner.invoke(app, ["track", "example.com"])
        result = runner.invoke(app, ["track", "--list", "--json"])
        assert result.exit_code == 0
        assert '"domain": "example.com"' in result.stdout


class TestBackupCommand:
    def test_backup_writes_snapshot(
        self, isolated_dirs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            DNSClient,
            "query_domain",
            _fake_query({"example.com": [_rec(A, "example.com.", "1.2.3.4")]}),
        )

        result = runner.invoke(app, ["backup", "example.com"])

        assert result.exit_code == 0
        assert "Saved snapshot for example.com" in result.stdout
        assert "Records found: A=1" in result.stdout
        files = list((isolated_dirs["backups"] / "example.com").glob("*.json"))
        assert len(files) == 1

    def test_backup_json(
        self, isolated_dirs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            DNSClient,
            "query_domain",
            _fake_query({"example.com": [_rec(A, "example.com.", "1.2.3.4")]}),
        )

        result = runner.invoke(app, ["backup", "example.com", "--json"])

        assert result.exit_code == 0
        assert '"domain": "example.com"' in result.stdout

    def _seed(
        self,
        isolated_dirs: dict[str, Path],
        *records: DNSRecord,
    ) -> None:
        store = SnapshotStore(Config(), base_dir=isolated_dirs["backups"])
        store.save(
            DomainSnapshot(
                domain="example.com",
                captured_at=datetime(2000, 1, 1, tzinfo=timezone.utc),
                records={A: list(records)},
            )
        )

    def test_backup_initial_logs_initial_and_exits_zero(
        self, isolated_dirs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            DNSClient,
            "query_domain",
            _fake_query({"example.com": [_rec(A, "example.com.", "1.2.3.4")]}),
        )

        result = runner.invoke(app, ["backup", "example.com"])

        assert result.exit_code == 0
        entry = last_entry("example.com", base_dir=isolated_dirs["history"])
        assert entry is not None
        assert entry.status is ChangeStatus.INITIAL

    def test_backup_no_change_exits_zero(
        self, isolated_dirs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._seed(isolated_dirs, _rec(A, "example.com.", "1.2.3.4"))
        monkeypatch.setattr(
            DNSClient,
            "query_domain",
            _fake_query({"example.com": [_rec(A, "example.com.", "1.2.3.4")]}),
        )

        result = runner.invoke(app, ["backup", "example.com"])

        assert result.exit_code == 0
        entry = last_entry("example.com", base_dir=isolated_dirs["history"])
        assert entry is not None
        assert entry.status is ChangeStatus.NO_CHANGE

    def test_backup_changed_exits_one(
        self, isolated_dirs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._seed(isolated_dirs, _rec(A, "example.com.", "1.2.3.4"))
        monkeypatch.setattr(
            DNSClient,
            "query_domain",
            _fake_query(
                {
                    "example.com": [
                        _rec(A, "example.com.", "1.2.3.4"),
                        _rec(A, "example.com.", "1.2.3.5"),
                    ]
                }
            ),
        )

        result = runner.invoke(app, ["backup", "example.com"])

        assert result.exit_code == 1
        entry = last_entry("example.com", base_dir=isolated_dirs["history"])
        assert entry is not None
        assert entry.status is ChangeStatus.CHANGED
        assert entry.added == 1

    def test_backup_changed_json_still_exits_one(
        self, isolated_dirs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._seed(isolated_dirs, _rec(A, "example.com.", "1.2.3.4"))
        monkeypatch.setattr(
            DNSClient,
            "query_domain",
            _fake_query(
                {
                    "example.com": [
                        _rec(A, "example.com.", "1.2.3.4"),
                        _rec(A, "example.com.", "1.2.3.5"),
                    ]
                }
            ),
        )

        result = runner.invoke(app, ["backup", "example.com", "--json"])

        assert result.exit_code == 1
        assert '"domain": "example.com"' in result.stdout

    def test_backup_error_exits_two(
        self, isolated_dirs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(self: DNSClient, domain: str, record_types: object | None = None) -> DomainResult:
            raise DNSEngineError("query failed")

        monkeypatch.setattr(DNSClient, "query_domain", boom)

        result = runner.invoke(app, ["backup", "example.com"])

        assert result.exit_code == 2
        assert "query failed" in result.stderr
        assert last_entry("example.com", base_dir=isolated_dirs["history"]) is None


class TestCommandSurface:
    def test_schedule_command_is_removed(self) -> None:
        result = runner.invoke(app, ["schedule", "example.com", "*/6 * * * *"])
        assert result.exit_code != 0
        assert "No such command" in result.output

    def test_backup_help_documents_exit_codes(
        self, isolated_dirs: dict[str, Path]
    ) -> None:
        result = runner.invoke(app, ["backup", "--help"])
        assert result.exit_code == 0
        assert "backup" in result.stdout


class TestDiffCommand:
    def _seed(
        self,
        isolated_dirs: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store = SnapshotStore(Config(), base_dir=isolated_dirs["backups"])
        monkeypatch.setattr(
            DNSClient,
            "query_domain",
            _fake_query({"example.com": [_rec(A, "example.com.", "1.2.3.4")]}),
        )
        store.capture(
            "example.com",
            captured_at=datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc),
        )
        monkeypatch.setattr(
            DNSClient,
            "query_domain",
            _fake_query(
                {
                    "example.com": [
                        _rec(A, "example.com.", "1.2.3.4"),
                        _rec(A, "example.com.", "1.2.3.5"),
                    ]
                }
            ),
        )
        store.capture(
            "example.com",
            captured_at=datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc),
        )

    def test_diff_shows_added_records(
        self, isolated_dirs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._seed(isolated_dirs, monkeypatch)

        result = runner.invoke(app, ["diff", "example.com"])

        assert result.exit_code == 0
        assert "Diff for example.com" in result.stdout
        assert "+ A example.com. ttl=300 1.2.3.5" in result.stdout

    def test_diff_json(
        self, isolated_dirs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._seed(isolated_dirs, monkeypatch)

        result = runner.invoke(app, ["diff", "example.com", "--json"])

        assert result.exit_code == 0
        assert '"domain": "example.com"' in result.stdout
        assert '"has_changes": true' in result.stdout

    def test_diff_requires_two_snapshots(
        self, isolated_dirs: dict[str, Path]
    ) -> None:
        result = runner.invoke(app, ["diff", "example.com"])
        assert result.exit_code == 1
        assert "at least two snapshots" in result.stderr
