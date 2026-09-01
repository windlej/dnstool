from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from textual import work
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Label, Static

from dnstool.tui.screens.check import CheckScreen

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from dnstool.config import Config


class Dashboard(Screen[None]):
    CSS_PATH = "../styles.tcss"

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("b", "backup_selected", "Backup"),
        ("d", "diff_selected", "Diff"),
        ("enter", "check_selected", "Check"),
    ]

    def __init__(self, config: Config | None = None) -> None:
        super().__init__()
        self.config = config

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(classes="screen-container"):
            with Container(classes="dashboard-header"):
                yield Label("Tracked Domains")
                yield Button(
                    "Check Domain", id="check-domain-btn", variant="primary"
                )
                yield Button("Backup", id="backup-btn", variant="default")
                yield Button("Manage", id="manage-btn", variant="default")
                yield Button("Refresh", id="refresh-btn", variant="default")
            yield DataTable(id="dashboard-table")
            yield Static(
                "No domains tracked", id="dashboard-empty", classes="empty-state"
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#dashboard-table", DataTable)
        table.add_columns("Domain", "Status", "Last Snapshot", "Records")
        table.cursor_type = "row"
        table.zebra_stripes = True
        self._load_domains()

    def on_screen_resume(self) -> None:
        self._load_domains()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh-btn":
            self._load_domains()
        elif event.button.id == "check-domain-btn":
            from dnstool.tui.app import DomainInputScreen

            self.app.push_screen(
                DomainInputScreen(mode="check", config=self.config)
            )
        elif event.button.id == "backup-btn":
            from dnstool.tui.app import DomainInputScreen

            self.app.push_screen(
                DomainInputScreen(mode="backup", config=self.config)
            )
        elif event.button.id == "manage-btn":
            from dnstool.tui.screens.track import TrackScreen

            self.app.push_screen(TrackScreen(config=self.config))

    def action_refresh(self) -> None:
        self._load_domains()

    def action_check_selected(self) -> None:
        domain = self._selected_domain()
        if domain:
            self.app.push_screen(
                CheckScreen(domain=domain, config=self.config)
            )

    def action_backup_selected(self) -> None:
        domain = self._selected_domain()
        if domain:
            self._push_backup(domain)

    def action_diff_selected(self) -> None:
        domain = self._selected_domain()
        if domain:
            from dnstool.tui.screens.diff import DiffScreen

            self.app.push_screen(DiffScreen(domain=domain, config=self.config))

    def _selected_domain(self) -> str | None:
        table = self.query_one("#dashboard-table", DataTable)
        if table.cursor_row is None:
            return None
        row = table.get_row_at(table.cursor_row)
        if not row:
            return None
        return str(row[0])

    def _push_backup(self, domain: str) -> None:
        from dnstool.tui.screens.backup import BackupScreen

        self.app.push_screen(BackupScreen(domain=domain, config=self.config))

    @work(exclusive=True, group="load-domains")
    async def _load_domains(self) -> None:
        from dnstool.snapshots import SnapshotStore
        from dnstool.tracking import TrackedRegistry

        def collect() -> list[tuple[str, str, str, int]]:
            tracked = TrackedRegistry()
            store = SnapshotStore()
            rows: list[tuple[str, str, str, int]] = []
            for entry in tracked.list():
                status = "enabled" if entry.schedule.enabled else "disabled"
                snaps = store.list_snapshots(entry.domain)
                if snaps:
                    latest = snaps[-1]
                    ts = latest.captured_at.strftime("%Y-%m-%d %H:%M")
                    count = latest.record_count
                else:
                    ts = "-"
                    count = 0
                rows.append((entry.domain, status, ts, count))
            return rows

        rows = await asyncio.to_thread(collect)

        table = self.query_one("#dashboard-table", DataTable)
        table.clear()
        empty_label = self.query_one("#dashboard-empty", Static)
        empty_label.display = not rows
        for domain, status, ts, count in rows:
            table.add_row(domain, status, ts, str(count))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table = event.control
        row_key = event.row_key.value if event.row_key else None
        if row_key is None:
            return
        domain = table.get_row(row_key)[0]
        self.app.push_screen(CheckScreen(domain=domain, config=self.config))
