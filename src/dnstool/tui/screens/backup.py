from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from textual import work
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Footer, Header, Label, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from dnstool.config import Config


class BackupScreen(Screen[None]):
    CSS_PATH = "../styles.tcss"

    BINDINGS = [("escape", "go_dashboard", "Dashboard")]

    def __init__(self, domain: str, config: Config | None = None) -> None:
        super().__init__()
        self.domain = domain
        self.config = config

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(classes="screen-container"):
            yield Static(
                f"Backing up {self.domain}...",
                id="backup-status",
                classes="backup-status",
            )
            with Container(id="backup-result", classes="backup-result"):
                pass
        yield Footer()

    def on_mount(self) -> None:
        self._run_backup()

    def action_go_dashboard(self) -> None:
        from dnstool.tui.screens.dashboard import Dashboard

        self.app.push_screen(Dashboard(config=self.config))

    @work(exclusive=True, group="backup-domain")
    async def _run_backup(self) -> None:
        from dnstool.config import load_config
        from dnstool.dns_engine import DNSClient, DNSEngineError
        from dnstool.snapshots import SnapshotError, SnapshotStore

        cfg = self.config or load_config()
        client = DNSClient(cfg, timeout=cfg.timeout)
        store = SnapshotStore(cfg)

        status = self.query_one("#backup-status", Static)
        try:
            snapshot = await asyncio.to_thread(
                store.capture, self.domain, client
            )
        except (DNSEngineError, ValueError, SnapshotError) as exc:
            status.update(f"Backup failed: {exc}")
            status.add_class("status-err")
            return

        status.update(f"Backup complete for {self.domain}")
        status.add_class("status-ok")

        result_container = self.query_one("#backup-result", Container)
        ts = snapshot.captured_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        total_records = sum(len(recs) for recs in snapshot.records.items())
        result_container.mount(
            Label(f"Timestamp: {ts}", classes="backup-result-label")
        )
        result_container.mount(
            Label(f"Records: {total_records}", classes="backup-result-label")
        )
        for rtype, records in snapshot.records.items():
            result_container.mount(
                Label(
                    f"  {rtype.value}: {len(records)} record(s)",
                    classes="backup-result-label",
                )
            )

        path = await asyncio.to_thread(store.saved_path, snapshot)
        result_container.mount(
            Label(f"Saved to: {path}", classes="backup-result-label")
        )
