from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from textual import work
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from dnstool.config import Config


class CheckScreen(Screen[None]):
    CSS_PATH = "../styles.tcss"

    BINDINGS = [
        ("escape", "go_dashboard", "Dashboard"),
        ("b", "backup_domain", "Backup"),
    ]

    def __init__(self, domain: str, config: Config | None = None) -> None:
        super().__init__()
        self.domain = domain
        self.config = config

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(classes="screen-container"):
            with Container(classes="check-summary"):
                yield Static("—", id="score-display", classes="check-score")
                with Vertical(classes="check-details"):
                    yield Static(
                        f"Compliance checks for {self.domain}", id="check-title"
                    )
            yield DataTable(id="checks-table")
            with Container():
                yield Static(f"Unique Records — {self.domain}", id="records-title")
                yield DataTable(id="records-table")
        yield Footer()

    def on_mount(self) -> None:
        checks_table = self.query_one("#checks-table", DataTable)
        checks_table.add_columns("Severity", "Check", "Message", "Details")
        checks_table.cursor_type = "row"
        checks_table.zebra_stripes = True

        records_table = self.query_one("#records-table", DataTable)
        records_table.add_columns("Type", "Name", "TTL", "Value")
        records_table.cursor_type = "row"
        records_table.zebra_stripes = True

        self._run_check()

    def action_go_dashboard(self) -> None:
        from dnstool.tui.screens.dashboard import Dashboard

        self.app.push_screen(Dashboard(config=self.config))

    def action_backup_domain(self) -> None:
        from dnstool.tui.screens.backup import BackupScreen

        self.app.push_screen(
            BackupScreen(domain=self.domain, config=self.config)
        )

    @work(exclusive=True, group="domain-check")
    async def _run_check(self) -> None:
        from dnstool.checks import run_compliance
        from dnstool.config import load_config
        from dnstool.dns_engine import DNSClient

        cfg = self.config or load_config()
        client = DNSClient(cfg, timeout=cfg.timeout)
        check_names = list(cfg.get_checks(self.domain))
        report = await asyncio.to_thread(
            run_compliance, self.domain, client, check_names
        )

        score = report.score
        label = f"{score:.0f}%"
        display = self.query_one("#score-display", Static)
        display.update(f"[bold]{label}[/bold]")
        display.add_class("check-score")
        if score >= 80:
            display.add_class("score-good")
        elif score >= 50:
            display.add_class("score-warn")
        else:
            display.add_class("score-bad")

        checks_table = self.query_one("#checks-table", DataTable)
        checks_table.clear()
        for check in report.checks:
            sev = check.severity.value.upper()
            msg = check.message or ""
            details = check.details or ""
            checks_table.add_row(sev, check.name, msg, details)

        result = await asyncio.to_thread(client.query_domain, self.domain)
        records_table = self.query_one("#records-table", DataTable)
        records_table.clear()
        for _rtype, records in result.unique_records.items():
            for rec in records:
                records_table.add_row(
                    rec.type.value, rec.name, str(rec.ttl), rec.value
                )
