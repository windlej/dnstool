from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from textual import events, work
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from dnstool.config import Config
    from dnstool.models import CheckResult


def truncate(text: str, max_width: int) -> str:
    """Truncate ``text`` to ``max_width`` characters, appending an ellipsis."""
    if len(text) <= max_width:
        return text
    if max_width <= 1:
        return "…"
    return text[: max_width - 1].rstrip() + "…"


# Monokai-tinted severity colors (match dnstool/tui/theme.py)
_SEVERITY_COLORS = {
    "critical": "#f92672",
    "warning": "#e6db74",
    "pass": "#a6e22e",
    "info": "#66d9ef",
}


def _severity_cell(severity: str) -> str:
    color = _SEVERITY_COLORS.get(severity, "#f8f8f2")
    return f"[bold {color}]{severity.upper()}[/]"


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
        self._checks: list[CheckResult] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(classes="screen-container"):
            with Container(classes="check-summary"):
                yield Static("—", id="score-display", classes="check-score")
                yield Static(
                    f"Compliance checks for {self.domain}", id="check-title"
                )
            with Container(classes="check-body"):
                with Container(id="checks-pane", classes="check-pane"):
                    yield DataTable(id="checks-table")
                    yield Static(
                        "", id="check-detail-bar", classes="check-detail-bar"
                    )
                with Container(id="records-pane", classes="check-pane"):
                    yield Static(
                        f"Unique Records — {self.domain}", id="records-title"
                    )
                    yield DataTable(id="records-table")
        yield Footer()

    def on_resize(self, event: events.Resize) -> None:
        body = self.query_one(".check-body", Container)
        body.set_class(event.size.width >= 130, "-split")

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

    def _update_check_details(self, index: int) -> None:
        check = self._checks[index]
        bar = self.query_one("#check-detail-bar", Static)
        parts = [f"[bold]{check.message}[/bold]"]
        if check.details:
            parts.append(f"  {check.details}")
        bar.update("\n".join(parts))

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted
    ) -> None:
        if event.control.id != "checks-table":
            return
        if event.cursor_row is not None and 0 <= event.cursor_row < len(self._checks):
            self._update_check_details(event.cursor_row)

    @work(exclusive=True, group="domain-check")
    async def _run_check(self) -> None:
        from dnstool.checks import run_compliance
        from dnstool.config import load_config
        from dnstool.dns_engine import DNSClient

        detail_bar = self.query_one("#check-detail-bar", Static)
        detail_bar.update("Checking…")

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

        self._checks = list(report.checks)
        checks_table = self.query_one("#checks-table", DataTable)
        checks_table.clear()
        for check in self._checks:
            sev = _severity_cell(check.severity.value)
            msg = truncate(check.message or "", 80)
            details = truncate(check.details or "", 60)
            checks_table.add_row(sev, check.name, msg, details)

        if self._checks:
            self._update_check_details(0)

        result = await asyncio.to_thread(client.query_domain, self.domain)
        records_table = self.query_one("#records-table", DataTable)
        records_table.clear()
        for _rtype, records in result.unique_records.items():
            for rec in records:
                records_table.add_row(
                    rec.type.value,
                    rec.name,
                    str(rec.ttl),
                    truncate(rec.value, 80),
                )
