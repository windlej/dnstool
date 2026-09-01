from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from textual import work
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Label, OptionList, Static
from textual.widgets._option_list import Option

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from dnstool.config import Config
    from dnstool.snapshots import SnapshotInfo


class DiffScreen(Screen[None]):
    CSS_PATH = "../styles.tcss"

    BINDINGS = [
        ("escape", "go_dashboard", "Dashboard"),
        ("enter", "compute_diff", "Compute Diff"),
    ]

    def __init__(self, domain: str, config: Config | None = None) -> None:
        super().__init__()
        self.domain = domain
        self.config = config
        self._snapshots: list[SnapshotInfo] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(classes="screen-container"):
            with Container(classes="toolbar"):
                yield Label(f"Snapshots — {self.domain}")
                yield Button(
                    "Compute Diff", id="diff-btn", variant="primary", disabled=True
                )
            yield OptionList(id="snapshots-list")
            yield Static(
                "No snapshots for this domain", id="diff-empty", classes="empty-state"
            )
            yield DataTable(id="diff-table")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#diff-table", DataTable).zebra_stripes = True
        self._load_snapshots()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "diff-btn":
            self._compute_diff()

    def action_go_dashboard(self) -> None:
        from dnstool.tui.screens.dashboard import Dashboard

        self.app.push_screen(Dashboard(config=self.config))

    def action_compute_diff(self) -> None:
        btn = self.query_one("#diff-btn", Button)
        if not btn.disabled:
            self._compute_diff()

    @work(exclusive=True, group="load-snapshots")
    async def _load_snapshots(self) -> None:
        from dnstool.config import load_config
        from dnstool.snapshots import SnapshotStore

        cfg = self.config or load_config()
        store = SnapshotStore(cfg)
        self._snapshots = await asyncio.to_thread(
            store.list_snapshots, self.domain
        )

        option_list = self.query_one("#snapshots-list", OptionList)
        option_list.clear_options()
        empty_label = self.query_one("#diff-empty", Static)
        empty_label.display = not self._snapshots
        for snap in self._snapshots:
            ts = snap.captured_at.strftime("%Y-%m-%d %H:%M:%S")
            label = f"{ts}  ({snap.record_count} records)"
            option_list.add_option(Option(label))
        btn = self.query_one("#diff-btn", Button)
        btn.disabled = len(self._snapshots) < 2

    @work(exclusive=True, group="compute-diff")
    async def _compute_diff(self) -> None:
        from dnstool.config import load_config
        from dnstool.snapshots import (
            NoSnapshotsError,
            SnapshotNotFoundError,
            SnapshotStore,
        )

        cfg = self.config or load_config()
        store = SnapshotStore(cfg)
        table = self.query_one("#diff-table", DataTable)
        table.clear()
        table.add_columns("Type", "Name", "TTL", "Value")

        if len(self._snapshots) < 2:
            self.notify("Need at least two snapshots to diff.", severity="warning")
            return

        try:
            old = self._snapshots[-2]
            new = self._snapshots[-1]
            diff_result = await asyncio.to_thread(
                store.diff,
                self.domain,
                old.captured_at.isoformat(),
                new.captured_at.isoformat(),
            )
        except (SnapshotNotFoundError, NoSnapshotsError) as exc:
            self.notify(str(exc), severity="error")
            return

        if not diff_result.has_changes:
            self.notify(
                "No changes between selected snapshots.", severity="warning"
            )
            return

        for rec in sorted(diff_result.added, key=lambda r: (r.type.value, r.name)):
            rtype = f"[bold #a6e22e]+ {rec.type.value}[/]"
            table.add_row(rtype, rec.name, str(rec.ttl), rec.value)
        for rec in sorted(diff_result.removed, key=lambda r: (r.type.value, r.name)):
            rtype = f"[bold #f92672]- {rec.type.value}[/]"
            table.add_row(rtype, rec.name, str(rec.ttl), rec.value)
        for change in diff_result.changed:
            key = change["record_key"]
            parts = key.split(":", 2)
            rtype = parts[0] if parts else ""
            name = parts[1] if len(parts) > 1 else ""
            table.add_row(
                f"[bold #e6db74]~ {rtype}[/]", name, "", str(change["changes"])
            )
