from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from textual import work
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, OptionList
from textual.widgets._option_list import Option

if TYPE_CHECKING:
    from textual.app import ComposeResult

    from dnstool.config import Config


class TrackScreen(Screen[None]):
    CSS_PATH = "../styles.tcss"

    BINDINGS = [("escape", "go_dashboard", "Dashboard")]

    def __init__(self, config: Config | None = None) -> None:
        super().__init__()
        self.config = config

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(classes="screen-container"):
            with Container(classes="track-section"):
                yield Label("Add Domain")
                with Container(classes="track-input-row"):
                    yield Input(
                        placeholder="e.g. example.com", id="add-domain-input"
                    )
                    yield Button("Track", id="track-btn", variant="primary")
            with Container(classes="track-section"):
                yield Label("Tracked Domains")
                yield OptionList(id="tracked-list")
                yield Button("Untrack", id="untrack-btn", variant="error")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_list()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "track-btn":
            domain = self.query_one("#add-domain-input", Input).value.strip()
            if domain:
                self._track_domain(domain)
        elif event.button.id == "untrack-btn":
            self._untrack_selected()

    def action_go_dashboard(self) -> None:
        from dnstool.tui.screens.dashboard import Dashboard

        self.app.push_screen(Dashboard(config=self.config))

    @work(exclusive=True, group="track-refresh")
    async def _refresh_list(self) -> None:
        from dnstool.tracking import TrackedRegistry

        entries = await asyncio.to_thread(TrackedRegistry().list)
        option_list = self.query_one("#tracked-list", OptionList)
        option_list.clear_options()
        for entry in entries:
            option_list.add_option(Option(entry.domain, id=entry.domain))

    @work(exclusive=True, group="track-add")
    async def _track_domain(self, domain: str) -> None:
        from dnstool.tracking import TrackedError, TrackedRegistry

        registry = TrackedRegistry()
        try:
            await asyncio.to_thread(registry.add, domain)
            self.app.notify(f"Tracking {domain}", severity="information")
        except TrackedError as exc:
            self.app.notify(f"Failed to track: {exc}", severity="error")
            return
        self._refresh_list()

    @work(exclusive=True, group="track-remove")
    async def _untrack_selected(self) -> None:
        from dnstool.tracking import DomainNotTrackedError, TrackedRegistry

        option_list = self.query_one("#tracked-list", OptionList)
        if option_list.option_count == 0:
            return
        option = option_list.highlighted_option
        if option is None:
            return
        domain = option.id or str(option.prompt)
        registry = TrackedRegistry()
        try:
            await asyncio.to_thread(registry.remove, domain)
            self.app.notify(f"Untracked {domain}", severity="information")
        except DomainNotTrackedError as exc:
            self.app.notify(f"Failed to untrack: {exc}", severity="error")
            return
        self._refresh_list()
