from __future__ import annotations

from functools import partial

from textual.app import App, ComposeResult
from textual.command import Hit, Hits, Provider
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Static

from dnstool.config import Config
from dnstool.tui.screens.check import CheckScreen
from dnstool.tui.screens.dashboard import Dashboard
from dnstool.tui.screens.diff import DiffScreen
from dnstool.tui.theme import DNSTOOL_THEME


class DomainInputScreen(Screen[None]):
    CSS_PATH = "styles.tcss"

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(
        self,
        mode: str = "check",
        config: Config | None = None,
    ) -> None:
        super().__init__()
        self.mode = mode
        self.config = config

    def compose(self) -> ComposeResult:
        title = {
            "check": "Check Domain",
            "backup": "Backup Domain",
            "diff": "Diff Domain",
        }.get(self.mode, "Enter Domain")
        with Container(classes="domain-input-container"):
            yield Label(title, id="domain-input-title")
            yield Input(placeholder="e.g. example.com", id="domain-input")
            with Container(classes="domain-input-buttons"):
                yield Button("Submit", id="submit-btn", variant="primary")
                yield Button("Cancel", id="cancel-btn", variant="default")

    def on_input_changed(self, event: Input.Changed) -> None:
        submit_btn = self.query_one("#submit-btn", Button)
        submit_btn.disabled = not event.input.value.strip()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit-btn":
            self._submit()
        elif event.button.id == "cancel-btn":
            self.action_cancel()

    def _submit(self) -> None:
        domain = self.query_one("#domain-input", Input).value.strip()
        if not domain:
            return
        app = self.app
        cfg = getattr(app, "config", self.config)
        if self.mode == "check":
            app.push_screen(CheckScreen(domain=domain, config=cfg))
        elif self.mode == "backup":
            from dnstool.tui.screens.backup import BackupScreen

            app.push_screen(BackupScreen(domain=domain, config=cfg))
        elif self.mode == "diff":
            app.push_screen(DiffScreen(domain=domain, config=cfg))
        else:
            app.push_screen(CheckScreen(domain=domain, config=cfg))

    def action_cancel(self) -> None:
        self.app.pop_screen()


class DnstoolCommandProvider(Provider):
    """Command palette provider for dnstool operations."""

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        commands = [
            ("check", "Run DNS compliance check"),
            ("backup", "Take a DNS backup snapshot"),
            ("diff", "Compare two snapshots"),
            ("track", "Manage tracked domains"),
            ("dashboard", "Go to the dashboard"),
        ]
        for label, help_text in commands:
            if matcher.match(label):
                yield Hit(
                    score=1.0,
                    match_display=label,
                    command=partial(self._dispatch, label),
                    text=label,
                    help=help_text,
                )

    def _dispatch(self, action: str) -> None:
        app = self.app
        assert isinstance(app, DnstoolApp)
        if action == "check":
            app.push_screen(DomainInputScreen(mode="check", config=app.config))
        elif action == "backup":
            app.push_screen(DomainInputScreen(mode="backup", config=app.config))
        elif action == "diff":
            app.push_screen(DomainInputScreen(mode="diff", config=app.config))
        elif action == "track":
            from dnstool.tui.screens.track import TrackScreen

            app.push_screen(TrackScreen(config=app.config))
        elif action == "dashboard":
            app.push_screen(Dashboard(config=app.config))


class DnstoolApp(App[None]):
    """dnstool TUI application."""

    TITLE = "dnstool"
    CSS_PATH = "styles.tcss"
    COMMANDS = {DnstoolCommandProvider}
    BINDINGS = [
        ("tab", "focus_next", "Next"),
        ("shift+tab", "focus_previous", "Previous"),
    ]

    def __init__(self, config: Config | None = None) -> None:
        super().__init__()
        self.config = config
        self.register_theme(DNSTOOL_THEME)
        self.theme = DNSTOOL_THEME.name

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Loading...", id="loading")
        yield Footer()

    def on_mount(self) -> None:
        self.push_screen(Dashboard(config=self.config))

    def action_check_domain(self, domain: str | None = None) -> None:
        if domain is None:
            self.push_screen(DomainInputScreen(mode="check", config=self.config))
            return
        self.push_screen(CheckScreen(domain=domain, config=self.config))

    def action_diff_domain(self, domain: str | None = None) -> None:
        if domain is None:
            self.push_screen(DomainInputScreen(mode="diff", config=self.config))
            return
        self.push_screen(DiffScreen(domain=domain, config=self.config))

    def action_go_dashboard(self) -> None:
        self.push_screen(Dashboard(config=self.config))
