"""dnstool - All-in-one DNS analysis tool."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from dnstool import __version__
from dnstool.config import (
    CONFIG_FILE,
    load_config,
    save_default_config,
    ensure_dirs,
)

app = typer.Typer(
    name="dnstool",
    help="All-in-one DNS analysis tool with TUI interface.",
    no_args_is_help=True,
)


@app.command()
def tui(config: Optional[Path] = typer.Option(None, "-c", "--config", help="Config file path")):
    """Launch the TUI interface."""
    ensure_dirs()
    cfg = load_config(config)
    typer.echo(f"Launching dnstool TUI (v{__version__})...")
    # Phase 5-6: Will launch Textual app here
    typer.echo("TUI not yet implemented. Use 'dnstool check' for now.")


@app.command()
def check(
    domain: str = typer.Argument(help="Domain to check"),
    nameservers: Optional[list[str]] = typer.Option(
        None, "-n", "--nameserver", help="Nameserver(s) to query"
    ),
    record_types: Optional[list[str]] = typer.Option(
        None, "-t", "--type", help="Record types to check"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    config: Optional[Path] = typer.Option(None, "-c", "--config", help="Config file path"),
):
    """Check DNS records and compliance for a domain."""
    ensure_dirs()
    cfg = load_config(config)
    typer.echo(f"Checking {domain}...")
    typer.echo(f"Nameservers: {nameservers or cfg.get_nameserver_ips()}")
    typer.echo(f"Record types: {record_types or [rt.value for rt in cfg.record_types]}")
    # Phase 2: Will resolve DNS here
    # Phase 3: Will run compliance checks here
    typer.echo("DNS resolution not yet implemented (Phase 2).")


@app.command()
def backup(
    domain: str = typer.Argument(help="Domain to backup"),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file path"),
    config: Optional[Path] = typer.Option(None, "-c", "--config", help="Config file path"),
):
    """Take a backup of all DNS records for a domain."""
    ensure_dirs()
    cfg = load_config(config)
    typer.echo(f"Backing up DNS records for {domain}...")
    # Phase 4: Will snapshot records here
    typer.echo("Backup not yet implemented (Phase 4).")


@app.command()
def diff(
    domain: str = typer.Argument(help="Domain to diff"),
    snapshot1: Optional[str] = typer.Option(None, help="First snapshot timestamp"),
    snapshot2: Optional[str] = typer.Option(None, help="Second snapshot timestamp"),
    config: Optional[Path] = typer.Option(None, "-c", "--config", help="Config file path"),
):
    """Show diff between two snapshots of a domain."""
    ensure_dirs()
    cfg = load_config(config)
    typer.echo(f"Showing diff for {domain}...")
    # Phase 4: Will compare snapshots here
    typer.echo("Diff not yet implemented (Phase 4).")


@app.command()
def track(
    domain: str = typer.Argument(help="Domain to track"),
    config: Optional[Path] = typer.Option(None, "-c", "--config", help="Config file path"),
):
    """Add a domain to the tracking list."""
    ensure_dirs()
    cfg = load_config(config)
    typer.echo(f"Tracking {domain}...")
    # Phase 4: Will add domain to tracked list
    typer.echo("Tracking not yet implemented (Phase 4).")


@app.command()
def schedule(
    domain: str = typer.Argument(help="Domain to schedule checks for"),
    cron: str = typer.Argument(help="Cron expression (e.g. '*/6 * * * *')"),
    config: Optional[Path] = typer.Option(None, "-c", "--config", help="Config file path"),
):
    """Schedule periodic checks for a domain."""
    ensure_dirs()
    cfg = load_config(config)
    typer.echo(f"Scheduling checks for {domain} with cron: {cron}")
    # Phase 7: Will set up scheduler here
    typer.echo("Scheduling not yet implemented (Phase 7).")


@app.command()
def init_config(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config"),
):
    """Initialize a default configuration file."""
    if CONFIG_FILE.exists() and not force:
        typer.echo(f"Config already exists at {CONFIG_FILE}")
        typer.echo("Use --force to overwrite.")
        raise typer.Exit(1)

    path = save_default_config()
    typer.echo(f"Default config saved to {path}")


@app.command()
def version():
    """Show version information."""
    typer.echo(f"dnstool v{__version__}")


if __name__ == "__main__":
    app()
