"""dnstool - All-in-one DNS analysis tool."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from dnstool import __version__
from dnstool.checks import UnknownCheckError, run_compliance
from dnstool.config import (
    CONFIG_FILE,
    ensure_dirs,
    load_config,
    save_default_config,
)
from dnstool.dns_engine import DNSClient, coerce_record_types
from dnstool.models import ComplianceReport, DomainResult

app = typer.Typer(
    name="dnstool",
    help="All-in-one DNS analysis tool with TUI interface.",
    no_args_is_help=True,
)


@app.command()
def tui(
    config: Path | None = typer.Option(
        None, "-c", "--config", help="Config file path"
    ),
) -> None:
    """Launch the TUI interface."""
    ensure_dirs()
    load_config(config)
    typer.echo(f"Launching dnstool TUI (v{__version__})...")
    # Phase 5-6: Will launch Textual app here
    typer.echo("TUI not yet implemented. Use 'dnstool check' for now.")


def _print_records_summary(result: DomainResult) -> None:
    counts = {t.value: len(recs) for t, recs in result.unique_records.items() if recs}
    summary = ", ".join(f"{k}={v}" for k, v in counts.items()) if counts else "none"
    typer.echo(f"Records found: {summary}")


def _print_compliance(report: ComplianceReport) -> None:
    typer.echo(
        f"Compliance report for {report.domain} "
        f"(checked at {report.checked_at.isoformat()}):"
    )
    for check in report.checks:
        typer.echo(f"  [{check.severity.value.upper():<8}] {check.name}: {check.message}")
        if check.details:
            typer.echo(f"          {check.details}")
    typer.echo(
        f"Score: {report.score:.1f}/100"
        f" | critical: {len(report.critical_issues)}"
        f" | warnings: {len(report.warnings)}"
    )


@app.command()
def check(
    domain: str = typer.Argument(help="Domain to check"),
    nameservers: list[str] | None = typer.Option(
        None, "-n", "--nameserver", help="Nameserver(s) to query"
    ),
    record_types: list[str] | None = typer.Option(
        None, "-t", "--type", help="Record types to check"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    config: Path | None = typer.Option(None, "-c", "--config", help="Config file path"),
) -> None:
    """Check DNS records and compliance for a domain."""
    ensure_dirs()
    cfg = load_config(config)
    checks = list(cfg.get_checks(domain))
    client = DNSClient(cfg, nameservers=nameservers, timeout=cfg.timeout)

    if not output_json:
        typer.echo(f"Checking {domain}...")
        typer.echo(f"Nameservers: {nameservers or cfg.get_nameserver_ips()}")
        typer.echo(f"Record types: {record_types or [rt.value for rt in cfg.record_types]}")

    types = coerce_record_types(record_types) if record_types else None
    result = client.query_domain(domain, types)

    try:
        report = run_compliance(result, client=client, check_names=checks)
    except UnknownCheckError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1) from exc

    if output_json:
        payload = {
            "domain_result": result.to_dict(),
            "compliance": report.to_dict(),
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    _print_records_summary(result)
    _print_compliance(report)


@app.command()
def backup(
    domain: str = typer.Argument(help="Domain to backup"),
    output: Path | None = typer.Option(None, "-o", "--output", help="Output file path"),
    config: Path | None = typer.Option(None, "-c", "--config", help="Config file path"),
) -> None:
    """Take a backup of all DNS records for a domain."""
    ensure_dirs()
    load_config(config)
    typer.echo(f"Backing up DNS records for {domain}...")
    # Phase 4: Will snapshot records here
    typer.echo("Backup not yet implemented (Phase 4).")


@app.command()
def diff(
    domain: str = typer.Argument(help="Domain to diff"),
    snapshot1: str | None = typer.Option(None, help="First snapshot timestamp"),
    snapshot2: str | None = typer.Option(None, help="Second snapshot timestamp"),
    config: Path | None = typer.Option(None, "-c", "--config", help="Config file path"),
) -> None:
    """Show diff between two snapshots of a domain."""
    ensure_dirs()
    load_config(config)
    typer.echo(f"Showing diff for {domain}...")
    # Phase 4: Will compare snapshots here
    typer.echo("Diff not yet implemented (Phase 4).")


@app.command()
def track(
    domain: str = typer.Argument(help="Domain to track"),
    config: Path | None = typer.Option(None, "-c", "--config", help="Config file path"),
) -> None:
    """Add a domain to the tracking list."""
    ensure_dirs()
    load_config(config)
    typer.echo(f"Tracking {domain}...")
    # Phase 4: Will add domain to tracked list
    typer.echo("Tracking not yet implemented (Phase 4).")


@app.command()
def schedule(
    domain: str = typer.Argument(help="Domain to schedule checks for"),
    cron: str = typer.Argument(help="Cron expression (e.g. '*/6 * * * *')"),
    config: Path | None = typer.Option(None, "-c", "--config", help="Config file path"),
) -> None:
    """Schedule periodic checks for a domain."""
    ensure_dirs()
    load_config(config)
    typer.echo(f"Scheduling checks for {domain} with cron: {cron}")
    # Phase 7: Will set up scheduler here
    typer.echo("Scheduling not yet implemented (Phase 7).")


@app.command()
def init_config(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config"),
) -> None:
    """Initialize a default configuration file."""
    if CONFIG_FILE.exists() and not force:
        typer.echo(f"Config already exists at {CONFIG_FILE}")
        typer.echo("Use --force to overwrite.")
        raise typer.Exit(1)

    path = save_default_config()
    typer.echo(f"Default config saved to {path}")


@app.command()
def version() -> None:
    """Show version information."""
    typer.echo(f"dnstool v{__version__}")


if __name__ == "__main__":
    app()
