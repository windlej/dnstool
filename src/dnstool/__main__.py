"""dnstool - All-in-one DNS analysis tool."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from dnstool import __version__
from dnstool.checks import UnknownCheckError, run_compliance
from dnstool.config import (
    CONFIG_FILE,
    Config,
    DomainConfig,
    ScheduleConfig,
    ensure_dirs,
    load_config,
    save_default_config,
)
from dnstool.dns_engine import DNSClient, DNSEngineError, coerce_record_types
from dnstool.history import ChangeStatus, log_run
from dnstool.models import (
    ComplianceReport,
    DNSRecord,
    DomainDiff,
    DomainResult,
)
from dnstool.snapshots import (
    NoSnapshotsError,
    SnapshotNotFoundError,
    SnapshotStore,
    normalize_domain,
)
from dnstool.tracking import DomainNotTrackedError, TrackedRegistry

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


def _print_diff(diff: DomainDiff) -> None:
    typer.echo(f"Diff for {diff.domain}")
    typer.echo(
        f"  {diff.old_snapshot.captured_at.isoformat()}"
        f" -> {diff.new_snapshot.captured_at.isoformat()}"
    )
    if not diff.has_changes:
        typer.echo("  No changes.")
        return

    def fmt(record: DNSRecord) -> str:
        return f"{record.type.value} {record.name} ttl={record.ttl} {record.value}"

    if diff.added:
        typer.echo("Added:")
        for r in sorted(diff.added, key=lambda r: (r.type.value, r.name)):
            typer.echo(f"  + {fmt(r)}")
    if diff.removed:
        typer.echo("Removed:")
        for r in sorted(diff.removed, key=lambda r: (r.type.value, r.name)):
            typer.echo(f"  - {fmt(r)}")
    if diff.changed:
        typer.echo("Changed:")
        for change in diff.changed:
            typer.echo(f"  ~ {change['record_key']}")
            for field_name, values in change["changes"].items():
                typer.echo(
                    f"      {field_name}: {values['old']} -> {values['new']}"
                )


def _schedule_for(cfg: Config, domain: str) -> ScheduleConfig:
    """Per-domain schedule config matching ``domain`` from the loaded config."""
    domain_cfg: DomainConfig | None = next(
        (c for k, c in cfg.domains.items() if normalize_domain(k) == normalize_domain(domain)),
        None,
    )
    if domain_cfg:
        return domain_cfg.schedule
    return ScheduleConfig()


@app.command()
def backup(
    domain: str = typer.Argument(help="Domain to backup"),
    output: Path | None = typer.Option(
        None, "-o", "--output", help="Also write snapshot to this file"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    config: Path | None = typer.Option(None, "-c", "--config", help="Config file path"),
) -> None:
    """Take a backup of all DNS records for a domain.

    Exit codes: 0 = success with no change (or first backup), 1 = success with
    changes, 2 = error.
    """
    ensure_dirs()
    cfg = load_config(config)
    store = SnapshotStore(cfg)
    client = DNSClient(cfg, timeout=cfg.timeout)

    if not output_json:
        typer.echo(f"Backing up DNS records for {domain}...")

    try:
        snapshot = store.capture(domain, client)
    except (DNSEngineError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc

    history = log_run(store, snapshot.domain)

    path = store.saved_path(snapshot)
    if output:
        snapshot.save(str(output))

    if output_json:
        typer.echo(json.dumps(snapshot.to_dict(), indent=2))
    else:
        counts = {t.value: len(recs) for t, recs in snapshot.records.items() if recs}
        summary = ", ".join(f"{k}={v}" for k, v in counts.items()) if counts else "none"
        typer.echo(f"Saved snapshot for {snapshot.domain} to {path}")
        typer.echo(f"  Captured at {snapshot.captured_at.isoformat()}")
        typer.echo(f"  Records found: {summary}")
        typer.echo(
            f"  Keeping up to {store.max_snapshots_for(domain)} snapshots for this domain."
        )
        if output:
            typer.echo(f"  Wrote a copy to {output}")

    if history.status == ChangeStatus.CHANGED:
        raise typer.Exit(1)


@app.command()
def diff(
    domain: str = typer.Argument(help="Domain to diff"),
    snapshot1: str | None = typer.Option(
        None, "--snapshot1", help="First (older) snapshot timestamp"
    ),
    snapshot2: str | None = typer.Option(
        None, "--snapshot2", help="Second (newer) snapshot timestamp"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    config: Path | None = typer.Option(None, "-c", "--config", help="Config file path"),
) -> None:
    """Show diff between two snapshots of a domain (defaults to the latest two)."""
    ensure_dirs()
    cfg = load_config(config)
    store = SnapshotStore(cfg)

    try:
        diff_result = store.diff(domain, snapshot1, snapshot2)
    except (NoSnapshotsError, SnapshotNotFoundError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1) from exc

    if output_json:
        typer.echo(json.dumps(diff_result.to_dict(), indent=2))
        return
    _print_diff(diff_result)


@app.command()
def track(
    domain: str | None = typer.Argument(None, help="Domain to track (omit with --list)"),
    remove: bool = typer.Option(False, "--remove", help="Remove the domain from tracking"),
    list_domains: bool = typer.Option(False, "--list", help="List tracked domains"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    config: Path | None = typer.Option(None, "-c", "--config", help="Config file path"),
) -> None:
    """Manage the tracked-domains list."""
    ensure_dirs()
    cfg = load_config(config)
    registry = TrackedRegistry()

    if list_domains:
        entries = registry.list()
        if output_json:
            typer.echo(json.dumps([e.to_dict() for e in entries], indent=2))
            return
        if not entries:
            typer.echo("No tracked domains.")
            return
        typer.echo(f"Tracked domains ({len(entries)}):")
        for entry in entries:
            schedule = entry.schedule
            status = "enabled" if schedule.enabled else "disabled"
            cron = f" cron={schedule.cron}" if schedule.cron else ""
            typer.echo(
                f"  {entry.domain}  [{status}]{cron}"
                f" (tracked since {entry.added_at.date().isoformat()})"
            )
        return

    if domain is None:
        typer.echo("Error: provide a domain (or use --list).", err=True)
        raise typer.Exit(1)

    if remove:
        try:
            removed = registry.remove(domain)
        except DomainNotTrackedError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(1) from exc
        if output_json:
            typer.echo(json.dumps({"removed": removed.domain}, indent=2))
        else:
            typer.echo(f"Removed {removed.domain} from tracking.")
        return

    entry = registry.add(domain, _schedule_for(cfg, domain))
    if output_json:
        typer.echo(json.dumps(entry.to_dict(), indent=2))
        return

    schedule = entry.schedule
    state = "enabled" if schedule.enabled else "disabled"
    cron = f", cron={schedule.cron}" if schedule.cron else ""
    typer.echo(
        f"Now tracking {entry.domain}"
        f" (added at {entry.added_at.isoformat()})."
    )
    typer.echo(
        f"  Schedule: {state}{cron}, notify_on_change={schedule.notify_on_change}"
    )


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
