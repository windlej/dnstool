# dnstool

All-in-one DNS analysis tool with TUI interface.

See [docs/usage.md](docs/usage.md) for full usage: the TUI dashboard, CLI
commands, configuration, and where data is stored.

## Features (planned)

- Query domains across multiple name servers with response time tracking
- Compliance checks: DMARC, DKIM, SPF, DNSSEC
- Record best practice analysis
- DNS record backup and diff
- Domain tracking with change history
- Beautiful TUI dashboard

## Scheduling backups

`dnstool` is a stateless one-shot CLI. To run periodic DNS backups with
change detection and script-friendly exit codes, wire it into your OS scheduler.

See [docs/scheduling.md](docs/scheduling.md) for Linux cron, macOS launchd, and
Windows Task Scheduler setup recipes.
