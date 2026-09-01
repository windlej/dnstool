# Using dnstool

`dnstool` is an all-in-one DNS analysis tool. It is a stateless, one-shot CLI
wrapped by a Textual TUI. Every operation works from the terminal with no
daemon or server; the "platform" is just this tool plus a few plain-text files
under `~/.config/dnstool/`.

This guide covers installing, configuring, using the TUI, and the CLI command
reference. For OS-scheduled periodic backups see
[scheduling.md](scheduling.md).

## Contents

1. [Installation](#installation)
2. [First run & configuration](#first-run--configuration)
3. [The TUI](#the-tui)
   - [Dashboard](#dashboard)
   - [Check screen](#check-screen)
   - [Backup screen](#backup-screen)
   - [Diff screen](#diff-screen)
   - [Track screen](#track-screen)
4. [CLI reference](#cli-reference)
5. [Where data is stored](#where-data-is-stored)
6. [Concepts](#concepts)

## Installation

Create a virtual environment, install the package, and install the `dnstool`
entry point:

```sh
python -m venv .venv
.venv/bin/pip install -e .
.venv/bin/dnstool --help
```

Requires Python 3.10+. No root privileges or network daemons are needed.

## First run & configuration

`dnstool` works out of the box with sensible defaults: it queries Google,
Cloudflare, Quad9, and OpenDNS, and runs DMARC/DKIM/SPF/DNSSEC plus
best-practice checks.

To see and edit the defaults, generate a config file:

```sh
.venv/bin/dnstool init-config
# overwrite an existing config:
.venv/bin/dnstool init-config --force
```

The config lives at `~/.config/dnstool/config.toml`. Key settings:

| Setting | Purpose |
|---------|---------|
| `nameservers` | DNS servers to query (IP, optional `label`, `timeout`) |
| `use_system_resolver` | Also query the OS resolver |
| `timeout` | Query timeout in seconds |
| `record_types` | Record types to fetch by default |
| `checks` | Compliance checks to run |
| `max_snapshots` | Keep at most this many backups per domain |
| `[domains."example.com"]` | Per-domain overrides (`record_types`, `checks`, `tags`) |
| `[domains."example.com".backup]` | Per-domain backup settings (`max_snapshots`) |
| `[domains."example.com".schedule]` | Schedule metadata (see `scheduling.md`) |

Config entries take effect at launch, so edits require restarting the TUI (a
plain TTY restart) — nothing is read at runtime.

## The TUI

Launch the TUI:

```sh
.venv/bin/dnstool tui
# with an explicit config:
.venv/bin/dnstool tui -c /path/to/config.toml
```

The TUI is keyboard-first. Open the **command palette** with `Ctrl+P` and type
the name of anything you want to run (`check`, `backup`, `diff`, `track`,
`dashboard`). `Escape` on any screen returns you to the dashboard.

### Dashboard

The landing screen. It lists **tracked domains** — domains you have added via
the *Track* screen or `dnstool track`. If nothing is tracked yet, it shows
"No domains tracked".

| Column | Meaning |
|--------|---------|
| Domain | The tracked domain |
| Status | `enabled` / `disabled` (from the schedule metadata) |
| Last Snapshot | Timestamp of the newest backup, or `-` if none |
| Records | Record count in the newest snapshot |
| Score | Compliance score (reserved) |

Header buttons (or the equivalent key bindings):

| Button / Key | Action |
|--------------|--------|
| `Check Domain` | Prompt for a domain, then run compliance checks |
| `r` | Refresh the dashboard table |
| `b` | Backup the selected row's domain |
| `d` | Diff the selected row's domain |
| `enter` | Run compliance checks for the selected row's domain |
| `Manage` | Open the *Track* screen |

### Check screen

Reached from the dashboard (`enter` on a row, or `Check Domain`) or the command
palette. It queries the domain and, when the DNS answers, renders:

- A **compliance score** out of 100 (green if ≥ 80, amber if ≥ 50, red below).
- A **checks table** — one row per check: `Severity`, `Check`, `Message`,
  `Details`.
- A **records table** — the deduplicated records found across all queried
  nameservers: `Type`, `Name`, `TTL`, `Value`.

Keys: `b` takes a backup of the same domain, `Escape` returns to the dashboard.

### Backup screen

Reached via `b` on a check/dashboard row or the command palette. Captures a
snapshot of the domain's DNS records, persists it to
`~/.config/dnstool/backups/<domain>/`, and shows the timestamp, total record
count, per-type counts, and the saved path.

The screen reports success or a failure message. `Escape` returns to the
dashboard. Backup data feeds the dashboard's snapshot columns and the *Diff*
screen.

### Diff screen

Reached via `d` on a dashboard row or the command palette. Shows the snapshots
available for the domain (each with its timestamp and record count) and a
**Compute Diff** button. Press it (or `enter`) to compare the two most recent
snapshots.

The diff table is populated from the selected pair:

- `+` rows are records **added** between the old and new snapshot.
- `-` rows are records **removed**.
- `~` rows are records whose values/attributes **changed** (shows the old → new
  field changes).

If there aren't at least two snapshots, or the snapshots are identical, the
screen notifies you instead of showing a table. `Escape` returns to the
dashboard.

### Track screen

Reached via the dashboard's `Manage` button or the command palette. Manages the
tracked-domains list that the dashboard displays:

- **Add Domain** — type a domain and press `Track`.
- **Tracked Domains** — the current list; highlight one and press `Untrack` to
  remove it.

Tracking does not query DNS; it only remembers the domain so the dashboard and
scheduled backups know what to look at. `Escape` returns to the dashboard.

## CLI reference

All commands support `--json` for machine-readable output and `-c/--config`
for a non-default config path.

### `check`

```sh
dnstool check <domain> [-n 8.8.8.8 ...] [-t A] [-t MX] [--json] [-c PATH]
```

Queries the domain's records and runs the configured compliance checks,
printing a record summary and a per-check report with a score out of 100.

### `backup`

```sh
dnstool backup <domain> [-o FILE] [--json] [-c PATH]
```

Captures a snapshot of all DNS records, persists it under
`~/.config/dnstool/backups/`, diffs it against the previous snapshot, and
appends a line to the domain's history log.

Exit codes (script-friendly):

| Code | Meaning |
|------|---------|
| `0` | Success; no change (or first backup for the domain) |
| `1` | Success; DNS records changed since the last backup |
| `2` | Error (e.g. DNS query timeout) |

### `diff`

```sh
dnstool diff <domain> [--snapshot1 TS] [--snapshot2 TS] [--json]
```

Diffs two snapshots of a domain. Defaults to the two most recent snapshots;
`--snapshot1`/`--snapshot2` accept a full ISO timestamp or a unique prefix.
Prints added/removed/changed records.

### `track`

```sh
dnstool track <domain>          # start tracking a domain
dnstool track --list            # list tracked domains
dnstool track <domain> --remove # stop tracking a domain
dnstool track --list --json     # JSON output
```

Manages the tracked-domains list. The schedule settings in `config.toml` are
carried as metadata used by the dashboard's Status column (see
`scheduling.md`).

### `init-config`

```sh
dnstool init-config [--force]
```

Writes a default `~/.config/dnstool/config.toml`. Fails without `--force` if
one already exists.

### `version`

```sh
dnstool version
```

Prints the installed version.

### `tui`

```sh
dnstool tui [-c PATH]
```

Launches the TUI dashboard.

## Where data is stored

Everything lives under `~/.config/dnstool/`:

| Path | Contents |
|------|----------|
| `config.toml` | Configuration (see above) |
| `backups/<domain>/<timestamp>.json` | Snapshot files; one per backup |
| `tracked/<domain>.json` | Tracked domain + schedule metadata |
| `history/<domain>.log` | Append-only change log (one line per backup run) |

Snapshots are plain JSON, so nothing is lost if you delete the tool — the files
are yours to read, version, or archive.

## Concepts

- **Snapshot** — a point-in-time backup of every DNS record for a domain,
  stored as JSON.
- **Compliance check** — a single rule evaluated against a domain's records
  (`dmarc`, `dkim`, `spf`, `dnssec`, and the `*_best_practices` rules). Each
  check returns `pass`, `warning`, `critical`, or `info`; the report's score is
  the fraction of passes.
- **Tracked domain** — a domain in the registry the dashboard and schedulers
  operate on. Tracking is separate from backing up: you can back up a domain
  without tracking it, but the dashboard only shows tracked ones.
- **Diff** — the added/removed/changed records between two snapshots of the
  same domain.