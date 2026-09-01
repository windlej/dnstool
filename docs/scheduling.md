# Scheduling dnstool backups

`dnstool` is a stateless, one-shot CLI: it has no in-process scheduler, daemon,
or background jobs. Scheduling a periodic `dnstool backup` run is the job of
your operating system's scheduler (cron, launchd, or Task Scheduler).

Each successful `dnstool backup <domain>` run does three things:

1. Captures a fresh snapshot of the domain's DNS records.
2. Diffs it against the previous snapshot and appends one line to
   `~/.config/dnstool/history/<domain>.log`:

   ```
   2026-09-01T21:00:00Z CHANGED added=2 removed=1 changed=1
   2026-09-01T22:00:00Z NO_CHANGE
   2026-09-01T23:00:00Z INITIAL
   ```

   `INITIAL` means it was the first run for that domain; `NO_CHANGE` and
   `CHANGED` are relative to the previous snapshot.

3. Exits with a deterministic, script-friendly status:

   | Exit code | Meaning                                            |
   |-----------|----------------------------------------------------|
   | `0`       | Success, no change (or first backup / `INITIAL`)    |
   | `1`       | Success, DNS records changed since the last backup  |
   | `2`       | Error (capture failed, e.g. a DNS query timeout)    |

You can hook notifications off the exit code, so a scheduler only acts when the
DNS actually changed.

> Note: the `[domains."<domain>".schedule]` block in `config.toml`
> (`enabled`, `cron`, `notify_on_change`) is **documentation only**. It is
> carried as metadata inside `dnstool track` entries for human reference and
> informational display; actual execution lives entirely in the OS scheduler
> setups below.

## Linux / cron

Run `backup` every 6 minutes, log stdout/stderr, and notify when the exit code
is non-zero (i.e. changes happened or the run errored):

```cron
*/6 * * * * /path/to/.venv/bin/dnstool backup example.com >> ~/.config/dnstool/cron.log 2>&1 || notify-send "DNS changed"
```

- Use the absolute path to the venv's `dnstool` binary and the absolute path to
  the log file; `cron` does not read your shell config or `~/.profile`.
- The trailing `|| notify-send "DNS changed"` fires on *any* non-zero exit,
  including exit code `2` (an error). To notify only on actual changes, wrap it
  in a small shell script:

  ```sh
  #!/bin/sh
  /path/to/.venv/bin/dnstool backup example.com >> ~/.config/dnstool/cron.log 2>&1
  [ $? -eq 1 ] && notify-send "DNS records changed for example.com"
  ```

  Point cron at that script instead:
  `*/6 * * * * /path/to/dnstool-backup.sh`

## macOS / launchd

`launchd` runs jobs listed in a property list (plist). Save this as
`~/Library/LaunchAgents/com.example.dnstool.backup.example.com.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.dnstool.backup.example.com</string>

  <key>ProgramArguments</key>
  <array>
    <string>/path/to/.venv/bin/dnstool</string>
    <string>backup</string>
    <string>example.com</string>
  </array>

  <!-- Every 6 minutes -->
  <key>StartInterval</key>
  <integer>360</integer>

  <key>StandardOutPath</key>
  <string>/Users/you/.config/dnstool/launchd-example.com.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/you/.config/dnstool/launchd-example.com.log</string>
</dict>
</plist>
```

Then load it:

```sh
launchctl load ~/Library/LaunchAgents/com.example.dnstool.backup.example.com.plist
```

`launchd` does not react to a job's exit code, so for notifications point
`ProgramArguments` at a wrapper script instead of `dnstool` directly:

```sh
#!/bin/sh
/path/to/.venv/bin/dnstool backup example.com >> ~/.config/dnstool/launchd-example.com.log 2>&1
[ $? -eq 1 ] && osascript -e 'display notification "DNS records changed for example.com"'
```

## Windows / Task Scheduler

Create a task that runs `dnstool backup` every 6 minutes:

```
schtasks /Create /F /TN "dnstool-backup-example.com" ^
  /TR "\"C:\path\to\.venv\Scripts\dnstool.exe\" backup example.com" ^
  /SC MINUTE /MO 6
```

Newer Windows (10/11) is stricter about quoting `dnstool.exe`. Let Task Scheduler
run a `.cmd` wrapper instead — this also lets you act on the exit code:

```cmd
@echo off
"C:\path\to\.venv\Scripts\dnstool.exe" backup example.com >> "%USERPROFILE%\.config\dnstool\scheduled.log" 2>&1
if errorlevel 1 if not errorlevel 2 powershell -Command "New-BurntToastNotification" -ErrorAction SilentlyContinue
```

Create the task pointing at the wrapper (GUI: Task Scheduler -> Create Task ->
`Program/script` = the `.cmd` path, `Triggers` -> `Daily` repeated every 6
minutes, `Settings` -> uncheck "Stop the task if it runs longer than"). Or with:

```
schtasks /Create /F /TN "dnstool-backup-example.com" ^
  /TR "C:\path\to\dnstool-backup.cmd" ^
  /SC MINUTE /MO 6
```

## Inspecting the change history

The history is plain text under `~/.config/dnstool/history/` — one `.log` file
per domain, newest line last:

```
tail -f ~/.config/dnstool/history/example.com.log
```