"""Append-only per-domain change log.

Each successful ``dnstool backup`` run appends one compact line to
``<HISTORY_DIR>/<domain>.log`` recording whether DNS records changed since the
previous snapshot and how many records were added, removed, or changed.

Change detection reuses ``SnapshotStore.diff``; a single snapshot (first run)
is logged as ``INITIAL``. Logging never issues DNS queries of its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from dnstool.config import HISTORY_DIR
from dnstool.snapshots import NoSnapshotsError, SnapshotStore, normalize_domain

_TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%SZ"


class ChangeStatus(str, Enum):
    """Outcome of a backup run relative to the previous snapshot."""

    INITIAL = "INITIAL"
    NO_CHANGE = "NO_CHANGE"
    CHANGED = "CHANGED"


@dataclass(frozen=True)
class HistoryEntry:
    """A single parsed history log entry."""

    timestamp: datetime
    status: ChangeStatus
    added: int = 0
    removed: int = 0
    changed: int = 0

    @property
    def line(self) -> str:
        """Render the entry as one compact log line."""
        line = (
            f"{self.timestamp.astimezone(timezone.utc).strftime(_TIMESTAMP_FMT)} "
            f"{self.status.value}"
        )
        if self.status == ChangeStatus.CHANGED:
            line += f" added={self.added} removed={self.removed} changed={self.changed}"
        return line


def path_for(domain: str, base_dir: Path | None = None) -> Path:
    """Path of the append-only history log for ``domain``."""
    return (base_dir or HISTORY_DIR) / f"{normalize_domain(domain)}.log"


def parse_entry(line: str) -> HistoryEntry:
    """Parse a single history log line into a ``HistoryEntry``."""
    parts = line.split()
    timestamp = datetime.strptime(parts[0], _TIMESTAMP_FMT).replace(
        tzinfo=timezone.utc
    )
    counts: dict[str, int] = {}
    for part in parts[2:]:
        key, value = part.split("=", 1)
        counts[key] = int(value)
    return HistoryEntry(
        timestamp=timestamp,
        status=ChangeStatus(parts[1]),
        added=counts.get("added", 0),
        removed=counts.get("removed", 0),
        changed=counts.get("changed", 0),
    )


def log_run(
    store: SnapshotStore,
    domain: str,
    base_dir: Path | None = None,
) -> HistoryEntry:
    """Diff ``domain`` against its previous snapshot and append a log line.

    A single snapshot means the first run: the entry is logged as ``INITIAL``
    (``NoSnapshotsError`` is swallowed; no extra DNS queries). The log line is
    always written and the appended entry is returned.
    """
    domain = normalize_domain(domain)
    try:
        diff = store.diff(domain)
    except NoSnapshotsError:
        try:
            captured_at = store.latest(domain).captured_at
        except NoSnapshotsError:
            captured_at = datetime.now(timezone.utc)
        entry = HistoryEntry(timestamp=captured_at, status=ChangeStatus.INITIAL)
    else:
        entry = HistoryEntry(
            timestamp=diff.new_snapshot.captured_at,
            status=(
                ChangeStatus.CHANGED
                if diff.has_changes
                else ChangeStatus.NO_CHANGE
            ),
            added=len(diff.added),
            removed=len(diff.removed),
            changed=len(diff.changed),
        )

    path = path_for(domain, base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(f"{entry.line}\n")
    return entry


def last_entry(domain: str, base_dir: Path | None = None) -> HistoryEntry | None:
    """Return the most recent history entry for ``domain``, or ``None``."""
    path = path_for(domain, base_dir)
    if not path.exists():
        return None
    with path.open() as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    if not lines:
        return None
    return parse_entry(lines[-1])
