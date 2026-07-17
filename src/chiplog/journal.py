"""Append-only journal of manifest state changes.

One line per record, carrying the resulting state of the chain and file that
record touched. This replaces rewriting the whole manifest per record: the same
fsync, O(1) bytes instead of O(every chain ever).

A line is written with one append + fsync, so the only way to get a partial line
is a crash mid-write, and that can only ever be the LAST line. A trailing partial
line is therefore dropped. A malformed line anywhere else is corruption and
raises: silently skipping it would drop an attestation, which is the failure this
library exists to prevent.
"""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path

from chiplog.manifest import JournalEntry
from chiplog.sinks.base import SinkError

_F_FULLFSYNC = 51  # macOS-specific fcntl constant


class JournalCorruptError(SinkError):
    """A journal line that is neither valid nor a torn tail."""


def _fsync_fd(fd: int) -> None:
    """Best-effort F_FULLFSYNC on macOS, regular fsync elsewhere.

    Default fsync on Darwin only flushes to disk write cache, not the actual
    platter — F_FULLFSYNC blocks until the data is durably on disk.
    """
    if platform.system() == "Darwin":
        try:
            import fcntl

            fcntl.fcntl(fd, _F_FULLFSYNC)
            return
        except (OSError, AttributeError):
            pass
    os.fsync(fd)


def append_entry(path: Path, entry: JournalEntry) -> None:
    """Append one entry + fsync. Durability matches the record append itself."""
    line = json.dumps(entry.to_dict(), sort_keys=True) + "\n"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        _fsync_fd(f.fileno())


def replay(path: Path) -> list[JournalEntry]:
    """Every entry in write order. Missing journal reads as empty."""
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8")
    if not raw:
        return []
    # Always drop the last element of the split. A complete journal ends in "\n",
    # so the last element is ""; a torn one ends mid-line, so the last element is
    # the half-written line. Either way it is not an entry to apply.
    body = raw.split("\n")[:-1]
    out: list[JournalEntry] = []
    for i, line in enumerate(body):
        if not line.strip():
            continue
        try:
            out.append(JournalEntry.from_dict(json.loads(line)))
        except (json.JSONDecodeError, TypeError) as e:
            raise JournalCorruptError(
                f"{path}: journal line {i + 1} is malformed and is not the "
                f"trailing line, so it is not a torn write: {e}"
            ) from e
    return out


__all__ = ["JournalCorruptError", "append_entry", "replay"]
