"""Sink protocol + in-memory implementation.

A Sink is a destination for fully-signed records. v0.1 ships only the
in-memory sink (used by tests and quickstart smoke runs). The Sink protocol
is intentionally narrow so adding a new backend in v0.2 is straightforward.

Contract that all sinks MUST honour:
- `write(record)` either persists the record durably OR raises a SinkError.
  No silent drops, ever.
- `flush()` blocks until every previously-written record is durable.
- `close()` implies a final flush() and frees resources.
- `write()` after `close()` raises SinkError.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


class SinkError(Exception):
    """Base for all sink-side errors."""


class DiskFullError(SinkError):
    """Local file sink ran out of disk space — emitter must halt loudly."""


class WALOverflowError(SinkError):
    """Write-ahead log has accumulated more pending records than the cap."""


@runtime_checkable
class Sink(Protocol):
    """A destination for signed audit records."""

    async def write(self, record: dict[str, Any]) -> None: ...

    async def flush(self) -> None: ...

    async def close(self) -> None: ...


class InMemorySink:
    """In-memory sink for tests and AuditRecorder smoke runs.

    Records remain accessible via `.records` for assertions. After close(),
    further write() calls raise SinkError.
    """

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self._closed = False

    async def write(self, record: dict[str, Any]) -> None:
        if self._closed:
            raise SinkError("InMemorySink is closed — cannot write more records")
        self.records.append(record)

    async def flush(self) -> None:
        # No buffering — everything is already in-memory by the time write() returns.
        return

    async def close(self) -> None:
        self._closed = True


__all__ = [
    "DiskFullError",
    "InMemorySink",
    "Sink",
    "SinkError",
    "WALOverflowError",
]
