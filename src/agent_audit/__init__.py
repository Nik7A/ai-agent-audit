"""agent-audit — Cryptographically-linked records of AI agent tool calls.

See SCOPE_STATEMENT.md before staking a compliance claim on v0.1.
"""

from agent_audit.emit import AuditRecorder
from agent_audit.keys import SigningKey, load_public_key, load_signing_key
from agent_audit.redact import DEFAULT_RULES, RedactionConfig, RedactionRule
from agent_audit.schema.v1 import (
    Gate,
    GateDecision,
    NoGateReason,
    Output,
    ToolCall,
    Ungated,
    gate,
    ungated,
)
from agent_audit.sinks.base import (
    DiskFullError,
    InMemorySink,
    Sink,
    SinkError,
    WALOverflowError,
)

__version__ = "0.1.0"

__all__ = [
    "AuditRecorder",
    "DEFAULT_RULES",
    "DiskFullError",
    "Gate",
    "GateDecision",
    "InMemorySink",
    "NoGateReason",
    "Output",
    "RedactionConfig",
    "RedactionRule",
    "Sink",
    "SinkError",
    "SigningKey",
    "ToolCall",
    "Ungated",
    "WALOverflowError",
    "__version__",
    "gate",
    "load_public_key",
    "load_signing_key",
    "ungated",
]
