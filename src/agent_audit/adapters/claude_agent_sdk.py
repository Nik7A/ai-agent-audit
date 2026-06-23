"""Claude Agent SDK (Python) adapter — `HookCallback` for ai-agent-audit.

The Claude Agent SDK exposes a native hooks system (see
``claude_agent_sdk.HookMatcher`` / ``HookCallback``). ``AuditHook`` is a
``HookCallback``-shaped class that records every successful tool call from
a ``ClaudeSDKClient`` session into the audit chain.

Plug it into ``ClaudeAgentOptions.hooks`` under the ``PostToolUse`` event:

    from claude_agent_sdk import (
        ClaudeAgentOptions, ClaudeSDKClient, HookMatcher,
    )
    from agent_audit import AuditRecorder, LocalFileSink, load_signing_key
    from agent_audit.adapters.claude_agent_sdk import AuditHook

    recorder = AuditRecorder(
        sink=LocalFileSink(dir="./audit"),
        signing_key=load_signing_key("./signing.key"),
    )
    options = ClaudeAgentOptions(
        hooks={
            "PostToolUse": [
                HookMatcher(matcher="*", hooks=[AuditHook(recorder=recorder)]),
            ],
        },
    )
    client = ClaudeSDKClient(options=options)

The hook payload supplies ``session_id`` and ``tool_use_id`` directly from
the SDK, so callers don't need to thread them through manually. Failed tool
calls (``PostToolUseFailure`` event) are NOT recorded in v0.1; that gap
closes with the broader ``Stop`` / ``SubagentStop`` work in v0.2.

Designed against claude-agent-sdk 0.2.x.
"""

from __future__ import annotations

import json
from typing import Any

from uuid import uuid7

from agent_audit.emit import AuditRecorder
from agent_audit.schema.v1 import NoGateReason, Output, ToolCall, ungated


def _coerce_to_json(value: Any) -> Any:
    """Round-trip through JSON to drop non-serialisable Python objects.

    Tool responses from the SDK can be arbitrary Python — content blocks,
    custom dataclasses, exception traces. ``json.dumps(default=str)`` falls
    back to ``str()`` for unknowns, keeping the audit record canonicalisable
    without losing the human-readable hint of what the value was.
    """
    return json.loads(json.dumps(value, default=str))


def _extract_session_id(
    hook_input: dict[str, Any], override: str | None
) -> str:
    """Caller override beats the SDK-supplied session_id."""
    if override:
        return override
    sid = hook_input.get("session_id")
    if isinstance(sid, str) and sid:
        return sid
    return "claude-agent-sdk-default"


def _extract_step_id(hook_input: dict[str, Any]) -> str:
    """tool_use_id is the SDK's per-invocation identifier; fall back to a fresh
    UUIDv7 only if it's missing (should not happen with a real PostToolUse)."""
    tool_use_id = hook_input.get("tool_use_id")
    if isinstance(tool_use_id, str) and tool_use_id:
        return tool_use_id
    return str(uuid7())


# ---------------------------------------------------------------------------
# AuditHook
# ---------------------------------------------------------------------------

try:
    import claude_agent_sdk  # noqa: F401

    _CLAUDE_AGENT_SDK_AVAILABLE = True
except ImportError:
    _CLAUDE_AGENT_SDK_AVAILABLE = False


class AuditHook:
    """Claude Agent SDK ``HookCallback`` that records every PostToolUse event.

    Construct once per recorder; pass it to ``ClaudeAgentOptions.hooks`` for
    every tool you want audited (use ``matcher="*"`` to cover all).

    The instance is itself an awaitable callable — the SDK invokes
    ``await audit_hook(input, tool_use_id, context)`` and that triggers one
    signed audit-record write.
    """

    def __init__(
        self,
        recorder: AuditRecorder,
        *,
        session_id: str | None = None,
    ) -> None:
        if not _CLAUDE_AGENT_SDK_AVAILABLE:
            raise ImportError(
                "AuditHook requires claude-agent-sdk >= 0.2. "
                "Install via `pip install claude-agent-sdk`."
            )
        self._recorder = recorder
        self._session_override = session_id

    async def __call__(
        self,
        hook_input: dict[str, Any],
        tool_use_id: str | None,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Record one audit entry for the completed tool call.

        Returns an empty dict — the audit hook does not modify SDK behavior
        or block the tool result. Future ``Gate``-shaped policy records will
        live behind a separate adapter type, not this one.
        """
        # Defensive: only record PostToolUse events. The SDK shouldn't dispatch
        # any other event class to a PostToolUse-registered matcher, but a
        # mis-registration shouldn't crash the agent loop — just no-op.
        if hook_input.get("hook_event_name") != "PostToolUse":
            return {}

        tool_name = hook_input.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name:
            tool_name = "unknown_tool"

        tool_input = hook_input.get("tool_input", {})
        tool_response = hook_input.get("tool_response")

        await self._recorder.record(
            session_id=_extract_session_id(hook_input, self._session_override),
            step_id=_extract_step_id(hook_input),
            tool=ToolCall(name=tool_name),
            input=_coerce_to_json(tool_input),
            output=Output(body=_coerce_to_json(tool_response)),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        )
        return {}


__all__ = ["AuditHook"]
