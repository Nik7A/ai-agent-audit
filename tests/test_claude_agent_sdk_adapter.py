"""Claude Agent SDK adapter tests.

Covers:
- _extract_session_id: caller override beats SDK-supplied; SDK value used otherwise; default fallback when both missing
- _extract_step_id: uses tool_use_id from input; falls back to UUIDv7 when missing
- _coerce_to_json: non-serialisable objects survive via str() default
- AuditHook.__call__ on a PostToolUse input emits a signed record
- The emitted record carries the SDK session_id, tool_use_id as step_id, tool_name, tool_input, tool_response
- Non-PostToolUse events are silently no-op'd (defensive)
- AuditHook records two sequential calls into a verifiable chain
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_audit.adapters.claude_agent_sdk import (
    AuditHook,
    _coerce_to_json,
    _extract_session_id,
    _extract_step_id,
)
from agent_audit.emit import AuditRecorder
from agent_audit.integrity import verify_record
from agent_audit.keys import SigningKey, compute_key_id
from agent_audit.sinks.base import InMemorySink


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def signing_key() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


@pytest.fixture
def sink() -> InMemorySink:
    return InMemorySink()


@pytest.fixture
def recorder(signing_key: SigningKey, sink: InMemorySink) -> AuditRecorder:
    return AuditRecorder(sink=sink, signing_key=signing_key)


def _post_tool_use_input(
    *,
    session_id: str = "sdk-session-001",
    tool_use_id: str = "toolu_01ABCdef",
    tool_name: str = "Bash",
    tool_input: dict[str, Any] | None = None,
    tool_response: Any = "command exited 0",
) -> dict[str, Any]:
    """Shape mirrors claude_agent_sdk.PostToolUseHookInput."""
    return {
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/workspace",
        "tool_use_id": tool_use_id,
        "tool_name": tool_name,
        "tool_input": tool_input if tool_input is not None else {"command": "ls -la"},
        "tool_response": tool_response,
    }


# ---------------------------------------------------------------------------
# Extractor unit tests
# ---------------------------------------------------------------------------


def test_extract_session_id_caller_override_wins() -> None:
    hook_input = _post_tool_use_input(session_id="sdk-session")
    assert _extract_session_id(hook_input, "user-override") == "user-override"


def test_extract_session_id_uses_sdk_value_when_no_override() -> None:
    hook_input = _post_tool_use_input(session_id="sdk-session-abc")
    assert _extract_session_id(hook_input, None) == "sdk-session-abc"


def test_extract_session_id_falls_back_when_missing() -> None:
    hook_input: dict[str, Any] = {"hook_event_name": "PostToolUse"}
    assert (
        _extract_session_id(hook_input, None) == "claude-agent-sdk-default"
    )


def test_extract_step_id_uses_tool_use_id() -> None:
    hook_input = _post_tool_use_input(tool_use_id="toolu_99XYZ")
    assert _extract_step_id(hook_input) == "toolu_99XYZ"


def test_extract_step_id_falls_back_to_uuid7() -> None:
    hook_input: dict[str, Any] = {"hook_event_name": "PostToolUse"}
    result = _extract_step_id(hook_input)
    # UUIDv7 string is 36 chars with the canonical hyphen layout
    assert len(result) == 36 and result.count("-") == 4


def test_coerce_to_json_drops_non_serialisable() -> None:
    class Opaque:
        def __repr__(self) -> str:
            return "<Opaque>"

    payload = {"k": Opaque(), "n": 1}
    assert _coerce_to_json(payload) == {"k": "<Opaque>", "n": 1}


# ---------------------------------------------------------------------------
# AuditHook integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_call_emits_signed_record(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    hook = AuditHook(recorder=recorder)
    hook_input = _post_tool_use_input(
        session_id="my-session",
        tool_use_id="toolu_xy_001",
        tool_name="Read",
        tool_input={"file_path": "/etc/hosts"},
        tool_response={"content": "127.0.0.1 localhost"},
    )

    result = await hook(hook_input=hook_input, tool_use_id="toolu_xy_001", context={})
    assert result == {}  # hook does not modify SDK behavior

    assert len(sink.records) == 1
    record = sink.records[0]

    assert record["header"]["session_id"] == "my-session"
    assert record["header"]["step_id"] == "toolu_xy_001"
    assert record["payload"]["tool"]["name"] == "Read"
    assert record["payload"]["input"] == {"file_path": "/etc/hosts"}
    assert record["payload"]["output"]["body"] == {"content": "127.0.0.1 localhost"}

    pubkey_by_id = {signing_key.key_id: signing_key.public_key}
    verification = verify_record(record, pubkey_by_id)
    assert verification.is_valid, verification.detail


@pytest.mark.asyncio
async def test_call_with_session_override(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    hook = AuditHook(recorder=recorder, session_id="audit-override")
    hook_input = _post_tool_use_input(session_id="sdk-supplied")
    await hook(hook_input=hook_input, tool_use_id="t1", context={})

    assert sink.records[0]["header"]["session_id"] == "audit-override"


@pytest.mark.asyncio
async def test_call_with_unknown_tool_name_is_recorded(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    hook = AuditHook(recorder=recorder)
    hook_input = _post_tool_use_input(tool_name="")
    await hook(hook_input=hook_input, tool_use_id="t1", context={})

    assert sink.records[0]["payload"]["tool"]["name"] == "unknown_tool"


@pytest.mark.asyncio
async def test_non_post_tool_use_event_is_silently_skipped(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """A misregistered hook receiving e.g. PreToolUse must not crash; just no-op."""
    hook = AuditHook(recorder=recorder)
    pre_tool_input = {
        "hook_event_name": "PreToolUse",
        "session_id": "s",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "tool_use_id": "t1",
    }
    result = await hook(hook_input=pre_tool_input, tool_use_id="t1", context={})

    assert result == {}
    assert len(sink.records) == 0


@pytest.mark.asyncio
async def test_chain_of_two_records(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    hook = AuditHook(recorder=recorder)
    for i in range(2):
        hook_input = _post_tool_use_input(
            tool_use_id=f"toolu_{i:03d}",
            tool_input={"i": i},
            tool_response=f"result-{i}",
        )
        await hook(hook_input=hook_input, tool_use_id=f"toolu_{i:03d}", context={})

    assert len(sink.records) == 2
    first, second = sink.records
    assert first["envelope"]["prev_hash"] is None
    assert second["envelope"]["prev_hash"] is not None

    pubkey_by_id = {signing_key.key_id: signing_key.public_key}
    for rec in (first, second):
        assert verify_record(rec, pubkey_by_id).is_valid
