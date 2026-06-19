"""Step 6.5: LangGraph adapter tests.

Covers:
- @audited_tool on a sync function: records input, records output, verifier accepts
- @audited_tool on an async function (verified via plain pytest-asyncio test)
- @audited_tool preserves return value and metadata (__name__, __doc__)
- AuditMiddleware.wrap_tool_call records the tool call from a fake ToolCallRequest
- AuditMiddleware.awrap_tool_call records the tool call from async path
- AuditMiddleware extracts tool name and args from dict-shaped tool_call
- AuditMiddleware handles ToolMessage-shaped results (content attr) and raw returns
- Real create_agent integration: build a tiny agent, invoke a single tool, audit log
  contains the expected record, verifier returns exit 0
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import PublicFormat

from agent_audit.adapters.langgraph import (
    AuditMiddleware,
    _coerce_to_json,
    _extract_output_body,
    _extract_tool_info,
    audited_tool,
)
from agent_audit.emit import AuditRecorder
from agent_audit.integrity import verify_record
from agent_audit.keys import SigningKey, compute_key_id
from agent_audit.sinks.base import InMemorySink


@pytest.fixture
def signing_key() -> SigningKey:
    pk = Ed25519PrivateKey.generate()
    pub = pk.public_key()
    return SigningKey(private_key=pk, public_key=pub, key_id=compute_key_id(pub))


@pytest.fixture
def sink() -> InMemorySink:
    return InMemorySink()


@pytest.fixture
def recorder(sink: InMemorySink, signing_key: SigningKey) -> AuditRecorder:
    return AuditRecorder(sink=sink, signing_key=signing_key)


# ---------------------------------------------------------------------------
# @audited_tool
# ---------------------------------------------------------------------------


def test_audited_tool_sync_records_and_returns(
    recorder: AuditRecorder, sink: InMemorySink, signing_key: SigningKey
) -> None:
    @audited_tool(recorder, session_id="demo")
    def add(x: int, y: int) -> int:
        return x + y

    result = add(2, 3)
    assert result == 5

    assert len(sink.records) == 1
    rec = sink.records[0]
    assert rec["payload"]["tool"]["name"] == "add"
    assert rec["payload"]["output"]["body"] == 5
    assert rec["payload"]["input"]["kwargs"] == {}

    # Audit record verifies
    assert verify_record(rec, {signing_key.key_id: signing_key.public_key}).is_valid


def test_audited_tool_captures_kwargs(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, session_id="demo")
    def search(query: str, limit: int = 10) -> list[str]:
        return [f"{query}-{i}" for i in range(min(limit, 2))]

    search(query="foo", limit=2)
    rec = sink.records[0]
    assert rec["payload"]["input"]["kwargs"] == {"query": "foo", "limit": 2}
    assert rec["payload"]["output"]["body"] == ["foo-0", "foo-1"]


def test_audited_tool_preserves_metadata(recorder: AuditRecorder) -> None:
    @audited_tool(recorder)
    def my_func(x: int) -> int:
        """Original docstring."""
        return x

    assert my_func.__name__ == "my_func"
    assert my_func.__doc__ == "Original docstring."


def test_audited_tool_custom_name(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, tool_name="custom_label")
    def some_fn() -> str:
        return "ok"

    some_fn()
    assert sink.records[0]["payload"]["tool"]["name"] == "custom_label"


async def test_audited_tool_async_records_and_returns(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    @audited_tool(recorder, session_id="demo")
    async def fetch(url: str) -> str:
        return f"<body of {url}>"

    result = await fetch(url="https://example.com")
    assert result == "<body of https://example.com>"

    rec = sink.records[0]
    assert rec["payload"]["tool"]["name"] == "fetch"
    assert rec["payload"]["input"]["kwargs"] == {"url": "https://example.com"}


def test_audited_tool_chain_advances_across_calls(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    from agent_audit.integrity import compute_chain_link

    @audited_tool(recorder)
    def noop() -> int:
        return 0

    noop()
    noop()
    noop()

    r0, r1, r2 = sink.records
    assert r0["envelope"]["prev_hash"] is None
    assert r1["envelope"]["prev_hash"] == compute_chain_link(r0)
    assert r2["envelope"]["prev_hash"] == compute_chain_link(r1)


# ---------------------------------------------------------------------------
# AuditMiddleware internals (via fake request shapes)
# ---------------------------------------------------------------------------


class _FakeRequest:
    """Mimics enough of LangChain's ToolCallRequest for the middleware to read."""

    def __init__(self, name: str, args: dict[str, Any]) -> None:
        self.tool_call = {"name": name, "args": args, "id": "fake-call-1"}


class _FakeToolMessage:
    """Mimics ToolMessage: has a .content attribute."""

    def __init__(self, content: Any) -> None:
        self.content = content


def test_middleware_wrap_tool_call_records_sync(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="sync-session")

    def handler(request: Any) -> _FakeToolMessage:
        return _FakeToolMessage(content="42")

    request = _FakeRequest("add", {"x": 1, "y": 2})
    result = mw.wrap_tool_call(request, handler)

    assert result.content == "42"
    assert len(sink.records) == 1
    rec = sink.records[0]
    assert rec["payload"]["tool"]["name"] == "add"
    assert rec["payload"]["input"] == {"x": 1, "y": 2}
    assert rec["payload"]["output"]["body"] == "42"


async def test_middleware_awrap_tool_call_records_async(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    mw = AuditMiddleware(recorder, session_id="async-session")

    async def handler(request: Any) -> _FakeToolMessage:
        return _FakeToolMessage(content={"k": "v"})

    request = _FakeRequest("dict_tool", {"q": "x"})
    result = await mw.awrap_tool_call(request, handler)

    assert result.content == {"k": "v"}
    rec = sink.records[0]
    assert rec["payload"]["tool"]["name"] == "dict_tool"
    assert rec["payload"]["output"]["body"] == {"k": "v"}


def test_middleware_handles_missing_tool_call_gracefully(
    recorder: AuditRecorder, sink: InMemorySink
) -> None:
    """A malformed request with no tool_call attribute should not crash —
    just record 'unknown_tool' so the audit trail isn't silently dropped."""
    mw = AuditMiddleware(recorder, session_id="x")

    class Bare:
        pass

    mw.wrap_tool_call(Bare(), lambda req: _FakeToolMessage(content="x"))
    assert sink.records[0]["payload"]["tool"]["name"] == "unknown_tool"


def test_extract_helpers() -> None:
    assert _extract_tool_info(_FakeRequest("foo", {"a": 1})) == ("foo", {"a": 1})
    assert _extract_output_body(_FakeToolMessage(content="hello")) == "hello"


def test_coerce_handles_non_json_values() -> None:
    """Non-serialisable Python objects fall back to repr/str. Audit records
    canonicalise without crashing on rich LangGraph state objects."""

    class Weird:
        def __str__(self) -> str:
            return "weird-thing"

    coerced = _coerce_to_json({"obj": Weird(), "n": 42})
    assert coerced["obj"] == "weird-thing"
    assert coerced["n"] == 42


# ---------------------------------------------------------------------------
# End-to-end via real create_agent + FakeListChatModel
# ---------------------------------------------------------------------------


class _FakeToolCallingChatModel:
    """Minimal stand-in for a tool-calling chat model in create_agent.

    Yields a pre-configured sequence of AIMessages — first one with a
    tool_calls entry (so create_agent dispatches to the tool), second
    with plain text (so the agent terminates). bind_tools is a no-op.
    """

    def __init__(self, messages: list[Any]) -> None:
        self._messages = list(messages)
        self._idx = 0

    def bind_tools(self, tools: list[Any], **kwargs: Any) -> _FakeToolCallingChatModel:
        return self

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        msg = self._messages[self._idx]
        self._idx += 1
        return msg

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        return self.invoke(input, config, **kwargs)


def test_real_create_agent_with_audit_middleware_records_tool_call(
    tmp_path: Path,
) -> None:
    """Build a tiny LangChain agent with a fake tool-calling model, invoke
    a single tool, and verify the audit log captured exactly that call."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _E,
        NoEncryption,
        PrivateFormat,
    )
    from langchain.agents import create_agent
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from click.testing import CliRunner

    from agent_audit.cli import EXIT_OK, cli
    from agent_audit.keys import load_signing_key
    from agent_audit.sinks.local_file import LocalFileSink

    pk = Ed25519PrivateKey.generate()
    priv = tmp_path / "signing.key"
    pub = tmp_path / "signing.pub"
    priv.write_bytes(
        pk.private_bytes(_E.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    priv.chmod(0o600)
    pub.write_bytes(
        pk.public_key().public_bytes(_E.PEM, PublicFormat.SubjectPublicKeyInfo)
    )

    sk = load_signing_key(priv)
    sink = LocalFileSink(dir=tmp_path / "audit", pubkey_pem=pub.read_bytes())
    recorder = AuditRecorder(sink=sink, signing_key=sk, chain_id="e2e")

    @tool
    def echo(text: str) -> str:
        """Echo the input."""
        return f"echoed: {text}"

    tool_call_msg = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "echo",
                "args": {"text": "hello"},
                "id": "call-1",
                "type": "tool_call",
            }
        ],
    )
    final_msg = AIMessage(content="done")
    model = _FakeToolCallingChatModel([tool_call_msg, final_msg])

    agent = create_agent(
        model=model,  # type: ignore[arg-type]
        tools=[echo],
        middleware=[AuditMiddleware(recorder, session_id="e2e-session")],
    )

    agent.invoke({"messages": [{"role": "user", "content": "say hi"}]})

    jsonl = next((tmp_path / "audit").glob("audit-*.jsonl"))
    lines = jsonl.read_text().splitlines()
    assert len(lines) == 1, f"expected 1 tool-call record, got {len(lines)}"
    record = json.loads(lines[0])
    assert record["payload"]["tool"]["name"] == "echo"
    assert record["payload"]["input"] == {"text": "hello"}
    assert "echoed" in str(record["payload"]["output"]["body"])
    assert record["envelope"]["chain_id"] == "e2e"

    runner = CliRunner()
    result = runner.invoke(cli, ["verify", str(jsonl), "--pubkey", str(pub)])
    assert result.exit_code == EXIT_OK, result.output
