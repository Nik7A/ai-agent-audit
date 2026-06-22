"""LangGraph adapter — secondary instrumentation path (for non-Claude-CLI users).

Two entry points:

  1. `AuditMiddleware` — subclass of LangChain 1.x's `AgentMiddleware`. Plug
     into `create_agent(model, tools, middleware=[AuditMiddleware(rec)])`
     and every tool call goes through `wrap_tool_call` / `awrap_tool_call`
     → one audit record per tool call.

  2. `@audited_tool` — decorator for any callable (sync or async). Useful
     for raw `StateGraph` users who don't go through `create_agent`, or for
     plain Python code that wants the same audit semantics.

Both routes use the same `AuditRecorder` underneath; differences are just
how they attach to the runtime.

Designed against LangChain 1.3.x / LangGraph 1.2.x. Older versions without
`langchain.agents.middleware` will get a clear ImportError when constructing
`AuditMiddleware`; the `@audited_tool` decorator has no LangChain dependency.
"""

from __future__ import annotations

import functools
import inspect
import json
from typing import Any, Callable, TypeVar

from uuid import uuid7

from agent_audit.emit import AuditRecorder
from agent_audit.schema.v1 import NoGateReason, Output, ToolCall, ungated

F = TypeVar("F", bound=Callable[..., Any])


def _coerce_to_json(value: Any) -> Any:
    """Round-trip through JSON to drop non-serialisable Python objects.

    LangGraph callbacks routinely pass state, config, and runtime objects
    that hold non-JSON-friendly references (locks, callbacks, BaseTools).
    `json.dumps(..., default=str)` falls back to str() for unknowns, which
    keeps the audit record canonicalisable without losing the human-readable
    hint of what was there.
    """
    return json.loads(json.dumps(value, default=str))


def audited_tool(
    recorder: AuditRecorder,
    *,
    session_id: str | None = None,
    tool_name: str | None = None,
) -> Callable[[F], F]:
    """Decorator: wrap a tool callable with audit recording.

    Records ONE audit entry per call, AFTER the wrapped function returns.
    Works on both sync and async callables. Errors from the wrapped tool
    propagate; v0.1 does not record failed calls (Stop/SubagentStop-style
    coverage lands in v0.2).
    """

    def decorator(fn: F) -> F:
        actual_name: str = tool_name or str(getattr(fn, "__name__", "anonymous_tool"))
        sid = session_id or "langgraph-default"

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = await fn(*args, **kwargs)
                await recorder.record(
                    session_id=sid,
                    step_id=str(uuid7()),
                    tool=ToolCall(name=actual_name),
                    input=_coerce_to_json({"args": args, "kwargs": kwargs}),
                    output=Output(body=_coerce_to_json(result)),
                    policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
                )
                return result

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            result = fn(*args, **kwargs)
            recorder.record_sync(
                session_id=sid,
                step_id=str(uuid7()),
                tool=ToolCall(name=actual_name),
                input=_coerce_to_json({"args": args, "kwargs": kwargs}),
                output=Output(body=_coerce_to_json(result)),
                policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
            )
            return result

        return sync_wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# AgentMiddleware integration
# ---------------------------------------------------------------------------

try:
    from langchain.agents.middleware import AgentMiddleware as _AgentMiddleware

    _AGENT_MIDDLEWARE_AVAILABLE = True
except ImportError:
    _AgentMiddleware = object  # type: ignore[assignment, misc]
    _AGENT_MIDDLEWARE_AVAILABLE = False


def _extract_tool_info(request: Any) -> tuple[str, Any]:
    """Best-effort extraction of (tool_name, tool_args) from a ToolCallRequest."""
    tool_call = getattr(request, "tool_call", None)
    if isinstance(tool_call, dict):
        return tool_call.get("name", "unknown_tool"), tool_call.get("args", {})
    if tool_call is not None:
        return (
            getattr(tool_call, "name", "unknown_tool"),
            getattr(tool_call, "args", {}),
        )
    return "unknown_tool", {}


def _extract_output_body(result: Any) -> Any:
    """Extract body from ToolMessage / Command / raw return."""
    content = getattr(result, "content", None)
    if content is not None:
        return content
    update = getattr(result, "update", None)
    if update is not None:
        return update
    return str(result)


class AuditMiddleware(_AgentMiddleware):
    """LangChain 1.x AgentMiddleware that records every tool call.

    Usage:
        from langchain.agents import create_agent
        from agent_audit import AuditRecorder, LocalFileSink, load_signing_key
        from agent_audit.adapters.langgraph import AuditMiddleware

        recorder = AuditRecorder(
            sink=LocalFileSink(dir="./audit"),
            signing_key=load_signing_key("./signing.key"),
        )
        agent = create_agent(
            model="claude-opus-4-7",
            tools=[my_tool],
            middleware=[AuditMiddleware(recorder, session_id="demo")],
        )
    """

    def __init__(
        self,
        recorder: AuditRecorder,
        *,
        session_id: str | None = None,
    ) -> None:
        if not _AGENT_MIDDLEWARE_AVAILABLE:
            raise ImportError(
                "AuditMiddleware requires langchain >= 1.0 with "
                "langchain.agents.middleware. Install via `pip install langchain`."
            )
        super().__init__()
        self._recorder = recorder
        self._session_id = session_id or "langgraph-default"

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        """Sync interceptor: run the tool, record, return the result."""
        result = handler(request)
        self._record_sync(request, result)
        return result

    async def awrap_tool_call(
        self, request: Any, handler: Callable[[Any], Any]
    ) -> Any:
        """Async interceptor: await the tool, record (async), return."""
        result = await handler(request)
        await self._record_async(request, result)
        return result

    def _record_sync(self, request: Any, result: Any) -> None:
        name, args = _extract_tool_info(request)
        self._recorder.record_sync(
            session_id=self._session_id,
            step_id=str(uuid7()),
            tool=ToolCall(name=name),
            input=_coerce_to_json(args),
            output=Output(body=_coerce_to_json(_extract_output_body(result))),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        )

    async def _record_async(self, request: Any, result: Any) -> None:
        name, args = _extract_tool_info(request)
        await self._recorder.record(
            session_id=self._session_id,
            step_id=str(uuid7()),
            tool=ToolCall(name=name),
            input=_coerce_to_json(args),
            output=Output(body=_coerce_to_json(_extract_output_body(result))),
            policy=ungated(NoGateReason.AUTO_ALLOWED_LOW_RISK),
        )


__all__ = ["AuditMiddleware", "audited_tool"]
