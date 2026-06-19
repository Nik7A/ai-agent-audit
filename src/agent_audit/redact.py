"""Deny-list PII redaction for tool call input/output.

Default rules cover the most common patterns that leak into agent tool calls:
emails, AWS access keys, GitHub PATs, OpenAI / Anthropic / Slack tokens.

Design notes:
- Whole-value replacement: if ANY rule matches anywhere in a string field,
  the entire field is replaced with a structured marker. This is the
  scorched-earth default; it's better to lose precision than to leak.
- Recursion through dicts and lists with JSONPath-shaped path tracking.
- Marker structure: `{redacted: true, type: "string", length: N, policy: "...", sha256?: "..."}`.
- High-sensitivity rules (API keys, secrets) set `strip_hash=True` so the
  marker does NOT include sha256 — hashing low-entropy or already-leaked
  values would itself be a leak.

For custom rules, users construct `RedactionConfig(rules=[*DEFAULT_RULES, my_rule])`
or replace the list entirely.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from agent_audit.schema.v1 import RedactionEntry


@dataclass(frozen=True)
class RedactionRule:
    """One deny-list rule.

    Attributes:
        policy_id: Stable identifier surfaced in the redaction audit
            (e.g. "pii.deny.email"). Use dotted lowercase by convention.
        pattern: Compiled regex. If it matches anywhere in a string value,
            the entire value is replaced with a marker.
        strip_hash: If True, the marker omits sha256. Set for high-sensitivity
            rules where even a hash is too much (e.g. low-entropy secrets,
            tokens that might be brute-forced from their hash).
    """

    policy_id: str
    pattern: re.Pattern[str]
    strip_hash: bool = False


DEFAULT_RULES: tuple[RedactionRule, ...] = (
    RedactionRule(
        "pii.deny.email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    RedactionRule(
        "pii.deny.aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        strip_hash=True,
    ),
    RedactionRule(
        "pii.deny.github_pat_fine_grained",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        strip_hash=True,
    ),
    RedactionRule(
        "pii.deny.github_pat_classic",
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        strip_hash=True,
    ),
    # Anthropic checked before OpenAI: `sk-ant-...` would otherwise match the
    # looser OpenAI pattern (it doesn't today because of dashes, but the
    # explicit ordering documents intent).
    RedactionRule(
        "pii.deny.anthropic_key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        strip_hash=True,
    ),
    RedactionRule(
        "pii.deny.openai_key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        strip_hash=True,
    ),
    RedactionRule(
        "pii.deny.slack_token",
        re.compile(r"\bxox[bopas]-\d+-\d+-\d+-[a-zA-Z0-9]+\b"),
        strip_hash=True,
    ),
)


@dataclass
class RedactionConfig:
    """User-facing config for the redactor.

    Default: enabled, with DEFAULT_RULES. Set `disable=True` to record
    full unredacted values — but note the recorder will surface that fact
    in the manifest so it's never silently off (self-audit checklist).
    """

    rules: tuple[RedactionRule, ...] = field(default=DEFAULT_RULES)
    disable: bool = False


def _make_marker(value: str, rule: RedactionRule) -> dict[str, Any]:
    marker: dict[str, Any] = {
        "redacted": True,
        "type": "string",
        "length": len(value),
        "policy": rule.policy_id,
    }
    if not rule.strip_hash:
        marker["sha256"] = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return marker


def redact_value(
    value: Any, config: RedactionConfig, path: str = "$"
) -> tuple[Any, list[RedactionEntry]]:
    """Recursively redact a value. Returns (redacted_value, list of audit entries).

    Path uses JSONPath-shaped notation: `$.input.args.email`, `$.output.body[3]`.
    """
    if config.disable:
        return value, []

    if isinstance(value, str):
        for rule in config.rules:
            if rule.pattern.search(value):
                return _make_marker(value, rule), [
                    RedactionEntry(path=path, policy=rule.policy_id)
                ]
        return value, []

    if isinstance(value, dict):
        result_dict: dict[str, Any] = {}
        all_entries: list[RedactionEntry] = []
        for k, v in value.items():
            child_path = f"{path}.{k}"
            redacted_v, entries = redact_value(v, config, child_path)
            result_dict[k] = redacted_v
            all_entries.extend(entries)
        return result_dict, all_entries

    if isinstance(value, list):
        result_list: list[Any] = []
        list_entries: list[RedactionEntry] = []
        for i, item in enumerate(value):
            child_path = f"{path}[{i}]"
            redacted_item, entries = redact_value(item, config, child_path)
            result_list.append(redacted_item)
            list_entries.extend(entries)
        return result_list, list_entries

    # primitives (int, float, bool, None) — no redaction needed
    return value, []


__all__ = [
    "DEFAULT_RULES",
    "RedactionConfig",
    "RedactionRule",
    "redact_value",
]
