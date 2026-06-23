"""Bench 3: verifier records/sec on a pre-populated 10 000-record corpus.

Answers "auditor wants to verify N months of records — how long?". This is
pure CPU + memory; no fsync, no writes. Single-threaded.

Throughput target for v0.1: under five minutes for one day of records on a
2-vCPU pod. With 10K records / round, throughput >= 33 rec/s would clear
five minutes per 10K; realistic numbers should land 1-2 orders higher.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit.integrity import verify_record

ROUNDS = 5


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _verify_all(
    records: list[dict[str, object]], pubkey_by_id: dict[str, object]
) -> None:
    for rec in records:
        result = verify_record(rec, pubkey_by_id)  # type: ignore[arg-type]
        if not result.is_valid:
            raise AssertionError(
                f"verifier returned invalid result on bench corpus: {result.failure}"
            )


@pytest.mark.benchmark(group="verifier_throughput")
def test_verifier_throughput(
    benchmark: object,
    prepopulated_jsonl: Path,
    prepopulated_pubkey_by_id: dict[str, object],
) -> None:
    """Verify a 10 000-record JSONL file end-to-end."""
    records = _load_jsonl(prepopulated_jsonl)
    if len(records) < 9_000:
        raise RuntimeError(
            f"verifier corpus underpopulated: expected ~10000 records, got {len(records)}"
        )

    benchmark.pedantic(  # type: ignore[attr-defined]
        _verify_all,
        args=(records, prepopulated_pubkey_by_id),
        iterations=1,
        rounds=ROUNDS,
    )
    benchmark.extra_info["records_in_corpus"] = len(records)  # type: ignore[attr-defined]
