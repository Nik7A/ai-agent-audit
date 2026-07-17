"""The journal carries resulting state, so replay is idempotent.

The manifest is an attestation, not a cache: verify.py reports MANIFEST_INTEGRITY
when it disagrees with the log. Replay therefore has to reconstruct exactly the
state the old full-rewrite path held — no more, no less.

Idempotence is not a nicety. Compaction writes the checkpoint and only then drops
the journal, so a crash between the two replays lines onto a newer checkpoint.
That is safe only because a line states the result rather than a delta.
"""

from __future__ import annotations

from chiplog.manifest import JournalEntry, Manifest, RedactionState


def _entry(**over: object) -> JournalEntry:
    base = dict(
        chain_id="c1",
        genesis_hash="g1",
        first_record_id="r1",
        head_hash="h1",
        last_record_id="r1",
        record_count=1,
        file="audit-2026-07-17.jsonl",
        file_sha256="s1",
        file_record_count=1,
        file_first_record_id="r1",
        redaction_disabled=False,
    )
    base.update(over)
    return JournalEntry(**base)  # type: ignore[arg-type]


def test_apply_sets_chain_and_file_state() -> None:
    m = Manifest()
    m.apply_journal_entry(_entry())
    assert m.chains["c1"].head_hash == "h1"
    assert m.chains["c1"].genesis_hash == "g1"
    assert m.chains["c1"].record_count == 1
    assert m.files["audit-2026-07-17.jsonl"].sha256 == "s1"
    assert m.files["audit-2026-07-17.jsonl"].record_count == 1


def test_apply_is_idempotent() -> None:
    m = Manifest()
    e = _entry(head_hash="h2", record_count=2, file_record_count=2)
    m.apply_journal_entry(e)
    m.apply_journal_entry(e)
    assert m.chains["c1"].record_count == 2, "counts must be stated, never incremented"
    assert m.files["audit-2026-07-17.jsonl"].record_count == 2


def test_replaying_an_older_line_after_a_newer_one_cannot_unlatch_redaction() -> None:
    m = Manifest()
    m.apply_journal_entry(_entry(redaction_disabled=True))
    m.apply_journal_entry(_entry(redaction_disabled=False))
    assert m.redaction_state is RedactionState.DISABLED


def test_roundtrips_through_json() -> None:
    e = _entry()
    assert JournalEntry.from_dict(e.to_dict()) == e
