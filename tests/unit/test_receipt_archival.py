"""Unit tests for bounded streaming audit iteration, chunked export, and archival."""

from __future__ import annotations

import json
from pathlib import Path

from actentra_core.envelope import build_envelope
from actentra_core.receipts import ReceiptStore, export_jsonl, verify_log
from actentra_core.verdict import Decision, Verdict


def _populate_test_store(store: ReceiptStore, count: int) -> None:
    for i in range(count):
        env = build_envelope(
            tool="fs.read",
            verb="read",
            resource=f"path:C:/data/file_{i}.txt",
            session_id="test-session",
            agent_id="test-agent",
        )
        dec = Decision(
            verdict=Verdict.ALLOW,
            rule_id=f"rule-{i}",
            reason="testing",
            policy_version="1",
            canonical_hash=env.canonical_hash,
        )
        store.record_decision(env, dec)
        store.record_outcome(
            crossing_id=env.crossing_id,
            session_id=env.session_id,
            canonical_hash=env.canonical_hash,
            policy_version=dec.policy_version,
            status="success",
        )


def test_iter_records_stream_and_export(tmp_path: Path) -> None:
    db_path = tmp_path / "stream_test.db"
    store = ReceiptStore(db_path)
    _populate_test_store(store, 10)  # 10 decisions + 10 outcomes = 20 records

    # 1. Stream records in small chunks (chunk_size=3)
    streamed = list(store.iter_records_stream(chunk_size=3))
    assert len(streamed) == 20
    assert [r.seq for r in streamed] == list(range(1, 21))

    # 2. Reverse streaming
    rev_streamed = list(store.iter_records_stream(chunk_size=4, reverse=True))
    assert len(rev_streamed) == 20
    assert rev_streamed[0].seq == 20
    assert rev_streamed[-1].seq == 1

    # 3. Export to JSONL in bounded chunks
    out_jsonl = tmp_path / "receipts.jsonl"
    exported_count = export_jsonl(db_path, out_jsonl, chunk_size=5)
    assert exported_count == 20

    lines = out_jsonl.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 20
    for idx, line in enumerate(lines):
        data = json.loads(line)
        assert data["seq"] == idx + 1
        assert data["record_type"] in ("decision", "outcome")

    # 4. verify_log using bounded chunk_size
    vr = verify_log(db_path, verify_envelopes=True, chunk_size=4)
    assert vr.ok is True
    assert vr.total_records == 20
    assert len(vr.errors) == 0


def test_archive_records(tmp_path: Path) -> None:
    source_db = tmp_path / "source.db"
    archive_db = tmp_path / "archive.db"
    store = ReceiptStore(source_db)
    _populate_test_store(store, 10)  # 20 records (seq 1 to 20)

    # Archive records with seq < 11 (first 10 records: seq 1 to 10) without deleting from source
    archived_count = store.archive_records(before_seq=11, archive_db_path=archive_db)
    assert archived_count == 10

    # Archive database is self-contained and passes log verification with envelope checking!
    vr_arch = verify_log(archive_db, verify_envelopes=True)
    assert vr_arch.ok is True
    assert vr_arch.total_records == 10

    # Source still has all 20 records
    assert len(store.iter_records()) == 20

    # Now archive with delete_from_source=True
    archive_db2 = tmp_path / "archive2.db"
    deleted_archived = store.archive_records(
        before_seq=11,
        archive_db_path=archive_db2,
        delete_from_source=True,
    )
    assert deleted_archived == 10

    # Source now has remaining 10 records (seq 11 to 20)
    remaining = store.iter_records()
    assert len(remaining) == 10
    assert remaining[0].seq == 11
    assert remaining[-1].seq == 20
