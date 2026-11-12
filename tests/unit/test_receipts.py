"""Unit tests for hash-chained SQLite WAL receipts, recovery, and tamper detection."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import jsonschema

from actentra_core.envelope import build_envelope
from actentra_core.policy import PolicyStore, load_policy_yaml
from actentra_core.receipts import ReceiptStore, export_jsonl, verify_log

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_receipt_chain_verify_export_and_tamper_detection(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    jsonl_path = tmp_path / "receipts.jsonl"
    schema = json.loads((REPO_ROOT / "spec" / "receipt.v1.schema.json").read_text(encoding="utf-8"))

    policy = load_policy_yaml(
        """
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-read
    match: { tool: fs.read, verb: read, resource: "path:C:/work/**" }
    verdict: allow
"""
    )
    engine = PolicyStore(policy).engine
    store = ReceiptStore(db_path)

    env = build_envelope(tool="fs.read", verb="read", resource="path:C:/work/file.txt")
    dec = engine.evaluate(env)
    store.record_decision(env, dec)
    store.record_outcome(
        crossing_id=env.crossing_id,
        session_id=env.session_id,
        canonical_hash=env.canonical_hash,
        policy_version=dec.policy_version,
        status="success",
        result_hash="sha256:" + ("a" * 64),
    )

    vr = verify_log(db_path)
    assert vr.ok is True
    assert vr.total_records == 2

    exported = export_jsonl(db_path, jsonl_path)
    assert exported == 2
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        jsonschema.validate(instance=json.loads(line), schema=schema)

    # Tamper with record #1 in SQLite directly and ensure verify_log catches it.
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE receipts SET verdict = 'deny' WHERE seq = 1;")
        conn.commit()

    tampered = verify_log(db_path)
    assert tampered.ok is False
    assert any("entry_hash mismatch" in err for err in tampered.errors)


def test_recover_pending_outcomes_marks_interrupted_execution_unknown(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    policy = load_policy_yaml(
        """
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-write
    match: { tool: fs.write, verb: write }
    verdict: allow
"""
    )
    engine = PolicyStore(policy).engine
    store = ReceiptStore(db_path)

    env = build_envelope(tool="fs.write", verb="write", resource="path:C:/work/out.txt")
    dec = engine.evaluate(env)
    store.record_decision(env, dec)

    # Simulate crash recovery before outcome was written
    recovered = store.recover_pending_outcomes()
    assert len(recovered) == 1
    assert recovered[0].status == "unknown"
    assert verify_log(db_path).ok is True
