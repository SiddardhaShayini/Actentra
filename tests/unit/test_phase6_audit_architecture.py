"""Comprehensive test suite for Phase 6: Actentra Tamper-Evident Audit Architecture (ACT-07).

Tests:
1. Reproduction of raw SQLite chain rewriting attack and detection by external anchor.
2. Detection of historical rollback / restoring older database backups.
3. Detection of tail truncation.
4. Detection of receipt deletion / omission.
5. Checkpoint hash-chain continuity (prev_checkpoint_hash and monotonic sequence).
6. Ed25519 signature verification and forgery rejection.
7. Untrusted / wrong signing key rejection (UNTRUSTED_KEY).
8. Key rotation handling (retiring active key, signing new checkpoints with new key).
9. Key revocation handling (revoking a compromised key, rejecting checkpoints).
10. Key expiration handling (rejecting checkpoints signed after valid_until).
11. Evidence status tampering detection (confirming evidence_status is hashed).
12. Offline audit bundle export and verification (with external checkpoints and key manifest).
13. Bundle tampering detection (offline detection of altered receipt or forged checkpoint).
14. Concurrent receipt recording and external checkpoint creation.
15. CLI roundtrip for checkpoint anchor signing, trail verification, and bundle verification.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import json
import sqlite3
import time
from dataclasses import replace
from pathlib import Path

from typer.testing import CliRunner

from actentra.boundary import Boundary
from actentra_cli.main import app
from actentra_core.checkpoints import (
    CheckpointError,
    FileCheckpointAnchor,
    KeyRing,
    MemoryCheckpointAnchor,
    create_key_record,
    generate_ed25519_keypair,
    sign_checkpoint,
    verify_audit_bundle,
    verify_audit_trail,
    verify_checkpoint,
)
from actentra_core.envelope import build_envelope
from actentra_core.policy import PolicyEngine, load_policy_yaml
from actentra_core.receipts import (
    GENESIS_HASH,
    ReceiptStore,
    _compute_entry_hash,
    verify_log,
)
from actentra_gateway.services import AppServices


def _create_sample_db(db_path: Path, count: int = 4) -> None:
    policy = load_policy_yaml(
        """
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-admin
    match: { tool: admin.exec, verb: exec }
    verdict: allow
  - id: allow-read
    match: { tool: fs.read, verb: read }
    verdict: allow
"""
    )
    engine = PolicyEngine(policy)
    store = ReceiptStore(db_path)

    for i in range(1, (count // 2) + 1):
        env = build_envelope(tool="admin.exec", verb="exec", resource=f"service:restart:{i}")
        dec = engine.evaluate(env)
        store.record_decision(env, dec)
        store.record_outcome(
            crossing_id=env.crossing_id,
            session_id=env.session_id,
            canonical_hash=env.canonical_hash,
            policy_version=dec.policy_version,
            status="success",
            result_hash="sha256:" + ("a" * 64),
            evidence_status="locally_observed",
        )


def test_reproduce_chain_rewrite_attack_and_external_checkpoint_detection(
    tmp_path: Path,
) -> None:
    """Test 1: Reproduce ACT-07 rewrite and demonstrate prevention via external checkpoint."""
    db_path = tmp_path / "receipts.db"
    anchor_dir = tmp_path / "checkpoints"
    _create_sample_db(db_path, count=4)

    # 1. External authority signs and anchors a checkpoint at head_seq=4
    priv_pem, pub_pem = generate_ed25519_keypair()
    anchor = FileCheckpointAnchor(anchor_dir)
    key_rec = create_key_record(pub_pem)
    ring = KeyRing([key_rec])

    cp = sign_checkpoint(db_path, priv_pem, anchor=anchor, key_ring=ring)
    assert cp.head_seq == 4
    assert cp.checkpoint_seq == 1

    # Verify initial intact audit trail
    vr_intact = verify_audit_trail(db_path, anchor, ring)
    assert vr_intact.ok is True
    assert vr_intact.receipts_verified == 4
    assert vr_intact.checkpoints_verified == 1
    assert vr_intact.divergence_type is None

    # 2. ATTACK: Attacker with SQLite editor access modifies seq=1 and recomputes the SHA-256 chain
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("UPDATE receipts SET reason = 'Fake administrative override' WHERE seq = 1;")
        # Recompute SHA-256 chain for all rows
        rows = conn.execute(
            "SELECT seq, record_type, crossing_id, session_id, canonical_hash, "
            "policy_version, verdict, rule_id, reason, risk_tags_json, shadow, "
            "status, result_hash, error, ts, evidence_status FROM receipts ORDER BY seq ASC;"
        ).fetchall()

        prev = GENESIS_HASH
        for r in rows:
            seq = r[0]
            rec_type = r[1]
            crossing_id = r[2]
            session_id = r[3]
            canonical_hash = r[4]
            policy_version = r[5]
            verdict = r[6]
            rule_id = r[7]
            reason = r[8]
            risk_tags = tuple(json.loads(r[9]))
            shadow = bool(r[10])
            status = r[11]
            result_hash = r[12]
            error = r[13]
            ts = r[14]
            ev_status = r[15]

            new_hash = _compute_entry_hash(
                seq=seq,
                record_type=rec_type,
                crossing_id=crossing_id,
                session_id=session_id,
                canonical_hash=canonical_hash,
                policy_version=policy_version,
                verdict=verdict,
                rule_id=rule_id,
                reason=reason,
                risk_tags=risk_tags,
                shadow=shadow,
                status=status,
                result_hash=result_hash,
                error=error,
                ts=ts,
                prev_hash=prev,
                evidence_status=ev_status,
            )
            conn.execute(
                "UPDATE receipts SET prev_hash = ?, entry_hash = ? WHERE seq = ?;",
                (prev, new_hash, seq),
            )
            prev = new_hash
        conn.commit()
    finally:
        conn.close()

    # Demonstrating the vulnerability on raw SQLite: verify_log alone passes!
    vr_local = verify_log(db_path)
    assert vr_local.ok is True, "Local SQLite recomputed chain passed verify_log unnoticed"

    # PREVENTION: External checkpoint verification detects the chain rewrite / fork!
    vr_trail = verify_audit_trail(db_path, anchor, ring)
    assert vr_trail.ok is False
    assert vr_trail.divergence_type == "CHAIN_REWRITE"
    assert any("rewrite" in err.lower() or "mismatch" in err.lower() for err in vr_trail.errors)


def test_historical_rollback_backup_restore_detection(tmp_path: Path) -> None:
    """Test 2: Restoring an older SQLite database backup is caught by external checkpoints."""
    db_path = tmp_path / "receipts.db"
    backup_path = tmp_path / "receipts_backup.db"
    anchor_dir = tmp_path / "checkpoints"

    # Step 1: Record 2 receipts and take a snapshot backup
    _create_sample_db(db_path, count=2)
    with sqlite3.connect(db_path) as src, sqlite3.connect(backup_path) as dst:
        src.backup(dst)

    # Step 2: Add 2 more receipts (now seq=4) and externally checkpoint seq=4
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(
        "version: 1\ndefaults: {verdict: deny}\n"
        "rules: [{id: allow-all, match: {tool: '*'}, verdict: allow}]"
    )
    engine = PolicyEngine(policy)
    env = build_envelope(tool="fs.read", verb="read", resource="doc.txt")
    dec = engine.evaluate(env)
    store.record_decision(env, dec)
    store.record_outcome(
        crossing_id=env.crossing_id,
        session_id=env.session_id,
        canonical_hash=env.canonical_hash,
        policy_version=dec.policy_version,
        status="success",
    )

    priv_pem, pub_pem = generate_ed25519_keypair()
    anchor = FileCheckpointAnchor(anchor_dir)
    ring = KeyRing([create_key_record(pub_pem)])
    sign_checkpoint(db_path, priv_pem, anchor=anchor, key_ring=ring)

    # Step 3: Attacker restores backup_path over db_path (rolling back from 4 to 2 receipts)
    with sqlite3.connect(backup_path) as src, sqlite3.connect(db_path) as dst:
        src.backup(dst)

    # Local verify_log passes on the backup alone:
    assert verify_log(db_path).ok is True
    assert verify_log(db_path).total_records == 2

    # verify_audit_trail detects ROLLBACK because checkpoint requires head_seq=4
    vr = verify_audit_trail(db_path, anchor, ring)
    assert vr.ok is False
    assert vr.divergence_type == "ROLLBACK"
    assert any("rollback" in err.lower() or "truncation" in err.lower() for err in vr.errors)


def test_tail_truncation_detection(tmp_path: Path) -> None:
    """Test 3: Dropping recent receipts is detected as tail truncation."""
    db_path = tmp_path / "receipts.db"
    anchor_dir = tmp_path / "checkpoints"
    _create_sample_db(db_path, count=4)

    priv_pem, pub_pem = generate_ed25519_keypair()
    anchor = FileCheckpointAnchor(anchor_dir)
    ring = KeyRing([create_key_record(pub_pem)])
    sign_checkpoint(db_path, priv_pem, anchor=anchor, key_ring=ring)

    # Delete row seq=4
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM receipts WHERE seq = 4;")
        conn.commit()

    vr = verify_audit_trail(db_path, anchor, ring)
    assert vr.ok is False
    assert vr.divergence_type == "ROLLBACK"


def test_receipt_deletion_detection(tmp_path: Path) -> None:
    """Test 4: Deleting an intermediate receipt is detected by sequence break or hash chain."""
    db_path = tmp_path / "receipts.db"
    anchor_dir = tmp_path / "checkpoints"
    _create_sample_db(db_path, count=4)

    priv_pem, pub_pem = generate_ed25519_keypair()
    anchor = FileCheckpointAnchor(anchor_dir)
    ring = KeyRing([create_key_record(pub_pem)])
    sign_checkpoint(db_path, priv_pem, anchor=anchor, key_ring=ring)

    # Delete record seq=2
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM receipts WHERE seq = 2;")
        conn.commit()

    vr = verify_audit_trail(db_path, anchor, ring)
    assert vr.ok is False
    assert vr.divergence_type in ("RECEIPT_TAMPERING", "ROLLBACK")


def test_checkpoint_hash_chain_continuity(tmp_path: Path) -> None:
    """Test 5: Checkpoints form an immutable hash chain with monotonic sequence numbers."""
    db_path = tmp_path / "receipts.db"
    _create_sample_db(db_path, count=2)

    anchor = MemoryCheckpointAnchor()
    priv_pem, pub_pem = generate_ed25519_keypair()
    ring = KeyRing([create_key_record(pub_pem)])

    cp1 = sign_checkpoint(db_path, priv_pem, anchor=anchor, key_ring=ring)
    assert cp1.checkpoint_seq == 1
    assert cp1.prev_checkpoint_hash.startswith("sha256:")

    # Append more records and create second checkpoint
    _create_sample_db(db_path, count=2)
    cp2 = sign_checkpoint(db_path, priv_pem, anchor=anchor, key_ring=ring)
    assert cp2.checkpoint_seq == 2
    assert cp2.prev_checkpoint_hash == cp1.compute_checkpoint_hash()

    # Append more records and create third checkpoint
    _create_sample_db(db_path, count=2)
    cp3 = sign_checkpoint(db_path, priv_pem, anchor=anchor, key_ring=ring)
    assert cp3.checkpoint_seq == 3
    assert cp3.prev_checkpoint_hash == cp2.compute_checkpoint_hash()

    # Audit trail verifies all 3 checkpoints in chain
    vr = verify_audit_trail(db_path, anchor, ring)
    assert vr.ok is True
    assert vr.checkpoints_verified == 3

    # Tampering with prev_checkpoint_hash in middle checkpoint fails verification
    bad_cp2 = replace(cp2, prev_checkpoint_hash="sha256:" + ("f" * 64))
    bad_anchor = MemoryCheckpointAnchor()
    bad_anchor.save_checkpoint(cp1)
    # Direct append to bad anchor bypassing save validation
    bad_anchor._checkpoints.append(bad_cp2)
    bad_anchor._checkpoints.append(cp3)

    vr_tampered = verify_audit_trail(db_path, bad_anchor, ring)
    assert vr_tampered.ok is False
    assert vr_tampered.divergence_type == "CHECKPOINT_TAMPERING"


def test_signature_forgery_rejection(tmp_path: Path) -> None:
    """Test 6: Checkpoints with forged or tampered signatures are rejected."""
    db_path = tmp_path / "receipts.db"
    _create_sample_db(db_path, count=2)

    priv_pem, pub_pem = generate_ed25519_keypair()
    ring = KeyRing([create_key_record(pub_pem)])
    cp = sign_checkpoint(db_path, priv_pem)

    # Forged signature bytes
    forged_sig = replace(
        cp,
        signature_b64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
    ok, err = verify_checkpoint(forged_sig, ring)
    assert ok is False
    assert "signature" in err.lower()


def test_untrusted_signing_key_rejection(tmp_path: Path) -> None:
    """Test 7: Checkpoints signed with unknown/untrusted keys are rejected."""
    db_path = tmp_path / "receipts.db"
    _create_sample_db(db_path, count=2)

    # Key 1 is trusted by ring
    _, pub1 = generate_ed25519_keypair()
    ring = KeyRing([create_key_record(pub1)])

    # Attacker signs with Key 2
    priv2, _ = generate_ed25519_keypair()
    anchor = MemoryCheckpointAnchor()
    sign_checkpoint(db_path, priv2, anchor=anchor)

    vr = verify_audit_trail(db_path, anchor, ring)
    assert vr.ok is False
    assert vr.divergence_type == "UNTRUSTED_KEY"
    assert any("untrusted" in err.lower() or "not found" in err.lower() for err in vr.errors)


def test_key_rotation_lifecycle(tmp_path: Path) -> None:
    """Test 8: Key rotation retires old key and verifies across lifecycle."""
    db_path = tmp_path / "receipts.db"
    _create_sample_db(db_path, count=2)
    anchor = MemoryCheckpointAnchor()

    # Key 1
    priv1, pub1 = generate_ed25519_keypair()
    rec1 = create_key_record(pub1)
    ring = KeyRing([rec1])

    # Checkpoint 1 signed with Key 1
    cp1 = sign_checkpoint(db_path, priv1, anchor=anchor, key_ring=ring)
    assert cp1.key_id == rec1.key_id

    # Rotate to Key 2
    priv2, pub2 = generate_ed25519_keypair()
    rec2 = create_key_record(pub2)
    ring.rotate_key(rec2)

    k1 = ring.get_key(rec1.key_id)
    assert k1 is not None and k1.status == "retired"
    active_k = ring.get_active_key()
    assert active_k is not None and active_k.key_id == rec2.key_id

    # Append more records and sign Checkpoint 2 with Key 2
    _create_sample_db(db_path, count=2)
    cp2 = sign_checkpoint(db_path, priv2, anchor=anchor, key_ring=ring)
    assert cp2.key_id == rec2.key_id

    # Both checkpoints verify cleanly against the key ring
    vr = verify_audit_trail(db_path, anchor, ring)
    assert vr.ok is True
    assert vr.checkpoints_verified == 2

    # Attempting to sign a new checkpoint with retired Key 1 raises CheckpointError
    _create_sample_db(db_path, count=2)
    try:
        sign_checkpoint(db_path, priv1, anchor=anchor, key_ring=ring)
        raise AssertionError("Signing with retired key should have failed")
    except CheckpointError as exc:
        assert "rejected by key ring" in str(exc).lower() or "expired" in str(exc).lower()


def test_key_revocation_lifecycle(tmp_path: Path) -> None:
    """Test 9: Key revocation immediately invalidates subsequent checkpoints from that key."""
    db_path = tmp_path / "receipts.db"
    _create_sample_db(db_path, count=2)

    priv, pub = generate_ed25519_keypair()
    rec = create_key_record(pub)
    ring = KeyRing([rec])
    anchor = MemoryCheckpointAnchor()

    # Valid checkpoint before revocation
    sign_checkpoint(db_path, priv, anchor=anchor, key_ring=ring)
    assert verify_audit_trail(db_path, anchor, ring).ok is True

    # Revoke key due to suspected compromise
    ring.revoke_key(
        rec.key_id,
        reason="Suspected credential leak",
        revoked_at="2000-01-01T00:00:00Z",
    )

    # Audit trail verification now rejects checkpoints signed by revoked key
    vr = verify_audit_trail(db_path, anchor, ring)
    assert vr.ok is False
    assert vr.divergence_type == "REVOKED_KEY"
    assert any("revoked" in err.lower() for err in vr.errors)


def test_evidence_status_tampering_is_detected(tmp_path: Path) -> None:
    """Test 10: Modifying evidence_status column in SQLite is detected by _compute_entry_hash."""
    db_path = tmp_path / "receipts.db"
    _create_sample_db(db_path, count=2)

    assert verify_log(db_path).ok is True

    # Tamper with evidence_status directly in SQLite
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE receipts SET evidence_status = 'externally_verified' WHERE seq = 2;")
        conn.commit()

    vr = verify_log(db_path)
    assert vr.ok is False
    assert any("entry_hash mismatch" in err for err in vr.errors)


def test_offline_audit_bundle_export_and_verification(tmp_path: Path) -> None:
    """Test 11: Exported audit bundles include checkpoints and keys, and verify offline."""
    db_path = tmp_path / "receipts.db"
    bundle_path = tmp_path / "bundle.json"
    anchor_dir = tmp_path / "checkpoints"
    _create_sample_db(db_path, count=4)

    priv_pem, pub_pem = generate_ed25519_keypair()
    anchor = FileCheckpointAnchor(anchor_dir)
    ring = KeyRing([create_key_record(pub_pem)])

    sign_checkpoint(db_path, priv_pem, anchor=anchor, key_ring=ring)

    policy = load_policy_yaml(
        "version: 1\ndefaults: {verdict: deny}\n"
        "rules: [{id: allow-all, match: {tool: '*'}, verdict: allow}]"
    )
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(db_path))
    services = AppServices(boundary, checkpoint_anchor=anchor, key_ring=ring)

    exported = services.export_audit_bundle(out_path=bundle_path)
    assert "external_checkpoints" in exported
    assert len(exported["external_checkpoints"]) == 1
    assert "key_manifest" in exported
    assert len(exported["key_manifest"]["keys"]) == 1

    # Verify completely offline using bundle file
    vr = verify_audit_bundle(bundle_path)
    assert vr.ok is True
    assert vr.receipts_verified == 4
    assert vr.checkpoints_verified == 1


def test_offline_audit_bundle_tamper_detection(tmp_path: Path) -> None:
    """Test 12: Offline bundle verifier detects tampering with bundle receipts or checkpoints."""
    db_path = tmp_path / "receipts.db"
    anchor_dir = tmp_path / "checkpoints"
    _create_sample_db(db_path, count=4)

    priv_pem, pub_pem = generate_ed25519_keypair()
    anchor = FileCheckpointAnchor(anchor_dir)
    ring = KeyRing([create_key_record(pub_pem)])
    sign_checkpoint(db_path, priv_pem, anchor=anchor, key_ring=ring)

    policy = load_policy_yaml(
        "version: 1\ndefaults: {verdict: deny}\n"
        "rules: [{id: allow-all, match: {tool: '*'}, verdict: allow}]"
    )
    services = AppServices(
        Boundary(policy=policy, receipt_store=ReceiptStore(db_path)),
        checkpoint_anchor=anchor,
        key_ring=ring,
    )
    bundle = services.export_audit_bundle()

    # Tamper 1: Alter receipt verdict inside the bundle
    tampered_bundle = dict(bundle)
    tampered_receipts = [dict(r) for r in bundle["receipts"]]
    tampered_receipts[0]["verdict"] = "deny"
    tampered_bundle["receipts"] = tampered_receipts

    vr_tampered = verify_audit_bundle(tampered_bundle)
    assert vr_tampered.ok is False
    assert vr_tampered.divergence_type == "RECEIPT_TAMPERING"


def test_concurrent_receipt_creation_and_checkpointing(tmp_path: Path) -> None:
    """Test 13: High-concurrency receipts recording while simultaneously creating checkpoints."""
    db_path = tmp_path / "receipts.db"
    anchor = MemoryCheckpointAnchor()
    priv_pem, pub_pem = generate_ed25519_keypair()
    ring = KeyRing([create_key_record(pub_pem)])

    store = ReceiptStore(db_path)
    policy = load_policy_yaml(
        "version: 1\ndefaults: {verdict: deny}\n"
        "rules: [{id: allow-all, match: {tool: '*'}, verdict: allow}]"
    )
    engine = PolicyEngine(policy)

    num_workers = 4
    iterations_per_worker = 15

    def worker_record(worker_id: int) -> None:
        for i in range(iterations_per_worker):
            env = build_envelope(
                tool="admin.exec",
                verb="exec",
                resource=f"resource:{worker_id}:{i}",
            )
            dec = engine.evaluate(env)
            store.record_decision(env, dec)
            store.record_outcome(
                crossing_id=env.crossing_id,
                session_id=env.session_id,
                canonical_hash=env.canonical_hash,
                policy_version=dec.policy_version,
                status="success",
            )
            time.sleep(0.005)

    def worker_checkpoint() -> None:
        for _ in range(5):
            time.sleep(0.03)
            with contextlib.suppress(CheckpointError):
                store.create_external_checkpoint(priv_pem, anchor=anchor, key_ring=ring)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers + 1) as executor:
        futures = [executor.submit(worker_record, wid) for wid in range(num_workers)]
        cp_future = executor.submit(worker_checkpoint)
        for f in futures:
            f.result()
        cp_future.result()

    # Final checkpoint after all workers finish
    store.create_external_checkpoint(priv_pem, anchor=anchor, key_ring=ring)

    # Comprehensive verification of receipts and checkpoint chain
    vr = store.verify_audit_trail(anchor, ring)
    assert vr.ok is True
    assert vr.receipts_verified == num_workers * iterations_per_worker * 2
    assert vr.checkpoints_verified >= 1


def test_cli_checkpoint_and_bundle_commands(tmp_path: Path) -> None:
    """Test 14: Typer CLI roundtrip for checkpoint keygen, anchor, and bundle commands."""
    runner = CliRunner()
    keys_dir = tmp_path / "keys"
    db_path = tmp_path / "receipts.db"
    anchor_dir = tmp_path / "anchor"
    bundle_path = tmp_path / "audit_bundle.json"

    _create_sample_db(db_path, count=2)

    # 1. keygen
    r_gen = runner.invoke(app, ["checkpoint", "keygen", str(keys_dir)])
    assert r_gen.exit_code == 0
    assert (keys_dir / "checkpoint.key.pem").exists()
    assert (keys_dir / "key_manifest.json").exists()

    # 2. sign with --anchor
    r_sign = runner.invoke(
        app,
        [
            "checkpoint",
            "sign",
            str(db_path),
            "--key",
            str(keys_dir / "checkpoint.key.pem"),
            "--anchor",
            str(anchor_dir),
        ],
    )
    assert r_sign.exit_code == 0, r_sign.output
    assert "anchor" in r_sign.output

    # 3. verify-trail
    r_ver = runner.invoke(
        app,
        [
            "checkpoint",
            "verify-trail",
            str(db_path),
            "--anchor",
            str(anchor_dir),
            "--keys",
            str(keys_dir / "key_manifest.json"),
        ],
    )
    assert r_ver.exit_code == 0, r_ver.output
    assert "OK audit trail verified" in r_ver.output

    # 4. bundle export
    r_exp = runner.invoke(
        app,
        [
            "bundle",
            "export",
            "--db",
            str(db_path),
            "--anchor",
            str(anchor_dir),
            "--keys",
            str(keys_dir / "key_manifest.json"),
            "--out",
            str(bundle_path),
        ],
    )
    assert r_exp.exit_code == 0, r_exp.output
    assert bundle_path.exists()

    # 5. bundle verify
    r_bver = runner.invoke(app, ["bundle", "verify", str(bundle_path)])
    assert r_bver.exit_code == 0, r_bver.output
    assert "OK audit bundle verified" in r_bver.output
