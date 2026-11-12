"""Unit and CLI tests for Ed25519 signed receipt checkpoints."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

from typer.testing import CliRunner

from actentra_cli.main import app
from actentra_core.checkpoints import (
    generate_ed25519_keypair,
    load_checkpoint,
    sign_checkpoint,
    verify_checkpoint,
    write_checkpoint,
)
from actentra_core.envelope import build_envelope
from actentra_core.policy import PolicyEngine, load_policy_yaml
from actentra_core.receipts import ReceiptStore


def test_ed25519_checkpoint_sign_verify_and_tamper_detection(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    cp_path = tmp_path / "cp.json"

    policy = load_policy_yaml(
        """
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-read
    match: { tool: fs.read, verb: read }
    verdict: allow
"""
    )
    store = ReceiptStore(db_path)
    engine = PolicyEngine(policy)
    env = build_envelope(tool="fs.read", verb="read", resource=r"path:C:\work\a.txt")
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
    cp = sign_checkpoint(db_path, priv_pem)
    write_checkpoint(cp, cp_path)
    loaded = load_checkpoint(cp_path)

    ok, msg = verify_checkpoint(loaded, pub_pem, db_path=db_path)
    assert ok is True, msg
    assert loaded.seq == 2

    # Additional appended records after checkpoint still verify against anchored seq=2
    env2 = build_envelope(tool="fs.read", verb="read", resource=r"path:C:\work\b.txt")
    store.record_decision(env2, engine.evaluate(env2))
    ok_after, _ = verify_checkpoint(loaded, pub_pem, db_path=db_path)
    assert ok_after is True

    # Tampered signature fails
    bad_sig = replace(loaded, seq=99)
    ok_sig, err_sig = verify_checkpoint(bad_sig, pub_pem)
    assert ok_sig is False
    assert "signature" in err_sig.lower()

    # Wrong key fails
    _, other_pub = generate_ed25519_keypair()
    ok_key, err_key = verify_checkpoint(loaded, other_pub)
    assert ok_key is False
    assert "key id" in err_key.lower()

    # Truncated/tampered DB fails
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DELETE FROM receipts WHERE seq >= 2;")
        conn.commit()
    finally:
        conn.close()

    ok_trunc, err_trunc = verify_checkpoint(loaded, pub_pem, db_path=db_path)
    assert ok_trunc is False
    assert "truncated" in err_trunc.lower()


def test_checkpoint_cli_roundtrip(tmp_path: Path) -> None:
    runner = CliRunner()
    keys_dir = tmp_path / "keys"
    db_path = tmp_path / "receipts.db"
    cp_path = tmp_path / "checkpoint.json"

    ReceiptStore(db_path)  # empty valid store (seq=0)

    r_gen = runner.invoke(app, ["checkpoint", "keygen", str(keys_dir)])
    assert r_gen.exit_code == 0, r_gen.output

    r_sign = runner.invoke(
        app,
        [
            "checkpoint",
            "sign",
            str(db_path),
            "--key",
            str(keys_dir / "checkpoint.key.pem"),
            "--out",
            str(cp_path),
        ],
    )
    assert r_sign.exit_code == 0, r_sign.output

    r_ver = runner.invoke(
        app,
        [
            "checkpoint",
            "verify",
            str(cp_path),
            "--pubkey",
            str(keys_dir / "checkpoint.pub.pem"),
            "--db",
            str(db_path),
        ],
    )
    assert r_ver.exit_code == 0, r_ver.output
    assert "OK checkpoint" in r_ver.output
