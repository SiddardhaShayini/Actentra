"""Unit tests for the local DPAPI SecretsBroker and Invariant I7 redaction."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from actentra import Boundary, SecretsBroker, SecretsError, dpapi_protect, dpapi_unprotect
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore, verify_log


def test_dpapi_roundtrip_and_persistent_store(tmp_path: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("Windows DPAPI only runs on Windows")

    cipher = dpapi_protect(b"super-secret-db-password")
    assert cipher != b"super-secret-db-password"
    assert dpapi_unprotect(cipher) == b"super-secret-db-password"

    store_file = tmp_path / "secrets.dpapi.json"
    broker = SecretsBroker(dpapi_store_path=store_file)
    broker.set_secret("API_TOKEN", "tok_live_987654321")

    raw_disk = store_file.read_text(encoding="utf-8")
    assert "tok_live_987654321" not in raw_disk

    reloaded = SecretsBroker(dpapi_store_path=store_file)
    assert reloaded.get_secret("API_TOKEN") == "tok_live_987654321"
    assert reloaded.list_names() == ("API_TOKEN",)


def test_secrets_broker_redact_and_boundary_i7(tmp_path: Path) -> None:
    broker = SecretsBroker({"DB_PASS": "s3cr3t_val"})
    assert broker.redact("failed connecting with s3cr3t_val") == "failed connecting with [REDACTED]"

    with pytest.raises(SecretsError):
        broker.get_secret("MISSING_KEY")

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
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    boundary = Boundary(policy=policy, receipt_store=store, secrets_broker=broker)

    def inject_and_call(env: object, _dec: object) -> str:
        # Executor retrieves secret at runtime; envelope never holds it.
        secret = broker.get_secret("DB_PASS")
        return f"authenticated:{len(secret)}"

    res = boundary.execute(
        tool="fs.read",
        verb="read",
        resource=r"path:C:\work\a.txt",
        fn=inject_and_call,
    )
    assert res == "authenticated:10"
    assert "s3cr3t_val" not in db_path.read_bytes().decode("latin-1")
    assert verify_log(db_path).ok is True
