"""Unit tests for Actentra cryptographic warrants (Phase 4 capability tokens)."""

from __future__ import annotations

import pytest

from actentra_core.checkpoints import generate_ed25519_keypair
from actentra_core.warrants import (
    Warrant,
    WarrantError,
    WarrantRegistry,
    is_action_permitted_by_warrant,
    issue_warrant,
    verify_warrant,
)


def test_warrant_issue_verify_and_scope() -> None:
    priv1, pub1 = generate_ed25519_keypair()
    _, pub2 = generate_ed25519_keypair()

    # Issue a scoped warrant for agent 'analyst-1'
    warrant = issue_warrant(
        holder="analyst-1",
        allowed_tools=["fs.read", "sqlite.query"],
        allowed_resources=["path:C:/data/**", "sqlite:metrics.db"],
        privkey_pem=priv1,
        issuer_id="actentra-root",
        ttl_seconds=3600.0,
        max_uses=5,
    )
    assert warrant.warrant_id.startswith("war_")
    assert warrant.holder == "analyst-1"
    assert warrant.issuer == "actentra-root"
    assert warrant.max_uses == 5

    # 1. Verification with matching public key succeeds
    ok, msg = verify_warrant(warrant, pub1, expected_holder="analyst-1")
    assert ok is True
    assert "Warrant valid" in msg

    # 2. Verification with wrong public key fails
    ok_wrong, msg_wrong = verify_warrant(warrant, pub2)
    assert ok_wrong is False
    assert "signature invalid" in msg_wrong.lower()

    # 3. Verification with wrong holder fails
    ok_holder, msg_holder = verify_warrant(warrant, pub1, expected_holder="other-agent")
    assert ok_holder is False
    assert "holder mismatch" in msg_holder.lower()

    # 4. Scope authorization checks
    # Allowed tool + allowed resource
    assert is_action_permitted_by_warrant(warrant, "fs.read", "path:C:/data/report.csv") is True
    assert is_action_permitted_by_warrant(warrant, "sqlite.query", "sqlite:metrics.db") is True

    # Unauthorized tool (e.g. fs.write, shell.exec)
    assert is_action_permitted_by_warrant(warrant, "fs.write", "path:C:/data/report.csv") is False
    assert is_action_permitted_by_warrant(warrant, "shell.exec", "proc:cmd.exe") is False

    # Unauthorized resource (e.g. outside C:/data/**)
    assert is_action_permitted_by_warrant(warrant, "fs.read", "path:C:/windows/cmd.exe") is False
    assert is_action_permitted_by_warrant(warrant, "sqlite.query", "sqlite:production.db") is False


def test_warrant_expiration() -> None:
    priv, pub = generate_ed25519_keypair()
    warrant = issue_warrant(
        holder="worker",
        allowed_tools=["calc"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        ttl_seconds=10.0,
    )

    # Valid immediately
    ok, _ = verify_warrant(warrant, pub)
    assert ok is True

    # Expired when checked against a future timestamp
    ok_exp, msg_exp = verify_warrant(
        warrant, pub, current_time_iso="2035-01-01T00:00:00Z"
    )
    assert ok_exp is False
    assert "expired" in msg_exp.lower()


def test_warrant_serialization_roundtrip() -> None:
    priv, _ = generate_ed25519_keypair()
    orig = issue_warrant(
        holder="subagent",
        allowed_tools=["http.get"],
        allowed_resources=["https://api.github.com/**"],
        privkey_pem=priv,
        issuer_id="orchestrator",
        ttl_seconds=600.0,
        max_uses=2,
    )
    d = orig.to_dict()
    reconstituted = Warrant.from_dict(d)
    assert reconstituted == orig


def test_warrant_registry_use_tracking() -> None:
    priv, _ = generate_ed25519_keypair()
    warrant = issue_warrant(
        holder="bot",
        allowed_tools=["calc"],
        allowed_resources=["tool:calc"],
        privkey_pem=priv,
        issuer_id="root",
        max_uses=2,
    )
    registry = WarrantRegistry()

    assert registry.remaining_uses(warrant) == 2
    registry.record_use(warrant)
    assert registry.remaining_uses(warrant) == 1
    registry.record_use(warrant)
    assert registry.remaining_uses(warrant) == 0

    # Third use exceeds max_uses -> raises WarrantError
    with pytest.raises(WarrantError, match="max uses"):
        registry.record_use(warrant)
