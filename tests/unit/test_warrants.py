"""Unit tests for Actentra cryptographic warrants (Phase 4 capability tokens)."""

from __future__ import annotations

from pathlib import Path

import pytest

from actentra import ActionBlockedError, Boundary
from actentra_core.checkpoints import generate_ed25519_keypair
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_core.verdict import Verdict
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
    ok_exp, msg_exp = verify_warrant(warrant, pub, current_time_iso="2035-01-01T00:00:00Z")
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


def test_boundary_warrant_enforcement(tmp_path: Path) -> None:
    priv, pub = generate_ed25519_keypair()
    _, other_pub = generate_ed25519_keypair()

    db_path = tmp_path / "warrant_receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(
        """
version: 1
policy_id: test-warrants
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-fs
    match: { tool: fs.read, verb: read }
    verdict: allow
  - id: allow-shell
    match: { tool: shell.exec, verb: exec }
    verdict: allow
"""
    )
    registry = WarrantRegistry()
    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        agent_id="agent-007",
        warrant_public_key=pub,
        warrant_registry=registry,
    )

    # 1. Issue valid warrant with max_uses=2 for agent-007
    warrant = issue_warrant(
        holder="agent-007",
        allowed_tools=["fs.read"],
        allowed_resources=["path:C:/data/**"],
        privkey_pem=priv,
        issuer_id="security-lead",
        ttl_seconds=300.0,
        max_uses=2,
    )

    # 1a. Successful execution with valid warrant
    res1 = boundary.execute(
        tool="fs.read",
        verb="read",
        resource="path:C:/data/report.txt",
        warrant=warrant,
        fn=lambda env, dec: "content-1",
    )
    assert res1 == "content-1"
    assert registry.remaining_uses(warrant) == 1

    # Verify receipt provenance includes warrant
    records = store.iter_records()
    assert len(records) == 2  # decision + outcome
    envelope = store.get_envelope(records[0].crossing_id)
    assert any(p["source"] == f"warrant:{warrant.warrant_id}" for p in envelope["provenance"])

    # 1b. Second execution with valid warrant succeeds
    res2 = boundary.execute(
        tool="fs.read",
        verb="read",
        resource="path:C:/data/other.txt",
        warrant=warrant.to_dict(),  # Pass as dict to test dict deserialization
        fn=lambda env, dec: "content-2",
    )
    assert res2 == "content-2"
    assert registry.remaining_uses(warrant) == 0

    # 1c. Third execution exceeds max_uses -> fails closed
    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.execute(
            tool="fs.read",
            verb="read",
            resource="path:C:/data/third.txt",
            warrant=warrant,
            fn=lambda env, dec: "content-3",
        )
    assert exc_info.value.decision.rule_id == "warrant:exhausted"
    assert "max uses" in exc_info.value.decision.reason

    # 2. Scope denied: tool not in warrant (even if allowed by policy)
    scope_warrant = issue_warrant(
        holder="agent-007",
        allowed_tools=["fs.read"],
        allowed_resources=["path:C:/data/**"],
        privkey_pem=priv,
        issuer_id="security-lead",
        ttl_seconds=300.0,
    )
    with pytest.raises(ActionBlockedError) as exc_info2:
        boundary.execute(
            tool="shell.exec",
            verb="exec",
            resource="proc:cmd.exe",
            warrant=scope_warrant,
            fn=lambda env, dec: "shell-run",
        )
    assert exc_info2.value.decision.rule_id == "warrant:scope-denied"
    assert "not authorized by warrant" in exc_info2.value.decision.reason

    # 3. Holder mismatch: warrant issued for different agent
    foreign_warrant = issue_warrant(
        holder="agent-999",
        allowed_tools=["fs.read"],
        allowed_resources=["path:C:/data/**"],
        privkey_pem=priv,
        issuer_id="security-lead",
        ttl_seconds=300.0,
    )
    with pytest.raises(ActionBlockedError) as exc_info3:
        boundary.execute(
            tool="fs.read",
            verb="read",
            resource="path:C:/data/report.txt",
            warrant=foreign_warrant,
            fn=lambda env, dec: "secret",
        )
    assert exc_info3.value.decision.rule_id == "warrant:invalid"
    assert "holder mismatch" in exc_info3.value.decision.reason

    # 4. Expired warrant
    expired_warrant = issue_warrant(
        holder="agent-007",
        allowed_tools=["fs.read"],
        allowed_resources=["path:C:/data/**"],
        privkey_pem=priv,
        issuer_id="security-lead",
        ttl_seconds=-10.0,  # Already expired
    )
    with pytest.raises(ActionBlockedError) as exc_info4:
        boundary.execute(
            tool="fs.read",
            verb="read",
            resource="path:C:/data/report.txt",
            warrant=expired_warrant,
            fn=lambda env, dec: "expired",
        )
    assert exc_info4.value.decision.rule_id == "warrant:invalid"
    assert "expired" in exc_info4.value.decision.reason

    # 5. Boundary configured with different public key (signature verification fails)
    boundary_wrong_key = Boundary(
        policy=policy,
        receipt_store=store,
        agent_id="agent-007",
        warrant_public_key=other_pub,
    )
    with pytest.raises(ActionBlockedError) as exc_info5:
        boundary_wrong_key.execute(
            tool="fs.read",
            verb="read",
            resource="path:C:/data/report.txt",
            warrant=scope_warrant,
            fn=lambda env, dec: "bad-sig",
        )
    assert exc_info5.value.decision.rule_id == "warrant:invalid"
    assert "signature invalid" in exc_info5.value.decision.reason


def test_boundary_warrant_dry_run(tmp_path: Path) -> None:
    priv, pub = generate_ed25519_keypair()
    db_path = tmp_path / "warrant_dryrun.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(
        """
version: 1
policy_id: test-warrants-dryrun
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-fs
    match: { tool: fs.read, verb: read }
    verdict: allow
"""
    )
    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        agent_id="agent-dry",
        warrant_public_key=pub,
    )

    warrant = issue_warrant(
        holder="agent-dry",
        allowed_tools=["fs.read"],
        allowed_resources=["path:C:/data/**"],
        privkey_pem=priv,
        issuer_id="sec-lead",
    )

    # Valid warrant dry-run
    dec = boundary.dry_run(
        tool="fs.read",
        verb="read",
        resource="path:C:/data/file.txt",
        warrant=warrant,
    )
    assert dec.verdict == Verdict.ALLOW
    assert dec.rule_id == "allow-fs"

    # Unauthorized resource in dry-run
    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.dry_run(
            tool="fs.read",
            verb="read",
            resource="path:C:/other/file.txt",
            warrant=warrant,
        )
    assert exc_info.value.decision.rule_id == "warrant:scope-denied"
