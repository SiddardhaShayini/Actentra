"""Chaos and invariant failure-mode tests (I1-I7)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from actentra import ActionBlockedError, Boundary
from actentra_core.envelope import build_envelope
from actentra_core.policy import PolicyStore, PolicyValidationError, load_policy_yaml
from actentra_core.receipts import ReceiptError, ReceiptStore, verify_log
from actentra_core.verdict import Verdict


def test_receipt_write_failure_prevents_execution_invariant_i5(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    store = ReceiptStore(tmp_path / "receipts.db")
    boundary = Boundary(policy=policy, receipt_store=store)

    def fail_commit(*_args: object, **_kwargs: object) -> None:
        raise ReceiptError("Simulated disk full")

    monkeypatch.setattr(store, "record_decision", fail_commit)

    ran = False

    def target(_env: object, _dec: object) -> str:
        nonlocal ran
        ran = True
        return "executed"

    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.execute(
            tool="fs.read",
            verb="read",
            resource=r"path:C:\work\file.txt",
            fn=target,
        )
    assert exc_info.value.decision.verdict == Verdict.HOLD
    assert ran is False


def test_approval_ttl_expiry_and_session_isolation_invariant_i4(tmp_path: Path) -> None:
    policy = load_policy_yaml(
        """
version: 1
defaults: { verdict: deny }
rules:
  - id: ask-write
    match: { tool: fs.write, verb: write }
    verdict: ask
"""
    )
    store = ReceiptStore(tmp_path / "receipts.db")
    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        session_id="session-a",
        approval_ttl_seconds=0.01,
    )
    env = build_envelope(
        tool="fs.write",
        verb="write",
        resource=r"path:C:\work\out.txt",
        session_id="session-a",
    )

    # Wrong session grant must not authorize session-a
    boundary.grant_approval(canonical_hash=env.canonical_hash, session_id="session-b")
    with pytest.raises(ActionBlockedError):
        boundary.execute(
            tool="fs.write",
            verb="write",
            resource=r"path:C:\work\out.txt",
            fn=lambda _e, _d: "ok",
        )

    # Expired grant must not authorize
    boundary.grant_approval(canonical_hash=env.canonical_hash, session_id="session-a")
    time.sleep(0.03)
    with pytest.raises(ActionBlockedError):
        boundary.execute(
            tool="fs.write",
            verb="write",
            resource=r"path:C:\work\out.txt",
            fn=lambda _e, _d: "ok",
        )


def test_corrupt_policy_reload_preserves_last_known_good_invariant_i6() -> None:
    good = load_policy_yaml(
        """
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-read
    match: { tool: fs.read, verb: read }
    verdict: allow
"""
    )
    store = PolicyStore(good)

    for bad_yaml in (
        "not: [valid: yaml",
        "version: 99\ndefaults: { verdict: deny }\nrules: []",
        "version: 1\ndefaults: { verdict: allow }\nrules: []",
        (
            "version: 1\ndefaults: { verdict: deny }\nrules:\n"
            "  - { id: dup, match: { tool: a }, verdict: allow }\n"
            "  - { id: dup, match: { tool: b }, verdict: deny }\n"
        ),
    ):
        with pytest.raises(PolicyValidationError):
            store.reload_yaml(bad_yaml)
        assert store.current.policy_hash == good.policy_hash


def test_failed_execution_logs_failure_without_secret_leak_invariant_i7(tmp_path: Path) -> None:
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
    boundary = Boundary(policy=policy, receipt_store=store)

    def crashing_fn(_env: object, _dec: object) -> str:
        raise ValueError("SUPER_SECRET_API_KEY_12345")

    with pytest.raises(ValueError):
        boundary.execute(
            tool="fs.read",
            verb="read",
            resource=r"path:C:\work\a.txt",
            fn=crashing_fn,
        )

    records = store.iter_records()
    assert len(records) == 2
    assert records[1].status == "failure"
    assert records[1].error == "ValueError"
    assert "SUPER_SECRET_API_KEY_12345" not in (records[1].error or "")
    assert verify_log(db_path).ok is True
