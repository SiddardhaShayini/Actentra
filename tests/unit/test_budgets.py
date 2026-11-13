"""Unit tests for Actentra cumulative session budgets (T4, T5 mitigations)."""

from __future__ import annotations

from pathlib import Path

import pytest

from actentra import ActionBlockedError, Boundary
from actentra_core.envelope import build_envelope
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_core.verdict import Verdict


def test_session_budget_actions_capping(tmp_path: Path) -> None:
    db_path = tmp_path / "budget.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(
        """
version: 1
policy_id: test-budget-actions
mode: enforce
defaults: { verdict: deny }
budgets:
  max_actions: 3
  on_exceeded: deny
rules:
  - id: allow-calc
    match: { tool: calc, verb: read }
    verdict: allow
"""
    )
    boundary = Boundary(policy=policy, receipt_store=store, session_id="s-loop")

    # Actions 1, 2, 3 should succeed
    for i in range(3):
        res = boundary.execute(
            tool="calc",
            verb="read",
            resource=f"calc:{i}",
            fn=lambda _env, _dec, val=i: val * 10,
        )
        assert res == i * 10

    # Action 4 exceeds session cumulative budget of 3 actions -> blocked
    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.execute(
            tool="calc",
            verb="read",
            resource="calc:4",
            fn=lambda _env, _dec: 40,
        )
    assert exc_info.value.decision.verdict == Verdict.DENY
    assert "budget:max-actions-exceeded" in exc_info.value.decision.rule_id
    assert "budget-exceeded" in exc_info.value.decision.risk_tags


def test_session_budget_external_calls(tmp_path: Path) -> None:
    db_path = tmp_path / "budget_ext.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(
        """
version: 1
policy_id: test-budget-external
mode: enforce
defaults: { verdict: deny }
budgets:
  max_external_calls: 2
  on_exceeded: ask
rules:
  - id: allow-http
    match: { tool: "http.*", verb: "read" }
    verdict: allow
"""
    )
    boundary = Boundary(policy=policy, receipt_store=store, session_id="s-ext")

    # 1. First external call succeeds
    res1 = boundary.execute(
        tool="http.get",
        verb="read",
        resource="https://api.github.com/repos",
        fn=lambda _env, _dec: {"status": 200},
    )
    assert res1 == {"status": 200}

    # 2. Second external call succeeds
    res2 = boundary.execute(
        tool="http.get",
        verb="read",
        resource="https://api.github.com/users",
        fn=lambda _env, _dec: {"status": 200},
    )
    assert res2 == {"status": 200}

    # 3. Third external call exceeds limit (2) and escalates to ASK (human approval required)
    env = build_envelope(
        tool="http.get",
        verb="read",
        resource="https://api.github.com/events",
        session_id="s-ext",
    )
    dec = boundary.engine.evaluate(env)
    assert dec.verdict == Verdict.ASK
    assert dec.rule_id == "budget:max-external-calls-exceeded"


def test_session_budget_write_bytes(tmp_path: Path) -> None:
    db_path = tmp_path / "budget_write.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(
        """
version: 1
policy_id: test-budget-bytes
mode: enforce
defaults: { verdict: deny }
budgets:
  max_write_bytes: 100
  on_exceeded: deny
rules:
  - id: allow-write
    match: { tool: fs.write, verb: write }
    verdict: allow
"""
    )
    boundary = Boundary(policy=policy, receipt_store=store, session_id="s-bytes")

    # 1. 60 bytes write allowed
    boundary.execute(
        tool="fs.write",
        verb="write",
        resource="path:C:/work/part1.txt",
        params={"content": "A" * 60},
        fn=lambda _env, _dec: 60,
    )

    # 2. Attempting another 50 bytes (total 110 > 100) -> blocked
    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.execute(
            tool="fs.write",
            verb="write",
            resource="path:C:/work/part2.txt",
            params={"content": "B" * 50},
            fn=lambda _env, _dec: 50,
        )
    assert exc_info.value.decision.verdict == Verdict.DENY
    assert "budget:max-write-bytes-exceeded" in exc_info.value.decision.rule_id
