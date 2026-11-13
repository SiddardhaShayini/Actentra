"""Unit tests for the Actentra Policy Canary diff and regression analysis engine."""

from __future__ import annotations

from pathlib import Path

from actentra_core.canary import run_policy_canary
from actentra_core.envelope import build_envelope
from actentra_core.policy import PolicyEngine, load_policy_yaml
from actentra_core.receipts import ReceiptStore


def test_policy_canary_shift_detection(tmp_path: Path) -> None:
    db_path = tmp_path / "baseline.db"
    store = ReceiptStore(db_path)

    # Baseline policy: allows calc and read, asks write
    baseline_policy = load_policy_yaml(
        """
version: 1
policy_id: baseline-policy
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-calc
    match: { tool: calc, verb: read }
    verdict: allow
  - id: allow-read
    match: { tool: fs.read, verb: read }
    verdict: allow
  - id: ask-write
    match: { tool: fs.write, verb: write }
    verdict: ask
"""
    )
    engine = PolicyEngine(baseline_policy)

    # Record 3 historical decisions
    # 1. calc (allow)
    env1 = build_envelope(tool="calc", verb="read", resource="tool:calc", session_id="s1")
    store.record_decision(env1, engine.evaluate(env1))

    # 2. fs.read (allow)
    env2 = build_envelope(
        tool="fs.read", verb="read", resource="path:C:/work/a.txt", session_id="s1"
    )
    store.record_decision(env2, engine.evaluate(env2))

    # 3. fs.write (ask)
    env3 = build_envelope(
        tool="fs.write", verb="write", resource="path:C:/work/b.txt", session_id="s1"
    )
    store.record_decision(env3, engine.evaluate(env3))

    # 4. shell.exec (deny by default)
    env4 = build_envelope(tool="shell.exec", verb="exec", resource="proc:cmd.exe", session_id="s1")
    store.record_decision(env4, engine.evaluate(env4))

    # Candidate 1: Identical policy -> 0 shifts
    summary1 = run_policy_canary(baseline_policy, db_path)
    assert summary1.total_evaluated == 4
    assert summary1.identical_count == 4
    assert summary1.more_restrictive_count == 0
    assert summary1.less_restrictive_count == 0
    assert summary1.has_regressions is False

    # Candidate 2: Hardened policy: calc is now DENY (more restrictive)
    hardened_policy = load_policy_yaml(
        """
version: 1
policy_id: hardened-policy
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-read
    match: { tool: fs.read, verb: read }
    verdict: allow
  - id: ask-write
    match: { tool: fs.write, verb: write }
    verdict: ask
"""
    )
    summary2 = run_policy_canary(hardened_policy, db_path)
    assert summary2.total_evaluated == 4
    assert summary2.identical_count == 3
    assert summary2.more_restrictive_count == 1  # calc shifted from allow -> deny
    assert summary2.less_restrictive_count == 0
    assert summary2.has_regressions is False

    # Candidate 3: Over-privileged policy: shell.exec is now ALLOW (Regression!)
    loose_policy = load_policy_yaml(
        """
version: 1
policy_id: loose-policy
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-calc
    match: { tool: calc, verb: read }
    verdict: allow
  - id: allow-read
    match: { tool: fs.read, verb: read }
    verdict: allow
  - id: allow-shell-unsafe
    match: { tool: shell.exec, verb: exec }
    verdict: allow
"""
    )
    summary3 = run_policy_canary(loose_policy, db_path)
    assert summary3.total_evaluated == 4
    assert summary3.less_restrictive_count >= 1  # shell.exec allow is a regression
    assert summary3.has_regressions is True
    regressions = [d for d in summary3.diffs if d.delta_type == "less_restrictive"]
    assert len(regressions) >= 1
    assert any(r.tool == "shell.exec" for r in regressions)
