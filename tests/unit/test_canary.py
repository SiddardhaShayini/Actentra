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


def test_policy_canary_faithful_timing_and_rate_windows(tmp_path: Path) -> None:
    """Canary evaluates historical rate limits using original timestamps, not real-time clock."""
    db_path = tmp_path / "timing_canary.db"
    store = ReceiptStore(db_path)

    baseline_policy = load_policy_yaml(
        """
version: 1
policy_id: timing-baseline
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-calc
    match: { tool: calc }
    verdict: allow
"""
    )
    engine = PolicyEngine(baseline_policy)

    # Record 3 actions 2 minutes apart (outside a 60-second window)
    timestamps_apart = [
        "2026-11-14T10:00:00Z",
        "2026-11-14T10:02:00Z",
        "2026-11-14T10:04:00Z",
    ]
    for i, ts in enumerate(timestamps_apart):
        env = build_envelope(
            tool="calc",
            verb="read",
            resource=f"tool:calc:{i}",
            session_id="s-time",
            ts=ts,
        )
        store.record_decision(env, engine.evaluate(env))

    # Candidate introduces a 2/min rate limit
    rate_candidate = load_policy_yaml(
        """
version: 1
policy_id: timing-candidate
mode: enforce
defaults: { verdict: deny }
limits:
  - id: tight-limit
    scope: global
    max_actions_per_minute: 2
rules:
  - id: allow-calc
    match: { tool: calc }
    verdict: allow
"""
    )
    # Because timestamps are 2 minutes apart, NONE of the 3 actions should trip the 2/min rate limit
    summary_apart = run_policy_canary(rate_candidate, db_path)
    assert summary_apart.total_evaluated == 3
    assert summary_apart.identical_count == 3
    assert summary_apart.more_restrictive_count == 0

    # Now record 3 actions 5 seconds apart (inside the same 60-second window)
    db_path_burst = tmp_path / "burst_canary.db"
    store_burst = ReceiptStore(db_path_burst)
    timestamps_burst = [
        "2026-11-14T10:00:00Z",
        "2026-11-14T10:00:05Z",
        "2026-11-14T10:00:10Z",
    ]
    for i, ts in enumerate(timestamps_burst):
        env = build_envelope(
            tool="calc",
            verb="read",
            resource=f"tool:calc:{i}",
            session_id="s-burst",
            ts=ts,
        )
        store_burst.record_decision(env, engine.evaluate(env))

    # Replay burst against the 2/min candidate: the 3rd action MUST trip rate limit!
    summary_burst = run_policy_canary(rate_candidate, db_path_burst)
    assert summary_burst.total_evaluated == 3
    assert summary_burst.identical_count == 2
    assert summary_burst.more_restrictive_count == 1
    diff = [d for d in summary_burst.diffs if d.delta_type == "more_restrictive"][0]
    assert diff.candidate_verdict == "deny"
    assert "limit:tight-limit" in diff.candidate_rule


def test_policy_canary_replays_provenance_and_fidelity_warnings(tmp_path: Path) -> None:
    """Canary faithfully preserves provenance and generates fidelity warnings on missing context."""
    from actentra_core.envelope import ProvenanceItem

    db_path = tmp_path / "prov_canary.db"
    store = ReceiptStore(db_path)

    baseline_policy = load_policy_yaml(
        """
version: 1
policy_id: prov-baseline
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-http
    match: { tool: "http.*" }
    verdict: allow
"""
    )
    engine = PolicyEngine(baseline_policy)

    # 1. Action with untrusted provenance
    env1 = build_envelope(
        tool="http.get",
        verb="read",
        resource="https://external.com",
        session_id="s-prov",
        provenance=[ProvenanceItem(source="prompt", trust="untrusted")],
    )
    store.record_decision(env1, engine.evaluate(env1))

    # 2. Action with trusted provenance
    env2 = build_envelope(
        tool="http.get",
        verb="read",
        resource="https://external.com",
        session_id="s-prov",
        provenance=[ProvenanceItem(source="user", trust="trusted")],
    )
    store.record_decision(env2, engine.evaluate(env2))

    # Candidate blocks untrusted taint
    cand_policy = load_policy_yaml(
        """
version: 1
policy_id: prov-candidate
mode: enforce
defaults: { verdict: deny }
rules:
  - id: block-tainted
    match: { tool: "http.*", taint: untrusted }
    verdict: deny
  - id: allow-http
    match: { tool: "http.*" }
    verdict: allow
"""
    )
    summary = run_policy_canary(cand_policy, db_path)
    assert summary.total_evaluated == 2
    assert summary.identical_count == 1  # env2 stays allow
    assert summary.more_restrictive_count == 1  # env1 shifts to deny due to provenance
    assert summary.missing_context_count == 0
    assert len(summary.fidelity_warnings) == 0

    # Delete an envelope to simulate missing context
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM action_envelopes WHERE crossing_id = ?;", (env1.crossing_id,))
    conn.commit()
    conn.close()

    summary_missing = run_policy_canary(cand_policy, db_path)
    assert summary_missing.missing_context_count == 1
    assert len(summary_missing.fidelity_warnings) == 1
    assert "advisory" in summary_missing.fidelity_warnings[0]
