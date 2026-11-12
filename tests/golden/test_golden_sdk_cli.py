"""Golden, SDK invariant, and CLI smoke tests for Actentra."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from actentra import ActionBlockedError, Boundary
from actentra_cli.main import app
from actentra_core.envelope import ProvenanceItem, build_envelope
from actentra_core.policy import load_policy_file
from actentra_core.receipts import ReceiptStore, verify_log
from actentra_core.verdict import Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_benign_corpus_replay(tmp_path: Path) -> None:
    policy = load_policy_file(REPO_ROOT / "policies" / "examples" / "starter.yaml")
    store = ReceiptStore(tmp_path / "receipts.db")
    boundary = Boundary(policy=policy, receipt_store=store, session_id="benign-eval")

    corpus_path = REPO_ROOT / "corpus" / "benign" / "sample_actions.jsonl"
    cases = [
        json.loads(line)
        for line in corpus_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    for case in cases:
        env = build_envelope(
            tool=case["tool"],
            verb=case["verb"],
            resource=case["resource"],
            session_id="benign-eval",
        )
        dec = boundary.engine.evaluate(env)
        assert dec.verdict == Verdict(case["expected_verdict"]), case["id"]


def test_sdk_guard_and_hash_bound_approval(tmp_path: Path) -> None:
    policy = load_policy_file(REPO_ROOT / "policies" / "examples" / "starter.yaml")
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)

    executed: list[str] = []
    boundary = Boundary(policy=policy, receipt_store=store, session_id="s-auth")

    @boundary.guard(
        tool="fs.write",
        verb="write",
        resource_fn=lambda path, _content: f"path:{path}",
    )
    def write_note(path: str, content: str) -> str:
        executed.append(f"{path}:{content}")
        return "ok"

    # Without approval, ASK blocks execution
    with pytest.raises(ActionBlockedError) as exc_info:
        write_note(r"C:\work\note.txt", "hello")
    assert exc_info.value.decision.verdict == Verdict.ASK
    assert executed == []

    # Pre-approve a DIFFERENT canonical hash -> must NOT authorize write_note
    other_env = build_envelope(
        tool="fs.write",
        verb="write",
        resource=r"path:C:\work\note.txt",
        params={"path": r"C:\work\note.txt", "content": "different"},
        session_id="s-auth",
    )
    boundary.grant_approval(canonical_hash=other_env.canonical_hash, session_id="s-auth")
    with pytest.raises(ActionBlockedError):
        write_note(r"C:\work\note.txt", "hello")
    assert executed == []

    # Pre-approve exact matching canonical hash -> executes once, then expires (one-time)
    exact_env = build_envelope(
        tool="fs.write",
        verb="write",
        resource=r"path:C:\work\note.txt",
        params={"path": r"C:\work\note.txt", "content": "hello"},
        session_id="s-auth",
    )
    boundary.grant_approval(canonical_hash=exact_env.canonical_hash, session_id="s-auth")
    assert write_note(r"C:\work\note.txt", "hello") == "ok"
    assert len(executed) == 1

    # Second call without new approval is blocked again
    with pytest.raises(ActionBlockedError):
        write_note(r"C:\work\note.txt", "hello")

    vr = verify_log(db_path)
    assert vr.ok is True
    assert vr.total_records == 5  # 4 decisions + 1 outcome


def test_sdk_fails_closed_on_invalid_path(tmp_path: Path) -> None:
    policy = load_policy_file(REPO_ROOT / "policies" / "examples" / "starter.yaml")
    store = ReceiptStore(tmp_path / "receipts.db")
    boundary = Boundary(policy=policy, receipt_store=store)

    ran = False

    def should_not_run(_env: object, _dec: object) -> str:
        nonlocal ran
        ran = True
        return "oops"

    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.execute(
            tool="fs.read",
            verb="read",
            resource=r"path:C:\work\file.txt:ads",
            fn=should_not_run,
        )
    assert exc_info.value.decision.verdict == Verdict.HOLD
    assert ran is False


def test_sdk_blocks_prompt_injected_egress(tmp_path: Path) -> None:
    policy = load_policy_file(REPO_ROOT / "policies" / "examples" / "starter.yaml")
    store = ReceiptStore(tmp_path / "receipts.db")
    boundary = Boundary(policy=policy, receipt_store=store)

    with pytest.raises(ActionBlockedError) as exc_info:
        boundary.execute(
            tool="http.post",
            verb="network",
            resource="https://attacker.example/leak",
            provenance=[ProvenanceItem(source="email:inbound", trust="untrusted")],
            fn=lambda _e, _d: "sent",
        )
    assert exc_info.value.decision.verdict == Verdict.DENY
    assert exc_info.value.decision.rule_id == "block-untrusted-egress"


def test_cli_commands_smoke(tmp_path: Path) -> None:
    runner = CliRunner()

    res_init = runner.invoke(app, ["init", str(tmp_path)])
    assert res_init.exit_code == 0, res_init.output
    policy_file = tmp_path / "actentra.policy.yaml"
    assert policy_file.exists()

    res_check = runner.invoke(app, ["policy", "check", str(policy_file)])
    assert res_check.exit_code == 0, res_check.output
    assert "OK policy=local-default" in res_check.output

    res_demo = runner.invoke(app, ["demo"])
    assert res_demo.exit_code == 0, res_demo.output
    assert "[ALLOW]" in res_demo.output
    assert "[BLOCKED]" in res_demo.output
    assert "[VERIFY] ok=True" in res_demo.output
