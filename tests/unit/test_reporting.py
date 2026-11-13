"""Unit and CLI tests for audit reporting and HTML generation."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from actentra_cli.main import app
from actentra_core.envelope import build_envelope
from actentra_core.policy import PolicyEngine, load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_core.reporting import build_audit_summary, render_html_report


def test_build_audit_summary_and_render_html(tmp_path: Path) -> None:
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(
        """
version: 1
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
    engine = PolicyEngine(policy)

    # 1. Successful read
    env1 = build_envelope(
        tool="fs.read", verb="read", resource="path:C:/work/a.txt", session_id="s1"
    )
    dec1 = engine.evaluate(env1)
    store.record_decision(env1, dec1)
    store.record_outcome(
        crossing_id=env1.crossing_id,
        session_id=env1.session_id,
        canonical_hash=env1.canonical_hash,
        policy_version=dec1.policy_version,
        status="success",
    )

    # 2. Blocked write (ASK)
    env2 = build_envelope(
        tool="fs.write", verb="write", resource="path:C:/work/b.txt", session_id="s1"
    )
    dec2 = engine.evaluate(env2)
    store.record_decision(env2, dec2)

    # 3. Default denied
    env3 = build_envelope(tool="shell.exec", verb="exec", resource="proc:cmd.exe", session_id="s2")
    dec3 = engine.evaluate(env3)
    store.record_decision(env3, dec3)

    summary = build_audit_summary(db_path)
    assert summary.total_records == 4
    assert summary.decision_count == 3
    assert summary.outcome_count == 1
    assert summary.verdict_counts["allow"] == 1
    assert summary.verdict_counts["ask"] == 1
    assert summary.verdict_counts["deny"] == 1
    assert summary.integrity_ok is True
    assert len(summary.items) == 3

    html_content = render_html_report(summary, title="Test Audit Report")
    assert "<!DOCTYPE html>" in html_content
    assert "Actentra" in html_content
    assert "Execution Audit Report" in html_content
    assert "VERIFIED (TAMPER-EVIDENT OK)" in html_content
    assert "allow-read" in html_content
    assert "ask-write" in html_content
    assert "Head Hash:" in html_content


def test_cli_report_command(tmp_path: Path) -> None:
    runner = CliRunner()
    db_path = tmp_path / "receipts.db"
    html_out = tmp_path / "audit.html"

    # Initialize a valid store
    ReceiptStore(db_path)

    res_summary = runner.invoke(app, ["report", str(db_path)])
    assert res_summary.exit_code == 0, res_summary.output
    assert "=== Actentra Audit Report:" in res_summary.output
    assert "Integrity Status    : OK" in res_summary.output

    res_html = runner.invoke(app, ["report", str(db_path), "--html", str(html_out)])
    assert res_html.exit_code == 0, res_html.output
    assert html_out.exists()
    assert "<!DOCTYPE html>" in html_out.read_text(encoding="utf-8")
