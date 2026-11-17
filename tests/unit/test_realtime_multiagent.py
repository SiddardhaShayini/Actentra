"""Unit and integration tests for Actentra Real-Time Concurrent Multi-Agent Simulation."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from actentra_cli.main import app
from actentra_gateway.multi_agent_realtime_sim import (
    RealtimeMultiagentResult,
    run_realtime_multiagent_simulation,
)

runner = CliRunner()


def test_realtime_multiagent_simulation_direct(tmp_path: Path) -> None:
    """Run 4 concurrent agents against a shared workspace and SQLite WAL database."""
    ws = tmp_path / "sim_ws"
    db = tmp_path / "sim.db"

    result: RealtimeMultiagentResult = run_realtime_multiagent_simulation(
        workspace_root=ws,
        db_file=db,
        num_cycles=4,
        verbose=False,
    )

    # 1. Overall outcome must be OK
    assert result.ok is True, f"Simulation failed: {result}"
    assert result.num_agents == 4
    assert result.total_operations > 0

    # 2. Concurrency protections: lease conflicts prevented under active contention
    assert result.total_conflicts_prevented > 0, (
        f"Expected conflicts prevented, got: {result.total_conflicts_prevented}"
    )

    # 3. Security enforcement: adversary blocked fail-closed under concurrent load
    assert result.total_policy_denials > 0, (
        f"Expected policy denials, got: {result.total_policy_denials}"
    )

    # 4. State verification: postconditions verified by workers and auditor
    assert result.total_postconditions_verified > 0

    # 5. Cryptographic hash-chain integrity of the SQLite WAL audit trail
    assert result.verification.ok is True
    assert result.verification.total_records > 0

    # 6. Check individual agent stats
    stats = result.agent_stats
    assert "ingest_agent" in stats
    assert "transform_agent" in stats
    assert "auditor_agent" in stats
    assert "adversary_agent" in stats

    assert stats["ingest_agent"]["succeeded"] > 0
    assert stats["transform_agent"]["conflicts_prevented"] > 0
    assert stats["adversary_agent"]["policy_denials"] > 0


def test_realtime_multiagent_cli_command(tmp_path: Path) -> None:
    """Test `actentra demo-realtime` command via Typer CliRunner."""
    ws = tmp_path / "cli_ws"
    db = tmp_path / "cli_sim.db"

    res = runner.invoke(
        app,
        [
            "demo-realtime",
            "--workspace",
            str(ws),
            "--db",
            str(db),
            "--cycles",
            "2",
        ],
    )
    assert res.exit_code == 0, f"CLI demo-realtime failed: {res.output}"
    assert "Actentra Real-Time Concurrent Multi-Agent Simulation" in res.output
    assert "WAL Hash-Chain Integrity:  OK (PASS)" in res.output


def test_demo_with_realtime_flag(tmp_path: Path) -> None:
    """Test `actentra demo --realtime` CLI flag."""
    res = runner.invoke(app, ["demo", "--realtime"])
    assert res.exit_code == 0, f"CLI demo --realtime failed: {res.output}"
    assert "Actentra Real-Time Concurrent Multi-Agent Simulation" in res.output
    assert "WAL Hash-Chain Integrity:  OK (PASS)" in res.output
