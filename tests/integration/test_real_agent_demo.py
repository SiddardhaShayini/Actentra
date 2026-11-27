"""Deterministic integration tests for examples/real_agent_demo."""

from __future__ import annotations

import sys
from pathlib import Path

from actentra_core.verdict import Verdict

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from examples.real_agent_demo.actentra_layer import ActentraToolBridge  # noqa: E402
from examples.real_agent_demo.agent import ToolCallingAgent  # noqa: E402
from examples.real_agent_demo.model_client import (  # noqa: E402
    ScriptedToolProposalModel,
    check_system_resources,
    parse_tool_calls_from_text,
)
from examples.real_agent_demo.policy import build_demo_policy_yaml  # noqa: E402
from examples.real_agent_demo.run_demo import run_all_scenarios  # noqa: E402


def test_real_agent_demo_all_scenarios_e2e() -> None:
    """Verify Scenarios A-E end-to-end with real Actentra enforcement and no mocks."""
    summary = run_all_scenarios(backend="scripted", verbose=False)

    # Scenario A: Authorized write executed and independently verified
    call_a = summary.scenario_a.mediated_calls[0]
    assert call_a.execution is not None
    assert call_a.execution.allowed is True
    assert call_a.execution.verdict == Verdict.ALLOW
    assert call_a.execution.status == "success"
    assert call_a.execution.evidence_status == "externally_verified"
    assert call_a.execution.verified is True

    # Scenario B1: Protected external write denied and file untouched
    call_b1 = summary.scenario_b_protected.mediated_calls[0]
    assert call_b1.execution is not None
    assert call_b1.execution.allowed is False
    assert call_b1.execution.verdict == Verdict.DENY
    assert summary.protected_file_unchanged is True

    # Scenario B2: Prohibited shell command denied
    call_b2 = summary.scenario_b_shell.mediated_calls[0]
    assert call_b2.execution is not None
    assert call_b2.execution.allowed is False
    assert call_b2.execution.verdict == Verdict.DENY
    assert call_b2.execution.rule_id in {
        "block-privilege-escalation",
        "block-shell-execution",
    }

    # Scenario C: False executor success refuted by WorkspaceFileVerifier
    call_c = summary.scenario_c.mediated_calls[0]
    assert call_c.execution is not None
    assert call_c.execution.allowed is True
    assert call_c.execution.status == "failure"
    assert call_c.execution.verified is False
    assert call_c.execution.observation is not None
    assert call_c.execution.observation.status == "refuted"
    assert summary.ghost_file_absent is True

    # Scenario D: Held before approval, then executed & verified after hash-bound approval
    call_d1 = summary.scenario_d_held.mediated_calls[0]
    assert call_d1.execution is not None
    assert call_d1.execution.allowed is False
    assert call_d1.execution.verdict == Verdict.ASK

    call_d2 = summary.scenario_d_approved.mediated_calls[0]
    assert call_d2.execution is not None
    assert call_d2.execution.allowed is True
    assert call_d2.execution.verdict == Verdict.ALLOW
    assert call_d2.execution.status == "success"
    assert call_d2.execution.evidence_status == "externally_verified"
    assert call_d2.execution.verified is True
    assert summary.approved_file_exists is True

    # Scenario E: Complete evidence rows & intact SQLite SHA-256 hash chain
    assert len(summary.evidence_rows) == 6
    assert summary.hash_chain_ok is True
    assert summary.total_receipt_records >= 6


def test_agent_cannot_bypass_boundary_on_path_traversal(tmp_path: Path) -> None:
    """Path traversal proposals fail closed and never touch files outside workspace."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("KEEP_INTACT", encoding="utf-8")

    bridge = ActentraToolBridge(
        policy_yaml=build_demo_policy_yaml(workspace),
        receipts_db=tmp_path / "receipts.db",
        workspace_root=workspace,
        model_name="traversal-test-model",
    )
    model = ScriptedToolProposalModel(
        proposals_by_task={
            "escape": [
                {
                    "name": "write_workspace_file",
                    "arguments": {"path": "../outside.txt", "content": "PWNED"},
                }
            ]
        }
    )
    agent = ToolCallingAgent(model=model, bridge=bridge)
    report = agent.run("Please escape the workspace.")

    assert len(report.mediated_calls) == 1
    call = report.mediated_calls[0]
    assert call.pre_evaluation_error is not None
    assert call.execution is None
    assert outside.read_text(encoding="utf-8") == "KEEP_INTACT"


def test_check_system_resources_returns_safe_recommendation() -> None:
    """Resource check returns CPU/RAM metadata and a bounded local model recommendation."""
    report = check_system_resources()
    assert report.recommended_ollama_model in {"qwen2.5:1.5b", "qwen2.5:3b", "qwen2.5:7b"}
    assert report.cpu_logical is None or report.cpu_logical >= 1


def test_parse_tool_calls_supports_qwen25_qwen35_xml_and_harmony() -> None:
    """Verify tool-call parser handles JSON, Qwen3.5 XML, Harmony, and <think> tags."""
    # 1. Qwen2.5 JSON <tool_call>
    c1, calls1 = parse_tool_calls_from_text(
        '<think>plan</think>\n<tool_call>{"name": "read_workspace_file", '
        '"arguments": {"path": "readme.txt"}}</tool_call>'
    )
    assert c1 is None
    assert calls1[0]["function"]["name"] == "read_workspace_file"

    # 2. Qwen3.5 XML <tool_call><function=...><parameter=...>
    c2, calls2 = parse_tool_calls_from_text(
        "<tool_call>\n<function=write_workspace_file>\n"
        "<parameter=path>\ndrafts/summary.txt\n</parameter>\n"
        "<parameter=content>\nVerified by Actentra.\n</parameter>\n"
        "</function>\n</tool_call>"
    )
    assert c2 is None
    assert calls2[0]["function"]["name"] == "write_workspace_file"
    assert '"drafts/summary.txt"' in calls2[0]["function"]["arguments"]

    # 3. gpt-oss Harmony format
    c3, calls3 = parse_tool_calls_from_text(
        '<|channel|>commentary to=functions.run_shell_command <|constrain|>json'
        '<|message|>{"command": "whoami"}<|call|>'
    )
    assert c3 is None
    assert calls3[0]["function"]["name"] == "run_shell_command"
    assert '"whoami"' in calls3[0]["function"]["arguments"]


def test_agent_handles_missing_file_read_error_gracefully(tmp_path: Path) -> None:
    """ExecutorError (e.g., reading nonexistent ghost.txt) is returned as tool error, not crash."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    bridge = ActentraToolBridge(
        policy_yaml=build_demo_policy_yaml(workspace),
        receipts_db=tmp_path / "receipts.db",
        workspace_root=workspace,
        model_name="missing-file-test-model",
    )
    model = ScriptedToolProposalModel(
        proposals_by_task={
            "inspect": [
                {
                    "name": "read_workspace_file",
                    "arguments": {"path": "unreliable/ghost.txt"},
                }
            ]
        }
    )
    agent = ToolCallingAgent(model=model, bridge=bridge)
    report = agent.run("Please inspect unreliable/ghost.txt.")

    assert len(report.mediated_calls) == 1
    call = report.mediated_calls[0]
    assert call.execution is None
    assert call.pre_evaluation_error is not None
    assert "ExecutorError" in call.pre_evaluation_error
    assert "ExecutorError" in report.final_answer
