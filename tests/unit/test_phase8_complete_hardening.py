"""Comprehensive verification suite for Phase 8: Project Hardening and Engineering Quality.

Covers:
1. MCP Stdio Proxy Identity and Idempotency Propagation.
2. Function Calling Adapter Identity, Scope, and Idempotency Propagation.
3. LangChain Tool Wrapper Identity, Scope, and Idempotency Propagation.
4. Gateway Action Lifecycle & Historical State Transitions API Endpoints.
5. CLI Lifecycle Inspection & Operational Metrics Commands.
6. Full End-to-End Agent Lifecycle: Request -> Evaluation -> Approval -> Execution
   -> Observation -> Receipt -> Checkpoint Trail.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from actentra.adapters.function_calling import FunctionCallAdapter
from actentra.adapters.langchain import wrap_langchain_tool
from actentra.boundary import Boundary
from actentra_cli.main import app as cli_app
from actentra_core.canonicalize import canonicalize_windows_path
from actentra_core.identity import CallerContext, PrincipalType
from actentra_core.policy import parse_policy_dict
from actentra_core.receipts import ReceiptStore, verify_log
from actentra_executors.fs import LocalFSExecutor
from actentra_gateway.mcp_proxy import MCPStdioProxy, MCPToolMapping
from actentra_gateway.services import AppServices, ExecutorRegistry

runner = CliRunner()


def _make_test_policy() -> Any:
    return parse_policy_dict(
        {
            "version": 1,
            "policy_id": "test-phase8-policy",
            "mode": "enforce",
            "defaults": {"verdict": "deny", "reason": "Default deny"},
            "rules": [
                {
                    "id": "allow-fs-read",
                    "match": {"tool": "fs.read", "verb": "read"},
                    "verdict": "allow",
                    "reason": "Allow reading files",
                },
                {
                    "id": "ask-fs-write",
                    "match": {"tool": "fs.write", "verb": "write"},
                    "verdict": "ask",
                    "reason": "Writing files requires approval",
                },
                {
                    "id": "allow-calc",
                    "match": {"tool": "calc", "verb": "read"},
                    "verdict": "allow",
                    "reason": "Allow calculation",
                },
            ],
        }
    )


def test_mcp_proxy_identity_and_idempotency_propagation(tmp_path: Path) -> None:
    """Verify MCPStdioProxy correctly propagates caller identity and idempotency keys."""
    policy = _make_test_policy()
    db_path = tmp_path / "mcp_phase8.db"
    store = ReceiptStore(db_path)
    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        session_id="mcp-session",
        agent_id="default-agent",
    )

    forward_calls: list[dict[str, Any]] = []

    def mock_forward(msg: dict[str, Any]) -> dict[str, Any]:
        forward_calls.append(msg)
        return {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "result": {"content": [{"type": "text", "text": "calc-result-42"}]},
        }

    # 1. Caller context restricting allowed agent
    caller_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="unauthorized_client",
        authenticated=True,
        trust_domain="local",
        scopes=("crossings:execute",),
        allowed_agents=("allowed-agent-only",),
        authenticated_principal_id="unauthorized_client",
    )
    mapper = lambda name, args: MCPToolMapping(tool="calc", verb="read", resource="tool:calc")  # noqa: E731
    proxy_restricted = MCPStdioProxy(
        boundary=boundary,
        forward=mock_forward,
        tool_mapper=mapper,
        caller_context=caller_ctx,
    )

    # Calling tool as unauthorized agent must be blocked
    resp_blocked = proxy_restricted.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "calc", "arguments": {"expr": "6 * 7"}},
        }
    )
    assert resp_blocked is not None
    assert resp_blocked["result"]["isError"] is True
    assert "UNAUTHORIZED_PRINCIPAL" in resp_blocked["result"]["content"][0]["text"]
    assert len(forward_calls) == 0

    # 2. Authorized caller context with durable idempotency key in _meta
    authorized_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="mcp_agent",
        authenticated=True,
        trust_domain="local",
        scopes=("crossings:execute",),
        allowed_agents=("default-agent",),
        authenticated_principal_id="mcp_agent",
    )
    proxy_auth = MCPStdioProxy(
        boundary=boundary,
        forward=mock_forward,
        tool_mapper=mapper,
        caller_context=authorized_ctx,
    )

    req_msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "calc",
            "arguments": {
                "expr": "6 * 7",
                "_meta": {"idempotency_key": "mcp-call-key-001"},
            },
        },
    }

    # First invocation executes downstream
    resp1 = proxy_auth.handle_message(req_msg)
    assert resp1 is not None
    assert resp1["result"]["content"][0]["text"] == "calc-result-42"
    assert len(forward_calls) == 1

    # Exact replay returns cached response without dispatching to downstream server
    req_replay = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "calc",
            "arguments": {
                "expr": "6 * 7",
                "_meta": {"idempotency_key": "mcp-call-key-001"},
            },
        },
    }
    resp2 = proxy_auth.handle_message(req_replay)
    assert resp2 is not None
    assert resp2["result"]["content"][0]["text"] == "calc-result-42"
    # Forward calls count remains 1 (replayed from durable idempotency store)
    assert len(forward_calls) == 1


def test_function_call_adapter_identity_and_idempotency_propagation(tmp_path: Path) -> None:
    """Verify FunctionCallAdapter propagates caller context and idempotency keys."""
    policy = _make_test_policy()
    db_path = tmp_path / "fn_phase8.db"
    store = ReceiptStore(db_path)
    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        session_id="fn-session",
        agent_id="default-agent",
    )

    adapter = FunctionCallAdapter(boundary)
    exec_count = 0

    def compute_sum(a: int, b: int) -> int:
        nonlocal exec_count
        exec_count += 1
        return a + b

    adapter.register_tool("calc", compute_sum, verb="read")

    # 1. Blocked via restricted caller context
    unauthorized_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="rogue_agent",
        authenticated=True,
        trust_domain="local",
        scopes=(),
        allowed_agents=(),
        authenticated_principal_id="rogue_agent",
    )
    res_unauth = adapter.execute_call(
        {"id": "call_1", "name": "calc", "arguments": {"a": 10, "b": 20}},
        caller_context=unauthorized_ctx,
    )
    assert res_unauth["is_error"] is True
    assert "Blocked by Actentra policy" in res_unauth["content"]
    assert exec_count == 0

    # 2. Executed with authorized context & idempotency key
    auth_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="calc_operator",
        authenticated=True,
        trust_domain="local",
        scopes=("crossings:execute",),
        allowed_agents=("default-agent",),
        authenticated_principal_id="calc_operator",
    )
    res1 = adapter.execute_call(
        {"id": "call_2", "name": "calc", "arguments": {"a": 10, "b": 20}},
        caller_context=auth_ctx,
        idempotency_key="idemp-fn-100",
    )
    assert res1["is_error"] is False
    assert res1["content"] == "30"
    assert exec_count == 1

    # 3. Replay with identical parameters returns cached result without re-executing
    res2 = adapter.execute_call(
        {"id": "call_3", "name": "calc", "arguments": {"a": 10, "b": 20}},
        caller_context=auth_ctx,
        idempotency_key="idemp-fn-100",
    )
    assert res2["is_error"] is False
    assert res2["content"] == "30"
    assert exec_count == 1


def test_langchain_wrapper_identity_and_idempotency_propagation(tmp_path: Path) -> None:
    """Verify LangChainToolWrapper propagates identity and durable idempotency."""
    policy = _make_test_policy()
    db_path = tmp_path / "langchain_phase8.db"
    store = ReceiptStore(db_path)
    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        session_id="lc-session",
        agent_id="default-agent",
    )

    invocations = 0

    class MockLangChainTool:
        name = "calc"
        description = "Add numbers"

        def invoke(self, input_val: dict[str, Any], config: Any = None) -> int:
            nonlocal invocations
            invocations += 1
            return int(input_val.get("a", 0)) + int(input_val.get("b", 0))

    auth_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="langchain_user",
        authenticated=True,
        trust_domain="local",
        scopes=("crossings:execute",),
        allowed_agents=("default-agent",),
        authenticated_principal_id="langchain_user",
    )
    wrapped = wrap_langchain_tool(
        MockLangChainTool(),
        boundary,
        verb="read",
        caller_context=auth_ctx,
    )

    out1 = wrapped.invoke({"a": 5, "b": 15}, idempotency_key="lc-key-1")
    assert out1 == 20
    assert invocations == 1

    out2 = wrapped.invoke({"a": 5, "b": 15}, idempotency_key="lc-key-1")
    assert out2 == 20
    assert invocations == 1


def test_gateway_action_lifecycle_and_transitions_api(tmp_path: Path) -> None:
    """Verify AppServices and HTTP API expose action lifecycle and state transitions."""
    policy = _make_test_policy()
    db_path = tmp_path / "gateway_phase8.db"
    store = ReceiptStore(db_path)
    boundary = Boundary(
        policy=policy,
        receipt_store=store,
        session_id="api-session",
        agent_id="api-agent",
    )

    registry = ExecutorRegistry()
    registry.register("calc", lambda env, dec: 999)
    services = AppServices(boundary, executor_registry=registry)

    auth_ctx = CallerContext(
        principal_type=PrincipalType.LOCAL_PROCESS,
        principal_id="api_admin",
        authenticated=True,
        trust_domain="local",
        scopes=("crossings:submit", "crossings:execute", "crossings:read", "approvals:read"),
        allowed_agents=("api-agent",),
        authenticated_principal_id="api_admin",
    )

    # Submit an allowed action
    submit_res = services.submit_crossing(
        {
            "tool": "calc",
            "verb": "read",
            "resource": "tool:calc",
            "agent_id": "api-agent",
            "params": {"op": "multiply"},
        },
        execute=True,
        caller_context=auth_ctx,
    )
    assert submit_res["verdict"] == "allow"
    cid = submit_res["crossing_id"]

    # Query action lifecycle via service
    lf = services.get_action_lifecycle(cid, caller_context=auth_ctx)
    assert lf is not None
    assert lf["crossing_id"] == cid
    assert lf["current_state"] == "succeeded"

    # Query historical state transitions via service
    transitions = services.list_action_transitions(cid, caller_context=auth_ctx)
    assert len(transitions) >= 4
    states = [t["to_state"] for t in transitions]
    assert "created" in states
    assert "authorized" in states
    assert "executing" in states
    assert "succeeded" in states

    # Query unified crossing
    crossing_info = services.get_crossing(cid, caller_context=auth_ctx)
    assert crossing_info is not None
    assert crossing_info["crossing_id"] == cid
    assert crossing_info["lifecycle"]["current_state"] == "succeeded"
    assert len(crossing_info["transitions"]) >= 4


def test_cli_lifecycle_and_metrics_commands(tmp_path: Path) -> None:
    """Verify actentra CLI lifecycle show, transitions, and metrics commands."""
    db_path = tmp_path / "cli_phase8.db"
    store = ReceiptStore(db_path)
    policy = _make_test_policy()
    boundary = Boundary(policy=policy, receipt_store=store, session_id="cli-session")

    # Execute an action to record lifecycle & transitions
    res = boundary.execute(
        tool="calc",
        verb="read",
        resource="tool:calc",
        params={"x": 1},
        fn=lambda env, dec: 100,
    )
    assert res == 100

    # Retrieve crossing id from receipts
    records, _ = store.query_records()
    cid = records[0].crossing_id

    # 1. CLI lifecycle show
    res_show = runner.invoke(
        cli_app,
        ["lifecycle", "show", cid, "--db", str(db_path)],
    )
    assert res_show.exit_code == 0
    show_json = json.loads(res_show.output)
    assert show_json["crossing_id"] == cid
    assert show_json["current_state"] == "succeeded"

    # 2. CLI lifecycle transitions
    res_tr = runner.invoke(
        cli_app,
        ["lifecycle", "transitions", cid, "--db", str(db_path)],
    )
    assert res_tr.exit_code == 0
    assert "created -> authorized" in res_tr.output
    assert "executing -> succeeded" in res_tr.output

    # 3. CLI metrics command
    res_metrics = runner.invoke(cli_app, ["metrics"])
    assert res_metrics.exit_code == 0
    metrics_json = json.loads(res_metrics.output)
    assert "crossings" in metrics_json
    assert "executions" in metrics_json
    assert "idempotency" in metrics_json


def test_full_agent_workflow_request_approval_execution_and_checkpoint(
    tmp_path: Path,
) -> None:
    """Verify complete end-to-end invariant enforcement across full lifecycle."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    db_path = tmp_path / "audit.db"

    policy_pack = parse_policy_dict(
        {
            "version": 1,
            "policy_id": "e2e-hardened-policy",
            "mode": "enforce",
            "defaults": {"verdict": "deny"},
            "rules": [
                {
                    "id": "write-approval",
                    "match": {
                        "tool": "fs.write",
                        "verb": "write",
                        "resource": f"path:{canonicalize_windows_path(str(ws))}/**",
                    },
                    "verdict": "ask",
                    "reason": "File modification requires human operator review",
                }
            ],
        }
    )

    store = ReceiptStore(db_path)
    boundary = Boundary(
        policy=policy_pack,
        receipt_store=store,
        session_id="e2e-session",
        agent_id="e2e-agent",
    )
    executor = LocalFSExecutor(ws)
    registry = ExecutorRegistry()
    registry.register("fs.write", executor.execute)
    services = AppServices(boundary, executor_registry=registry)

    target_file = ws / "report.txt"
    target_res = f"path:{canonicalize_windows_path(str(target_file))}"

    operator_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_OPERATOR,
        principal_id="sec_admin",
        authenticated=True,
        trust_domain="local",
        scopes=(
            "crossings:submit",
            "crossings:approve",
            "crossings:execute",
            "crossings:read",
            "approvals:read",
            "approvals:write",
        ),
        allowed_agents=("e2e-agent", "*"),
        authenticated_principal_id="sec_admin",
    )

    # 1. Request action that triggers human approval
    prop = services.submit_crossing(
        {
            "tool": "fs.write",
            "verb": "write",
            "resource": target_res,
            "params": {"content": "Security Audit Report 2026\n"},
        },
        caller_context=operator_ctx,
    )
    assert prop["verdict"] == "ask"
    cid = prop["crossing_id"]

    # 2. Verify lifecycle state is 'created' pending approval
    lf1 = services.get_action_lifecycle(cid, caller_context=operator_ctx)
    assert lf1 is not None
    assert lf1["current_state"] == "created"

    # 3. Human resolves approval
    resolved = services.resolve_approval(
        cid, approved=True, execute=True, caller_context=operator_ctx
    )
    assert resolved["status"] == "approved"
    assert resolved["execution"]["status"] == "success"

    # 4. Verify postcondition executed in workspace
    assert target_file.exists()
    assert target_file.read_text(encoding="utf-8") == "Security Audit Report 2026\n"

    # 5. Verify lifecycle transitioned to 'succeeded'
    lf2 = services.get_action_lifecycle(cid, caller_context=operator_ctx)
    assert lf2 is not None
    assert lf2["current_state"] == "succeeded"

    # 6. Verify hash-chain receipt store log integrity
    vr = verify_log(db_path)
    assert vr.ok is True
    assert vr.total_records >= 2  # decision + outcome
