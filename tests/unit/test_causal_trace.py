"""Tests for Phase 3 Causal Trace, typed references, and DAG integrity."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from actentra.boundary import Boundary
from actentra_cli.main import app
from actentra_core.causal import (
    CausalLink,
    CausalTraceEdge,
    CycleDetectedError,
    build_causal_trace,
    detect_cycles,
    generate_link_id,
)
from actentra_core.envelope import build_envelope
from actentra_core.observations import build_observation
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_core.verdict import Decision, Verdict
from actentra_gateway.http_service import ActentraHTTPHandler
from actentra_gateway.services import AppServices

runner = CliRunner()

_STARTER_POLICY = """\
version: 1
policy_id: test-causal-policy
mode: enforce
defaults:
  verdict: deny
rules:
  - id: allow-read
    match:
      verb: read
    verdict: allow
  - id: ask-delete
    match:
      verb: delete
    verdict: ask
"""


def _dispatch_handler(
    services: AppServices,
    path: str,
    method: str = "GET",
    data: Any = None,
) -> tuple[int, Any]:
    handler = ActentraHTTPHandler.__new__(ActentraHTTPHandler)
    server_mock = MagicMock()
    server_mock.services = services
    server_mock.auth_token = None
    server_mock.boundary = services.boundary
    handler.server = server_mock
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.close_connection = True
    handler.path = path
    handler.wfile = io.BytesIO()

    body_bytes = json.dumps(data).encode("utf-8") if data is not None else b""
    handler.headers = {  # type: ignore[assignment]
        "Content-Length": str(len(body_bytes)),
        "Content-Type": "application/json",
        "Origin": "http://127.0.0.1:8080",
    }
    handler.rfile = io.BytesIO(body_bytes)

    if method == "GET":
        handler.do_GET()
    elif method == "POST":
        handler.do_POST()
    elif method == "DELETE":
        handler.do_DELETE()
    else:
        raise ValueError(f"Unsupported method {method}")

    raw_output = handler.wfile.getvalue().decode("utf-8")
    status_code = int(raw_output.splitlines()[0].split()[1])
    parts = raw_output.split("\r\n\r\n", 1)
    body_str = parts[1] if len(parts) > 1 else ""
    try:
        parsed_body = json.loads(body_str)
    except Exception:
        parsed_body = body_str
    return status_code, parsed_body


def test_causal_schemas_validation() -> None:
    """Verify CausalLink and CausalTrace conform to versioned JSON schemas."""
    import jsonschema  # type: ignore[import-untyped]

    link_schema_path = Path("spec/causal-link.v1.schema.json")
    trace_schema_path = Path("spec/causal-trace.v1.schema.json")
    assert link_schema_path.exists()
    assert trace_schema_path.exists()

    link_schema = json.loads(link_schema_path.read_text(encoding="utf-8"))
    trace_schema = json.loads(trace_schema_path.read_text(encoding="utf-8"))

    link = CausalLink(
        link_id=generate_link_id(),
        link_version="1",
        source_id="cr_01HZX000000000000000000001",
        source_type="crossing",
        relation="caused_by",
        target_id="task_build_release_v1",
        target_type="task",
        created_at="2026-11-16T15:00:00.000Z",
        metadata={"priority": "high"},
    )
    jsonschema.validate(instance=link.to_dict(), schema=link_schema)

    # Empty DAG trace validation
    trace_dict = {
        "root_id": "cr_01HZX000000000000000000001",
        "root_type": "crossing",
        "nodes": [],
        "edges": [],
        "timeline": [],
        "dag_verified": True,
        "missing_references": [],
    }
    jsonschema.validate(instance=trace_dict, schema=trace_schema)


def test_detect_cycles_and_dag_validation() -> None:
    """detect_cycles reliably distinguishes acyclic DAGs from cyclic dependency graphs."""
    # 1. Acyclic linear: A -> B -> C
    edges_acyclic = [
        CausalTraceEdge("A", "B", "evaluates_to", "intrinsic"),
        CausalTraceEdge("B", "C", "executes_to", "intrinsic"),
    ]
    assert detect_cycles(edges_acyclic) is False

    # 2. Diamond DAG: A -> B, A -> C, B -> D, C -> D
    edges_diamond = [
        CausalTraceEdge("A", "B", "step", "explicit"),
        CausalTraceEdge("A", "C", "step", "explicit"),
        CausalTraceEdge("B", "D", "step", "explicit"),
        CausalTraceEdge("C", "D", "step", "explicit"),
    ]
    assert detect_cycles(edges_diamond) is False

    # 3. Direct self-loop: A -> A
    assert detect_cycles([CausalTraceEdge("A", "A", "self", "explicit")]) is True

    # 4. 2-node cycle: A -> B -> A
    edges_2cycle = [
        CausalTraceEdge("A", "B", "triggers", "explicit"),
        CausalTraceEdge("B", "A", "triggers", "explicit"),
    ]
    assert detect_cycles(edges_2cycle) is True

    # 5. 3-node cycle: A -> B -> C -> A
    edges_3cycle = [
        CausalTraceEdge("A", "B", "triggers", "explicit"),
        CausalTraceEdge("B", "C", "triggers", "explicit"),
        CausalTraceEdge("C", "A", "triggers", "explicit"),
    ]
    assert detect_cycles(edges_3cycle) is True


def test_receipt_store_causal_links_and_cycle_prevention(tmp_path: Path) -> None:
    """ReceiptStore stores typed causal links and rejects additions that introduce cycles."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)

    link1 = CausalLink(
        link_id=generate_link_id(),
        link_version="1",
        source_id="cr_step_2",
        source_type="crossing",
        relation="caused_by",  # causal direction: target (cr_step_1) -> source (cr_step_2)
        target_id="cr_step_1",
        target_type="crossing",
        created_at="2026-11-16T15:00:00.000Z",
    )
    store.record_causal_link(link1)
    assert store.count_causal_links() == 1

    # Fetch and list
    fetched = store.get_causal_link(link1.link_id)
    assert fetched is not None
    assert fetched.source_id == "cr_step_2"
    assert fetched.target_id == "cr_step_1"

    listed = store.list_causal_links("cr_step_1")
    assert len(listed) == 1
    assert listed[0].link_id == link1.link_id

    # Add cr_step_3 caused_by cr_step_2 (cr_step_1 -> cr_step_2 -> cr_step_3)
    link2 = CausalLink(
        link_id=generate_link_id(),
        link_version="1",
        source_id="cr_step_3",
        source_type="crossing",
        relation="caused_by",
        target_id="cr_step_2",
        target_type="crossing",
        created_at="2026-11-16T15:01:00.000Z",
    )
    store.record_causal_link(link2)
    assert store.count_causal_links() == 2

    # Attempting to add cr_step_1 caused_by cr_step_3 would create a cycle:
    # cr_step_3 -> cr_step_1, but we already have cr_step_1 -> cr_step_2 -> cr_step_3!
    cyclic_link = CausalLink(
        link_id=generate_link_id(),
        link_version="1",
        source_id="cr_step_1",
        source_type="crossing",
        relation="caused_by",
        target_id="cr_step_3",
        target_type="crossing",
        created_at="2026-11-16T15:02:00.000Z",
    )
    with pytest.raises(CycleDetectedError):
        store.record_causal_link(cyclic_link)

    # Store count remains 2
    assert store.count_causal_links() == 2

    # Delete link
    deleted = store.delete_causal_link(link1.link_id)
    assert deleted is True
    assert store.count_causal_links() == 1


def test_build_causal_trace_intrinsic_lifecycle(tmp_path: Path) -> None:
    """build_causal_trace reconstructs full proposal -> decision -> outcome -> observation."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_STARTER_POLICY)
    _ = Boundary(policy=pack, receipt_store=store)

    # 1. Propose & record ALLOW crossing
    env = build_envelope(
        tool="fs",
        verb="read",
        resource="path:C:/workspace/notes.txt",
        params={},
        session_id="sess_001",
        agent_id="agent_writer",
    )
    decision = Decision(
        canonical_hash=env.canonical_hash,
        verdict=Verdict.ALLOW,
        rule_id="allow-read",
        reason="Reading workspace notes",
        policy_version="1",
    )
    store.record_decision(env, decision)
    store.record_outcome(
        crossing_id=env.crossing_id,
        session_id=env.session_id,
        canonical_hash=env.canonical_hash,
        policy_version="1",
        status="success",
        result_hash="sha256:" + "a" * 64,
    )

    # 2. Record state observation linked to crossing
    obs = build_observation(
        subject_resource="path:C:/workspace/notes.txt",
        claim="exists",
        status="verified",
        crossing_id=env.crossing_id,
        verifier_id="actentra.verifier.fs.v1",
    )
    store.record_observation(obs)

    # 3. Build trace for crossing_id
    trace = build_causal_trace(store, env.crossing_id)
    assert trace.root_id == env.crossing_id
    assert trace.root_type == "crossing"
    assert trace.dag_verified is True
    assert len(trace.missing_references) == 0

    # Verify nodes
    node_roles = [n.role for n in trace.nodes]
    assert "proposal" in node_roles
    assert "decision" in node_roles
    assert "outcome" in node_roles
    assert "observation" in node_roles

    # Verify edges
    edge_relations = [e.relation for e in trace.edges]
    assert "evaluates_to" in edge_relations
    assert "executes_to" in edge_relations
    assert "verified_by" in edge_relations

    # Verify timeline sequence: proposal -> decision -> outcome -> observation
    timeline_roles = [t.role for t in trace.timeline]
    assert timeline_roles == ["proposal", "decision", "outcome", "observation"]

    # Verify ASCII rendering contains key elements
    rendered = trace.render_ascii()
    assert "Actentra Causal Trace" in rendered
    assert "PROPOSAL" in rendered
    assert "DECISION" in rendered
    assert "OUTCOME" in rendered
    assert "OBSERVATION" in rendered
    assert "DAG Verified: True" in rendered


def test_build_causal_trace_with_approval_and_task_links(tmp_path: Path) -> None:
    """build_causal_trace handles human approval gating and explicit task links."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_STARTER_POLICY)
    _ = Boundary(policy=pack, receipt_store=store)

    # 1. Propose ASK delete crossing
    env = build_envelope(
        tool="fs",
        verb="delete",
        resource="path:C:/workspace/obsolete.txt",
        params={},
        session_id="sess_002",
        agent_id="agent_cleanup",
    )
    decision = Decision(
        canonical_hash=env.canonical_hash,
        verdict=Verdict.ASK,
        rule_id="ask-delete",
        reason="Requires operator approval",
        policy_version="1",
    )
    store.record_decision(env, decision)
    store.add_pending_approval(envelope=env, decision=decision, ttl_seconds=300.0)

    # Resolve approval
    store.resolve_pending_approval(env.crossing_id, approved=True)
    # Record outcome
    store.record_outcome(
        crossing_id=env.crossing_id,
        session_id=env.session_id,
        canonical_hash=env.canonical_hash,
        policy_version="1",
        status="success",
        result_hash="sha256:" + "b" * 64,
    )

    # 2. Add explicit causal link linking crossing to parent task
    link = CausalLink(
        link_id=generate_link_id(),
        link_version="1",
        source_id=env.crossing_id,
        source_type="crossing",
        relation="part_of",
        target_id="task_workspace_cleanup",
        target_type="task",
        created_at="2026-11-16T15:00:00.000Z",
    )
    store.record_causal_link(link)

    # 3. Build trace from crossing_id
    trace = build_causal_trace(store, env.crossing_id)
    assert trace.dag_verified is True
    node_roles = [n.role for n in trace.nodes]
    assert "approval" in node_roles
    assert "task" in node_roles

    # 4. Build trace from task_workspace_cleanup
    task_trace = build_causal_trace(store, "task_workspace_cleanup")
    assert task_trace.root_id == "task_workspace_cleanup"
    assert task_trace.root_type == "task"
    assert any(n.node_id == f"{env.crossing_id}:proposal" for n in task_trace.nodes)


def test_causal_trace_http_endpoints(tmp_path: Path) -> None:
    """HTTP endpoints expose trace retrieval, link creation, and cycle prevention."""
    db_file = tmp_path / "receipts.db"
    store = ReceiptStore(db_file)
    pack = load_policy_yaml(_STARTER_POLICY)
    boundary = Boundary(policy=pack, receipt_store=store)
    services = AppServices(boundary)

    # 1. POST /v1/trace/links (create explicit link)
    code, created_link = _dispatch_handler(
        services,
        "/v1/trace/links",
        method="POST",
        data={
            "source_id": "cr_002",
            "source_type": "crossing",
            "relation": "caused_by",
            "target_id": "cr_001",
            "target_type": "crossing",
            "metadata": {"reason": "chained step"},
        },
    )
    assert code == 201
    assert created_link["source_id"] == "cr_002"
    assert created_link["target_id"] == "cr_001"
    link_id = created_link["link_id"]

    # 2. GET /v1/trace/links
    code, list_resp = _dispatch_handler(services, "/v1/trace/links?entity_id=cr_001")
    assert code == 200
    assert list_resp["count"] == 1
    assert list_resp["items"][0]["link_id"] == link_id

    # 3. POST /v1/trace/links introducing a cycle -> 400 Bad Request
    code, err_resp = _dispatch_handler(
        services,
        "/v1/trace/links",
        method="POST",
        data={
            "source_id": "cr_001",
            "source_type": "crossing",
            "relation": "caused_by",
            "target_id": "cr_002",
            "target_type": "crossing",
        },
    )
    assert code == 400
    assert err_resp.get("code") == "cycle_detected"

    # 4. GET /v1/trace/cr_002
    code, trace_resp = _dispatch_handler(services, "/v1/trace/cr_002")
    assert code == 200
    assert trace_resp["root_id"] == "cr_002"
    assert trace_resp["dag_verified"] is True

    # 5. Export bundle includes causal_links
    bundle = services.export_audit_bundle()
    assert "causal_links" in bundle
    assert len(bundle["causal_links"]) == 1

    # 6. DELETE /v1/trace/links/{link_id}
    del_code, del_resp = _dispatch_handler(services, f"/v1/trace/links/{link_id}", method="DELETE")
    assert del_code == 200
    assert del_resp["deleted"] is True


def test_causal_trace_cli_commands(tmp_path: Path) -> None:
    """CLI commands 'actentra trace link', 'list', 'show', and 'delete' operate correctly."""
    db_file = tmp_path / "cli_receipts.db"

    # 1. Create a link via CLI
    res_link = runner.invoke(
        app,
        [
            "trace",
            "link",
            "cr_step_2",
            "caused_by",
            "cr_step_1",
            "--db",
            str(db_file),
        ],
    )
    assert res_link.exit_code == 0
    assert "Created causal link lnk_" in res_link.stdout

    # 2. List links via CLI
    res_list = runner.invoke(app, ["trace", "list", "--db", str(db_file)])
    assert res_list.exit_code == 0
    assert "cr_step_2" in res_list.stdout
    assert "cr_step_1" in res_list.stdout

    # Extract link ID from output
    link_id = res_list.stdout.split("[")[1].split("]")[0]

    # 3. Show trace via CLI
    res_show = runner.invoke(app, ["trace", "show", "cr_step_2", "--db", str(db_file)])
    assert res_show.exit_code == 0
    assert "Actentra Causal Trace" in res_show.stdout

    # Show trace in JSON mode
    res_show_json = runner.invoke(
        app, ["trace", "show", "cr_step_2", "--db", str(db_file), "--json"]
    )
    assert res_show_json.exit_code == 0
    parsed = json.loads(res_show_json.stdout)
    assert parsed["root_id"] == "cr_step_2"

    # 4. Attempt cyclic link via CLI -> exit code 1
    res_cycle = runner.invoke(
        app,
        [
            "trace",
            "link",
            "cr_step_1",
            "caused_by",
            "cr_step_2",
            "--db",
            str(db_file),
        ],
    )
    assert res_cycle.exit_code == 1
    assert "Cycle detected" in res_cycle.stdout or "Cycle detected" in res_cycle.stderr

    # 5. Delete link via CLI
    res_del = runner.invoke(app, ["trace", "delete", link_id, "--db", str(db_file)])
    assert res_del.exit_code == 0
    assert f"Deleted causal link '{link_id}'" in res_del.stdout
