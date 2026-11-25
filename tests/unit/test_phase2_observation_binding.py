"""Adversarial & integration tests for Phase 2 external evidence and observation binding."""

from __future__ import annotations

import concurrent.futures
import hashlib
import io
import json
import sqlite3
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from actentra.boundary import Boundary
from actentra_core.evidence import EvidenceTier, build_evidence_record
from actentra_core.identity import CallerContext, PrincipalType
from actentra_core.observations import build_observation
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_gateway.http_service import ActentraHTTPHandler
from actentra_gateway.services import AppServices, ExecutorRegistry

_POLICY_YAML = """
version: 1
policy_id: test-phase2-obs-binding
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-write-digest
    match: { tool: fs.write, verb: write }
    verdict: allow
    constraints:
      require_postcondition: true
      postcondition: digest_match
  - id: allow-delete-absent
    match: { tool: fs.delete, verb: delete }
    verdict: allow
    constraints:
      require_postcondition: true
      postcondition: absent
  - id: allow-restricted-verifier
    match: { tool: custom.restricted, verb: exec }
    verdict: allow
    constraints:
      require_postcondition: true
      postcondition: exists
      allowed_verifiers: ["verifier-trusted"]
"""


def _sha256(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _make_env(
    tmp_path: Path,
    policy_yaml: str = _POLICY_YAML,
) -> tuple[Path, ReceiptStore, AppServices, CallerContext, CallerContext]:
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    db_path = tmp_path / "receipts.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(policy_yaml)
    boundary = Boundary(policy=policy, receipt_store=store, agent_id="agent-1")
    registry = ExecutorRegistry()
    registry.register_fs(ws)
    services = AppServices(boundary, executor_registry=registry)

    executor_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="executor-1",
        authenticated=True,
        trust_domain="local",
        scopes=("crossings:submit", "crossings:claim", "crossings:outcome"),
        allowed_agents=("agent-1",),
    )
    verifier_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="verifier-1",
        authenticated=True,
        trust_domain="local",
        scopes=("observations:verify", "observations:read"),
        allowed_agents=("agent-1",),
    )
    return ws, store, services, executor_ctx, verifier_ctx


def _dispatch_http(
    services: AppServices,
    path: str,
    method: str = "POST",
    data: Any = None,
    *,
    auth_token: str | None = None,
    token_principals: dict[str, Any] | None = None,
    bearer: str | None = None,
) -> tuple[int, Any]:
    handler = ActentraHTTPHandler.__new__(ActentraHTTPHandler)
    server_mock = MagicMock()
    server_mock.services = services
    server_mock.auth_token = auth_token
    server_mock.token_principals = token_principals
    server_mock.boundary = services.boundary
    server_mock.allowed_hosts = ()
    handler.server = server_mock
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.close_connection = True
    handler.path = path
    handler.wfile = io.BytesIO()

    body_bytes = json.dumps(data).encode("utf-8") if data is not None else b""
    headers: dict[str, str] = {
        "Content-Length": str(len(body_bytes)),
        "Content-Type": "application/json",
        "Origin": "http://127.0.0.1:8080",
    }
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    handler.headers = headers  # type: ignore[assignment]
    handler.rfile = io.BytesIO(body_bytes)

    if method == "POST":
        handler.do_POST()
    elif method == "GET":
        handler.do_GET()
    else:
        raise ValueError(method)

    raw_output = handler.wfile.getvalue().decode("utf-8")
    status_code = int(raw_output.splitlines()[0].split()[1])
    parts = raw_output.split("\r\n\r\n", 1)
    body_str = parts[1] if len(parts) > 1 else ""
    try:
        parsed_body = json.loads(body_str)
    except Exception:
        parsed_body = body_str
    return status_code, parsed_body


def _submit_write_crossing(
    services: AppServices,
    target_path: Path,
    content: str = "expected content",
    session_id: str = "s1",
) -> str:
    res_str = f"path:{target_path.as_posix()}"
    sub = services.submit_crossing(
        {
            "tool": "fs.write",
            "verb": "write",
            "resource": res_str,
            "params": {"path": target_path.as_posix(), "content": content},
            "session_id": session_id,
            "agent": {"id": "agent-1"},
        },
        execute=False,
    )
    assert sub["verdict"] == "allow"
    return str(sub["crossing_id"])


def test_audit_attack_unrelated_resource_rejected_http_and_service(tmp_path: Path) -> None:
    """Reproduce exact audit attack: unrelated observation must not verify required.txt."""
    ws, store, services, exec_ctx, ver_ctx = _make_env(tmp_path)
    required = ws / "required.txt"
    unrelated = ws / "other.txt"
    unrelated.write_text("decoy", encoding="utf-8")

    cid = _submit_write_crossing(services, required, content="secret payload")
    claim = services.claim_crossing_for_execution(cid, caller_context=exec_ctx)
    claim_id = claim["claim_id"]

    # Attack 1: Direct service call with unrelated resource
    obs_res = services.verify_state(
        f"path:{unrelated.as_posix()}",
        "exists",
        crossing_id=cid,
        claim_id=claim_id,
        caller_context=ver_ctx,
    )
    assert obs_res["status"] == "error"
    assert obs_res["code"] == "resource_mismatch"

    # Attack 2: HTTP /v1/observations/verify with unrelated resource
    tp = {
        "tok-exec": exec_ctx,
        "tok-ver": ver_ctx,
    }
    code, http_obs = _dispatch_http(
        services,
        "/v1/observations/verify",
        data={
            "resource": f"path:{unrelated.as_posix()}",
            "claim": "digest_match",
            "crossing_id": cid,
            "claim_id": claim_id,
            "expected_digest": _sha256("secret payload"),
        },
        auth_token="tok-exec",
        token_principals=tp,
        bearer="tok-ver",
    )
    assert code == 400
    assert http_obs["code"] == "resource_mismatch"

    # Attack 3: Unbound observation (crossing_id=None) on unrelated resource
    unbound = services.verify_state(
        f"path:{unrelated.as_posix()}",
        "exists",
        caller_context=ver_ctx,
    )
    assert unbound["status"] == "verified"

    # Outcome promotion must be rejected
    code_out, out_http = _dispatch_http(
        services,
        f"/v1/crossings/{cid}/outcome",
        data={
            "status": "success",
            "claim_id": claim_id,
            "observation_id": unbound["observation_id"],
        },
        auth_token="tok-exec",
        token_principals=tp,
        bearer="tok-exec",
    )
    assert code_out == 400
    assert out_http["code"] == "unverified_postcondition"
    assert store.get_outcome_receipt(cid) is None


def test_different_crossing_and_different_claim_rejected(tmp_path: Path) -> None:
    """Observation bound to crossing A / claim A cannot finalize crossing B / claim B."""
    ws, store, services, exec_ctx, ver_ctx = _make_env(tmp_path)
    file_a = ws / "a.txt"
    file_b = ws / "b.txt"
    file_a.write_text("alpha", encoding="utf-8")
    file_b.write_text("beta", encoding="utf-8")

    cid_a = _submit_write_crossing(services, file_a, content="alpha")
    cid_b = _submit_write_crossing(services, file_b, content="beta")

    claim_a = services.claim_crossing_for_execution(cid_a, caller_context=exec_ctx)["claim_id"]
    claim_b = services.claim_crossing_for_execution(cid_b, caller_context=exec_ctx)["claim_id"]

    obs_a = services.verify_state(
        f"path:{file_a.as_posix()}",
        "digest_match",
        crossing_id=cid_a,
        claim_id=claim_a,
        expected_digest=_sha256("alpha"),
        caller_context=ver_ctx,
    )
    assert obs_a["status"] == "verified"

    # Cannot use obs_a for crossing B
    out_b = services.record_external_outcome(
        cid_b,
        status="success",
        claim_id=claim_b,
        observation_id=obs_a["observation_id"],
        caller_context=exec_ctx,
    )
    assert out_b["code"] == "unverified_postcondition"
    assert store.get_outcome_receipt(cid_b) is None

    # Cannot verify crossing B using claim A
    bad_ver = services.verify_state(
        f"path:{file_b.as_posix()}",
        "digest_match",
        crossing_id=cid_b,
        claim_id=claim_a,
        expected_digest=_sha256("beta"),
        caller_context=ver_ctx,
    )
    assert bad_ver["status"] == "error"
    assert bad_ver["code"] == "claim_crossing_mismatch"


def test_digest_mismatch_and_missing_digest_rejected(tmp_path: Path) -> None:
    """Digest verification rejects wrong file content, wrong expected_digest, and weak claims."""
    ws, store, services, exec_ctx, ver_ctx = _make_env(tmp_path)
    target = ws / "doc.txt"
    target.write_text("wrong content", encoding="utf-8")

    cid = _submit_write_crossing(services, target, content="expected content")
    claim_id = services.claim_crossing_for_execution(cid, caller_context=exec_ctx)["claim_id"]

    # 1. Weak claim ('exists') rejected for write under strict postconditions
    weak = services.verify_state(
        f"path:{target.as_posix()}",
        "exists",
        crossing_id=cid,
        claim_id=claim_id,
        caller_context=ver_ctx,
    )
    assert weak["status"] == "error"
    assert weak["code"] == "postcondition_mismatch"

    # 2. Caller attempting to override expected_digest to match wrong content is rejected
    override = services.verify_state(
        f"path:{target.as_posix()}",
        "digest_match",
        crossing_id=cid,
        claim_id=claim_id,
        expected_digest=_sha256("wrong content"),
        caller_context=ver_ctx,
    )
    assert override["status"] == "error"
    assert override["code"] == "digest_mismatch"

    # 3. Legitimate verification against actual wrong content -> refuted
    obs = services.verify_state(
        f"path:{target.as_posix()}",
        "digest_match",
        crossing_id=cid,
        claim_id=claim_id,
        caller_context=ver_ctx,
    )
    assert obs["status"] == "refuted"

    out = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        caller_context=exec_ctx,
    )
    assert out["code"] == "unverified_postcondition"
    assert store.get_outcome_receipt(cid) is None


def test_expired_and_replayed_observation_rejected(tmp_path: Path) -> None:
    """Expired observations and already-consumed observations cannot be reused."""
    ws, store, services, exec_ctx, ver_ctx = _make_env(tmp_path)
    target = ws / "fresh.txt"
    target.write_text("fresh", encoding="utf-8")

    cid = _submit_write_crossing(services, target, content="fresh")
    claim_id = services.claim_crossing_for_execution(cid, caller_context=exec_ctx)["claim_id"]

    # 1. Expired observation
    obs_exp = services.verify_state(
        f"path:{target.as_posix()}",
        "digest_match",
        crossing_id=cid,
        claim_id=claim_id,
        ttl_seconds=0.01,
        caller_context=ver_ctx,
    )
    assert obs_exp["status"] == "verified"
    time.sleep(0.05)

    out_exp = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        observation_id=obs_exp["observation_id"],
        caller_context=exec_ctx,
    )
    assert out_exp["code"] == "unverified_postcondition"
    assert "expired" in out_exp["error"].lower()

    # 2. Fresh observation succeeds once, then replay on another crossing/claim fails
    obs_ok = services.verify_state(
        f"path:{target.as_posix()}",
        "digest_match",
        crossing_id=cid,
        claim_id=claim_id,
        ttl_seconds=60.0,
        caller_context=ver_ctx,
    )
    assert obs_ok["status"] == "verified"

    out_ok = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        observation_id=obs_ok["observation_id"],
        caller_context=exec_ctx,
    )
    assert out_ok["status"] == "recorded"
    assert out_ok["externally_verified"] is True
    assert out_ok["evidence_tier"] == "externally_verified"

    # Second crossing cannot replay obs_ok
    cid2 = _submit_write_crossing(services, target, content="fresh", session_id="s2")
    claim2 = services.claim_crossing_for_execution(cid2, caller_context=exec_ctx)["claim_id"]
    out_replay = services.record_external_outcome(
        cid2,
        status="success",
        claim_id=claim2,
        observation_id=obs_ok["observation_id"],
        caller_context=exec_ctx,
    )
    assert out_replay["code"] == "unverified_postcondition"
    assert "consumed" in out_replay["error"].lower()


def test_forged_evidence_generic_claim_and_wrong_verifier_rejected(tmp_path: Path) -> None:
    """Forged EvidenceRecord, generic 'verified' claim, and unauthorized verifier are rejected."""
    ws, store, services, exec_ctx, ver_ctx = _make_env(tmp_path)
    target = ws / "forged.txt"
    target.write_text("ok", encoding="utf-8")

    cid = _submit_write_crossing(services, target, content="ok")
    claim_id = services.claim_crossing_for_execution(cid, caller_context=exec_ctx)["claim_id"]

    # 1. Inject forged EXTERNALLY_VERIFIED EvidenceRecord without bound ObservationRecord
    forged_ev = build_evidence_record(
        crossing_id=cid,
        tier=EvidenceTier.EXTERNALLY_VERIFIED,
        trust_domain="verifier:workspace",
        collector="caller:forged",
        details={"status": "verified"},
    )
    store.record_evidence(forged_ev)

    out_forged = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        caller_context=exec_ctx,
    )
    assert out_forged["code"] == "unverified_postcondition"

    # 2. Inject ObservationRecord with generic claim 'verified' and untrusted producer
    forged_obs = build_observation(
        subject_resource=f"path:{target.as_posix()}",
        claim="verified",
        status="verified",
        verifier_id="llm:self-report",
        crossing_id=cid,
        claim_id=claim_id,
    )
    store.record_observation(forged_obs)
    out_generic = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        observation_id=forged_obs.observation_id,
        caller_context=exec_ctx,
    )
    assert out_generic["code"] == "unverified_postcondition"

    # 3. Caller without observations:verify scope is rejected
    no_scope_ctx = CallerContext(
        principal_type=PrincipalType.AUTHENTICATED_AGENT,
        principal_id="unprivileged",
        authenticated=True,
        trust_domain="local",
        scopes=("observations:read",),
        allowed_agents=("agent-1",),
    )
    denied = services.verify_state(
        f"path:{target.as_posix()}",
        "digest_match",
        crossing_id=cid,
        claim_id=claim_id,
        caller_context=no_scope_ctx,
    )
    assert denied["code"] == "forbidden"

    # 4. Restricted verifier constraint
    sub_r = services.submit_crossing(
        {
            "tool": "custom.restricted",
            "verb": "exec",
            "resource": f"path:{target.as_posix()}",
            "session_id": "s-r",
            "agent": {"id": "agent-1"},
        },
        execute=False,
    )
    cid_r = sub_r["crossing_id"]
    claim_r = services.claim_crossing_for_execution(cid_r, caller_context=exec_ctx)["claim_id"]
    wrong_ver = services.verify_state(
        f"path:{target.as_posix()}",
        "exists",
        crossing_id=cid_r,
        claim_id=claim_r,
        caller_context=ver_ctx,
    )
    assert wrong_ver["code"] == "forbidden"


def test_tampered_observation_and_action_hash_rejected(tmp_path: Path) -> None:
    """Modifying observation or action hash in DB after verification fails integrity/binding."""
    ws, store, services, exec_ctx, ver_ctx = _make_env(tmp_path)
    target = ws / "tamper.txt"
    target.write_text("clean", encoding="utf-8")

    cid = _submit_write_crossing(services, target, content="clean")
    claim_id = services.claim_crossing_for_execution(cid, caller_context=exec_ctx)["claim_id"]
    obs = services.verify_state(
        f"path:{target.as_posix()}",
        "digest_match",
        crossing_id=cid,
        claim_id=claim_id,
        caller_context=ver_ctx,
    )
    assert obs["status"] == "verified"

    # Tamper with canonical_action_hash directly in SQLite
    conn = sqlite3.connect(store.db_path)
    conn.execute(
        "UPDATE observations SET canonical_action_hash = ? WHERE observation_id = ?;",
        ("sha256:" + "0" * 64, obs["observation_id"]),
    )
    conn.commit()
    conn.close()

    out = services.record_external_outcome(
        cid,
        status="success",
        claim_id=claim_id,
        observation_id=obs["observation_id"],
        caller_context=exec_ctx,
    )
    assert out["code"] == "unverified_postcondition"
    assert store.get_outcome_receipt(cid) is None


def test_concurrent_outcome_submissions_single_winner(tmp_path: Path) -> None:
    """Concurrent outcome submissions cannot reuse an observation or claim."""
    ws, store, services, exec_ctx, ver_ctx = _make_env(tmp_path)
    target = ws / "race.txt"
    target.write_text("race-data", encoding="utf-8")

    cid = _submit_write_crossing(services, target, content="race-data")
    claim_id = services.claim_crossing_for_execution(cid, caller_context=exec_ctx)["claim_id"]
    obs = services.verify_state(
        f"path:{target.as_posix()}",
        "digest_match",
        crossing_id=cid,
        claim_id=claim_id,
        caller_context=ver_ctx,
    )
    assert obs["status"] == "verified"

    def _attempt() -> dict[str, Any]:
        return services.record_external_outcome(
            cid,
            status="success",
            claim_id=claim_id,
            observation_id=obs["observation_id"],
            caller_context=exec_ctx,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: _attempt(), range(4)))

    successes = [r for r in results if r.get("status") == "recorded"]
    failures = [r for r in results if "error" in r]
    assert len(successes) == 1
    assert len(failures) == 3


def test_end_to_end_http_bound_verification_and_outcome_success(tmp_path: Path) -> None:
    """Legitimate HTTP workflow: submit -> claim -> verify -> outcome succeeds."""
    ws, store, services, exec_ctx, ver_ctx = _make_env(tmp_path)
    target = ws / "required.txt"
    content = "verified artifact content"
    target.write_text(content, encoding="utf-8")

    cid = _submit_write_crossing(services, target, content=content)
    claim_id = services.claim_crossing_for_execution(cid, caller_context=exec_ctx)["claim_id"]

    tp = {"tok-exec": exec_ctx, "tok-ver": ver_ctx}
    code_v, obs = _dispatch_http(
        services,
        "/v1/observations/verify",
        data={
            "resource": f"path:{target.as_posix()}",
            "claim": "digest_match",
            "crossing_id": cid,
            "claim_id": claim_id,
        },
        auth_token="tok-exec",
        token_principals=tp,
        bearer="tok-ver",
    )
    assert code_v == 200
    assert obs["status"] == "verified"
    assert obs["verification_id"].startswith("ver_")
    assert obs["verification_context_hash"].startswith("sha256:")
    assert obs["executor_principal_id"] == "executor-1"
    assert obs["verifier_principal_id"] == "verifier-1"

    code_o, out = _dispatch_http(
        services,
        f"/v1/crossings/{cid}/outcome",
        data={
            "status": "success",
            "claim_id": claim_id,
            "observation_id": obs["observation_id"],
        },
        auth_token="tok-exec",
        token_principals=tp,
        bearer="tok-exec",
    )
    assert code_o == 200
    assert out["status"] == "recorded"
    assert out["externally_verified"] is True
    assert out["evidence_tier"] == "externally_verified"
    assert out["observation_id"] == obs["observation_id"]
    assert out["verification_id"] == obs["verification_id"]
