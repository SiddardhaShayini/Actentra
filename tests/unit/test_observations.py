"""Tests for Phase 2 verifiable state observations and WorkspaceFileVerifier."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from typer.testing import CliRunner

from actentra.boundary import Boundary
from actentra_cli.main import app
from actentra_core.observations import (
    ObservationRecord,
    build_observation,
)
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore
from actentra_executors.verifiers import WorkspaceFileVerifier
from actentra_gateway.http_service import ActentraHTTPHandler
from actentra_gateway.services import AppServices, ExecutorRegistry

runner = CliRunner()


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


def test_observation_record_integrity_and_hashing() -> None:
    """ObservationRecord binds its fields cryptographically to detect tampering."""
    obs = build_observation(
        subject_resource="path:C:/work/test.txt",
        claim="exists",
        status="verified",
        verifier_id="actentra.verifier.fs.v1",
        verifier_version="1.0.0",
        trust_domain="local_host",
        observed_digest="sha256:" + ("a" * 64),
        metadata={"size_bytes": 100},
    )
    assert obs.verify_integrity() is True

    # Tampering with status must fail integrity check
    tampered = ObservationRecord(
        observation_id=obs.observation_id,
        observation_version=obs.observation_version,
        crossing_id=obs.crossing_id,
        subject_resource=obs.subject_resource,
        claim=obs.claim,
        status="refuted",  # Tampered!
        observed_digest=obs.observed_digest,
        observed_at=obs.observed_at,
        expires_at=obs.expires_at,
        verifier_id=obs.verifier_id,
        verifier_version=obs.verifier_version,
        trust_domain=obs.trust_domain,
        metadata=obs.metadata,
        error=obs.error,
        observation_hash=obs.observation_hash,
    )
    assert tampered.verify_integrity() is False


def test_observation_freshness_and_expiry() -> None:
    """Observations have explicit freshness bounds."""
    obs = build_observation(
        subject_resource="path:C:/work/data.json",
        claim="exists",
        status="verified",
        verifier_id="actentra.verifier.fs.v1",
        expires_at="2026-11-16T15:00:00.000Z",
    )
    # Check freshness relative to timestamps
    # 2026-11-16T15:00:00.000Z is 1794841200.0
    assert obs.is_fresh(now=1794845000.0) is False  # after expires_at -> not fresh
    assert obs.is_fresh(now=1794837600.0) is True  # before expires_at -> fresh


def test_workspace_file_verifier_claims(tmp_path: Path) -> None:
    """WorkspaceFileVerifier checks existence, non-existence, and digest match."""
    ws = tmp_path / "ws"
    ws.mkdir()
    target = ws / "artifact.txt"
    target.write_text("verifiable state content\n", encoding="utf-8")

    verifier = WorkspaceFileVerifier(ws, default_ttl_seconds=30.0)

    # 1. Claim: exists on existing file -> verified
    obs_exists = verifier.verify("path:artifact.txt", "exists")
    assert obs_exists.status == "verified"
    assert obs_exists.observed_digest is not None
    assert obs_exists.metadata["exists"] is True
    assert obs_exists.trust_domain == "local_host"
    assert obs_exists.is_fresh() is True

    # 2. Claim: exists on missing file -> refuted
    obs_missing = verifier.verify("path:absent.txt", "exists")
    assert obs_missing.status == "refuted"
    assert obs_missing.observed_digest is None
    assert obs_missing.metadata["exists"] is False

    # 3. Claim: absent on missing file -> verified
    obs_absent_ok = verifier.verify("path:absent.txt", "absent")
    assert obs_absent_ok.status == "verified"

    # 4. Claim: absent on existing file -> refuted
    obs_absent_bad = verifier.verify("path:artifact.txt", "absent")
    assert obs_absent_bad.status == "refuted"

    # 5. Claim: digest_match matching digest -> verified
    expected_dig = obs_exists.observed_digest
    obs_match = verifier.verify("path:artifact.txt", "digest_match", expected_digest=expected_dig)
    assert obs_match.status == "verified"

    # 6. Claim: digest_match wrong digest -> refuted
    obs_mismatch = verifier.verify(
        "path:artifact.txt", "digest_match", expected_digest="sha256:" + ("0" * 64)
    )
    assert obs_mismatch.status == "refuted"

    # 7. Path traversal escape attempt -> error
    obs_escape = verifier.verify(r"path:..\..\outside.txt", "exists")
    assert obs_escape.status == "error"
    assert "outside workspace" in str(obs_escape.error).lower()


def test_sqlite_persistence_and_restart(tmp_path: Path) -> None:
    """Observations survive SQLite store restart and maintain integrity."""
    db_path = tmp_path / "obs.db"
    store1 = ReceiptStore(db_path)

    obs1 = build_observation(
        subject_resource="path:C:/app/config.yaml",
        claim="exists",
        status="verified",
        verifier_id="actentra.verifier.fs.v1",
        crossing_id="01M7HVP4RDGZ8KJAS4DCPN1ZGR",
        observed_digest="sha256:" + ("b" * 64),
        metadata={"size_bytes": 512},
    )
    store1.record_observation(obs1)

    # Recreate store on same database
    del store1
    store2 = ReceiptStore(db_path)

    fetched = store2.get_observation(obs1.observation_id)
    assert fetched is not None
    assert fetched.observation_id == obs1.observation_id
    assert fetched.status == "verified"
    assert fetched.verify_integrity() is True
    assert fetched.crossing_id == "01M7HVP4RDGZ8KJAS4DCPN1ZGR"

    latest = store2.get_latest_observation(obs1.subject_resource)
    assert latest is not None
    assert latest.observation_id == obs1.observation_id

    assert store2.count_observations() == 1


def test_state_drift_detection(tmp_path: Path) -> None:
    """Drift is captured as distinct chronological observation records."""
    ws = tmp_path / "drift_ws"
    ws.mkdir()
    f = ws / "mutable.txt"
    f.write_text("version 1\n", encoding="utf-8")

    db_path = tmp_path / "drift.db"
    store = ReceiptStore(db_path)
    verifier = WorkspaceFileVerifier(ws)

    # Observation 1: file exists with version 1 content
    obs1 = verifier.verify("path:mutable.txt", "exists")
    assert obs1.status == "verified"
    store.record_observation(obs1)

    # State modification outside Actentra
    f.write_text("version 2 modified\n", encoding="utf-8")

    # Observation 2: same claim against modified state produces different digest
    obs2 = verifier.verify("path:mutable.txt", "exists")
    assert obs2.status == "verified"
    assert obs2.observed_digest != obs1.observed_digest
    store.record_observation(obs2)

    # File deleted outside Actentra
    f.unlink()

    # Observation 3: same claim now produces refuted
    obs3 = verifier.verify("path:mutable.txt", "exists")
    assert obs3.status == "refuted"
    store.record_observation(obs3)

    # All three chronological observations are persisted
    history = store.list_observations(subject_resource=obs1.subject_resource)
    assert len(history) == 3
    assert history[0].status == "refuted"  # Latest
    assert history[1].status == "verified"  # Middle (version 2)
    assert history[2].status == "verified"  # First (version 1)


def test_http_observation_endpoints(tmp_path: Path) -> None:
    """HTTP gateway provides verify, list, and detail observation routes."""
    ws = tmp_path / "http_obs_ws"
    ws.mkdir()
    (ws / "sample.txt").write_text("sample content\n", encoding="utf-8")

    db_path = tmp_path / "http_obs.db"
    store = ReceiptStore(db_path)
    policy = load_policy_yaml(
        """
version: 1
policy_id: test-obs-http
mode: enforce
defaults: { verdict: deny }
rules:
  - id: allow-reads
    match: { verb: read }
    verdict: allow
"""
    )
    boundary = Boundary(policy=policy, receipt_store=store, session_id="s-obs")
    registry = ExecutorRegistry()
    registry.register_fs(ws)
    services = AppServices(boundary, executor_registry=registry)

    # 1. POST /v1/observations/verify
    code, v_res = _dispatch_handler(
        services,
        "/v1/observations/verify",
        method="POST",
        data={"resource": "path:sample.txt", "claim": "exists"},
    )
    assert code == 200
    assert v_res["status"] == "verified"
    assert v_res["observed_digest"] is not None
    obs_id = v_res["observation_id"]

    # 2. GET /v1/observations
    code, obs_list = _dispatch_handler(services, "/v1/observations", method="GET")
    assert code == 200
    assert len(obs_list) >= 1
    assert obs_list[0]["observation_id"] == obs_id

    # 3. GET /v1/observations/{id}
    code, detail = _dispatch_handler(services, f"/v1/observations/{obs_id}", method="GET")
    assert code == 200
    assert detail["observation_id"] == obs_id
    assert detail["status"] == "verified"

    # 4. GET /v1/observations/nonexistent -> 404
    code, nf = _dispatch_handler(services, "/v1/observations/missing-id", method="GET")
    assert code == 404


def test_cli_observation_commands(tmp_path: Path) -> None:
    """CLI provides verify, list, and show commands for observations."""
    ws = tmp_path / "cli_obs_ws"
    ws.mkdir()
    (ws / "hello.txt").write_text("hello world\n", encoding="utf-8")
    db_path = tmp_path / "cli_obs.db"

    # Verify
    res1 = runner.invoke(
        app,
        [
            "observation",
            "verify",
            "path:hello.txt",
            "--workspace",
            str(ws),
            "--db",
            str(db_path),
            "--claim",
            "exists",
        ],
    )
    assert res1.exit_code == 0
    assert "[VERIFIED]" in res1.output
    assert "digest=sha256:" in res1.output

    # List
    res2 = runner.invoke(app, ["observation", "list", "--db", str(db_path)])
    assert res2.exit_code == 0
    assert "[VERIFIED / FRESH]" in res2.output

    # Extract observation ID from list output
    line = [line for line in res2.output.splitlines() if "id=obs_" in line][0]
    obs_id = line.split("id=")[1].split()[0]

    # Show
    res3 = runner.invoke(app, ["observation", "show", obs_id, "--db", str(db_path)])
    assert res3.exit_code == 0
    assert f'"observation_id": "{obs_id}"' in res3.output
