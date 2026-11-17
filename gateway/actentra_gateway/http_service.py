"""Lightweight, local-first HTTP service and Unified Operator Console for Actentra.

Provides versioned REST APIs for policy evaluation, persistent human approvals,
execution continuation, canary diff simulations, and an embedded offline Web Console.
"""

from __future__ import annotations

import json
import os
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from actentra.boundary import Boundary
from actentra_core.causal import CycleDetectedError
from actentra_core.handoffs import (
    ExpiredHandoffError,
    HandoffError,
    UnauthorizedAgentHandoffError,
)
from actentra_gateway.services import AppServices, ExecutorRegistry

_MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB bound on HTTP request body
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"})


class PendingCrossing:
    """In-memory compatibility view for pending crossings."""

    __slots__ = (
        "crossing_id",
        "session_id",
        "canonical_hash",
        "tool",
        "verb",
        "resource",
        "risk_tags",
        "reason",
        "ts",
        "expires_at",
    )

    def __init__(
        self,
        crossing_id: str,
        session_id: str,
        canonical_hash: str,
        tool: str,
        verb: str,
        resource: str,
        risk_tags: tuple[str, ...],
        reason: str,
        ts: str,
        expires_at: float,
    ) -> None:
        self.crossing_id = crossing_id
        self.session_id = session_id
        self.canonical_hash = canonical_hash
        self.tool = tool
        self.verb = verb
        self.resource = resource
        self.risk_tags = risk_tags
        self.reason = reason
        self.ts = ts
        self.expires_at = expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "crossing_id": self.crossing_id,
            "session_id": self.session_id,
            "canonical_hash": self.canonical_hash,
            "tool": self.tool,
            "verb": self.verb,
            "resource": self.resource,
            "risk_tags": list(self.risk_tags),
            "reason": self.reason,
            "ts": self.ts,
            "expires_in_seconds": max(0.0, round(self.expires_at - time.time(), 1)),
        }


class ActentraHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Actentra REST API and Unified Operator Console."""

    server: ActentraHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default noisy access logs to keep terminal output clean
        pass

    def _check_auth(self) -> bool:
        if not self.server.auth_token:
            return True
        auth_hdr = self.headers.get("Authorization", "")
        expected = f"Bearer {self.server.auth_token}"
        if auth_hdr != expected:
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Unauthorized: missing or invalid Bearer token"},
            )
            return False
        return True

    def _allowed_origin(self) -> str | None:
        origin = self.headers.get("Origin")
        if not origin:
            return None
        clean = origin.strip().lower()
        if (
            clean.startswith("http://127.0.0.1:")
            or clean.startswith("http://localhost:")
            or clean in ("http://127.0.0.1", "http://localhost")
        ):
            return origin
        return None

    def _send_json(self, status: int, payload: dict[str, Any] | list[Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        allowed_origin = self._allowed_origin()
        if allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Actentra-Client",
        )
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html_text: str) -> None:
        body = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any]:
        content_len_header = self.headers.get("Content-Length")
        if not content_len_header:
            raise ValueError("Missing Content-Length header")
        try:
            length = int(content_len_header)
        except ValueError as exc:
            raise ValueError(f"Invalid Content-Length header: {content_len_header!r}") from exc
        if length < 0:
            raise ValueError(f"Negative Content-Length header is invalid: {length}")
        if length > _MAX_BODY_BYTES:
            raise ValueError(f"Request body exceeds {_MAX_BODY_BYTES} bytes limit")
        raw_bytes = self.rfile.read(length)
        parsed = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("JSON request body must be an object")
        return parsed

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        allowed_origin = self._allowed_origin()
        if allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Actentra-Client",
        )
        self.end_headers()

    def do_GET(self) -> None:
        if not self._check_auth():
            return

        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        query = parse_qs(parts.query)
        services = self.server.services

        if path == "/health":
            self._send_json(HTTPStatus.OK, services.get_health())
            return

        if path == "/v1/crossings/pending":
            pending = services.list_pending_approvals(status="pending")
            self._send_json(HTTPStatus.OK, pending)
            return

        if path.startswith("/v1/crossings/") and not path.endswith(
            ("/approve", "/execute", "/outcome")
        ):
            cid = path[len("/v1/crossings/") :]
            detail = services.get_pending_approval(cid)
            if detail is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Crossing '{cid}' not found"})
                return
            self._send_json(HTTPStatus.OK, detail)
            return

        if path == "/v1/receipts":
            query = parse_qs(parts.query)
            try:
                raw_limit = int(query.get("limit", ["50"])[0])
                limit = max(1, min(raw_limit, 500))
            except ValueError:
                limit = 50
            try:
                raw_offset = int(query.get("offset", ["0"])[0])
                offset = max(0, raw_offset)
            except ValueError:
                offset = 0
            verdict = query.get("verdict", [None])[0]
            status_f = query.get("status", [None])[0]
            tool_f = query.get("tool", [None])[0]
            session_f = query.get("session_id", [None])[0]
            search_f = query.get("search", [None])[0]

            resp = services.query_receipts(
                limit=limit,
                offset=offset,
                verdict=verdict,
                status=status_f,
                tool=tool_f,
                session_id=session_f,
                search=search_f,
            )
            # Maintain backward compatibility: if simple query without offset/search, return list
            if "offset" not in query and "search" not in query:
                self._send_json(HTTPStatus.OK, resp["records"])
            else:
                self._send_json(HTTPStatus.OK, resp)
            return

        if path == "/v1/verify":
            self._send_json(HTTPStatus.OK, services.verify_audit_log())
            return

        if path == "/v1/policy":
            self._send_json(HTTPStatus.OK, {"policy_yaml": services.get_policy_yaml()})
            return

        if path == "/v1/policy/lint":
            self._send_json(HTTPStatus.OK, {"warnings": services.lint_active_policy()})
            return

        if path == "/v1/bundle/export":
            bundle = services.export_audit_bundle()
            self._send_json(HTTPStatus.OK, bundle)
            return

        if path == "/v1/observations":
            cid_f = query.get("crossing_id", [None])[0]
            res_f = query.get("resource", [None])[0]
            lim_f = int(query.get("limit", [50])[0])
            off_f = int(query.get("offset", [0])[0])
            obs_list = services.list_observations(
                crossing_id=cid_f,
                subject_resource=res_f,
                limit=lim_f,
                offset=off_f,
            )
            self._send_json(HTTPStatus.OK, obs_list)
            return

        if path.startswith("/v1/observations/") and path != "/v1/observations/verify":
            obs_id = path[len("/v1/observations/") :]
            obs_detail = services.get_observation(obs_id)
            if obs_detail is None:
                self._send_json(
                    HTTPStatus.NOT_FOUND, {"error": f"Observation '{obs_id}' not found"}
                )
            else:
                self._send_json(HTTPStatus.OK, obs_detail)
            return

        if path == "/v1/trace/links":
            ent_f = query.get("entity_id", [None])[0]
            lim_f = int(query.get("limit", [100])[0])
            links = services.list_causal_links(entity_id=ent_f, limit=lim_f)
            self._send_json(HTTPStatus.OK, {"items": links, "count": len(links)})
            return

        if path.startswith("/v1/trace/"):
            trace_id = path[len("/v1/trace/") :]
            trace_data = services.get_causal_trace(trace_id)
            self._send_json(HTTPStatus.OK, trace_data)
            return

        if path == "/v1/handoffs":
            task_f = query.get("task_id", [None])[0]
            agent_f = query.get("assigned_agent_id", [None])[0]
            stat_f = query.get("status", [None])[0]
            lim_f = int(query.get("limit", [50])[0])
            hnds = services.list_task_handoffs(
                task_id=task_f,
                assigned_agent_id=agent_f,
                status=stat_f,
                limit=lim_f,
            )
            self._send_json(HTTPStatus.OK, hnds)
            return

        if path.startswith("/v1/handoffs/") and not path.endswith(("/advance", "/verify")):
            hnd_id = path[len("/v1/handoffs/") :]
            hnd = services.get_task_handoff(hnd_id)
            if hnd is None:
                self._send_json(
                    HTTPStatus.NOT_FOUND, {"error": f"Handoff '{hnd_id}' not found"}
                )
            else:
                self._send_json(HTTPStatus.OK, hnd)
            return

        if path in ("/ui", "/"):
            self._send_html(HTTPStatus.OK, self._render_dashboard_html())
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Route '{path}' not found"})

    def do_POST(self) -> None:
        if not self._check_auth():
            return

        parts = urlsplit(self.path)
        path = parts.path.rstrip("/")
        services = self.server.services

        # Mutating requests require loopback origin if Origin is provided
        origin = self.headers.get("Origin")
        if origin and not self._allowed_origin():
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "Forbidden: cross-origin browser request rejected"},
            )
            return

        if path == "/v1/crossings":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            raw_execute = data.get("execute", False)
            if not isinstance(raw_execute, bool):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Field 'execute' must be a JSON boolean if provided"},
                )
                return
            execute = raw_execute
            resp = services.submit_crossing(data, execute=execute)
            status_code = HTTPStatus.OK if "error" not in resp else HTTPStatus.BAD_REQUEST
            self._send_json(status_code, resp)
            return

        if path.startswith("/v1/crossings/") and path.endswith("/approve"):
            crossing_id = path[len("/v1/crossings/") : -len("/approve")]
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            if "approved" not in data:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Missing required field 'approved'"},
                )
                return

            approved = data["approved"]
            if not isinstance(approved, bool):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Field 'approved' must be a JSON boolean (true or false)"},
                )
                return

            raw_execute = data.get("execute", False)
            if not isinstance(raw_execute, bool):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Field 'execute' must be a JSON boolean if provided"},
                )
                return
            execute = raw_execute

            res = services.resolve_approval(crossing_id, approved=approved, execute=execute)
            if "error" in res:
                self._send_json(HTTPStatus.NOT_FOUND, res)
                return
            self._send_json(HTTPStatus.OK, res)
            return

        if path.startswith("/v1/crossings/") and path.endswith("/execute"):
            crossing_id = path[len("/v1/crossings/") : -len("/execute")]
            res = services.execute_approved_crossing(crossing_id)
            status_code = HTTPStatus.OK if "error" not in res else HTTPStatus.BAD_REQUEST
            self._send_json(status_code, res)
            return

        if path.startswith("/v1/crossings/") and path.endswith("/outcome"):
            crossing_id = path[len("/v1/crossings/") : -len("/outcome")]
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            if "status" not in data:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Missing required field 'status'"},
                )
                return

            status_val = data.get("status")
            if status_val not in ("success", "failure", "unknown"):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Field 'status' must be one of: 'success', 'failure', 'unknown'"},
                )
                return

            res = services.record_external_outcome(
                crossing_id,
                status=status_val,
                result_hash=data.get("result_hash"),
                error=data.get("error"),
            )
            if "error" in res:
                err_msg = str(res.get("error", "")).lower()
                if "already recorded" in err_msg:
                    status_code = HTTPStatus.CONFLICT
                elif "not found" in err_msg:
                    status_code = HTTPStatus.NOT_FOUND
                else:
                    status_code = HTTPStatus.BAD_REQUEST
                self._send_json(status_code, res)
                return

            self._send_json(HTTPStatus.OK, res)
            return

        if path == "/v1/policy/canary":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            cand_yaml = str(data.get("candidate_yaml", ""))
            limit = int(data.get("limit", 100))
            try:
                canary_res = services.run_canary_on_candidate(cand_yaml, limit=limit)
                self._send_json(HTTPStatus.OK, canary_res)
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Canary execution failed: {exc}"},
                )
            return

        if path == "/v1/simulate":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            try:
                sim_res = services.simulate_dry_run(
                    tool=str(data.get("tool", "")),
                    verb=str(data.get("verb", "other")),
                    resource=str(data.get("resource", "")),
                    params=data.get("params"),
                    session_id=str(data.get("session_id", "default")),
                    provenance=data.get("provenance"),
                )
                self._send_json(HTTPStatus.OK, sim_res)
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Simulation failed: {exc}"})
            return

        if path == "/v1/observations/verify":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            resource = data.get("resource")
            claim = data.get("claim")
            if not resource or not claim:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Fields 'resource' and 'claim' are required"},
                )
                return

            res = services.verify_state(
                resource=str(resource),
                claim=str(claim),
                crossing_id=data.get("crossing_id"),
                expected_digest=data.get("expected_digest"),
                ttl_seconds=float(data.get("ttl_seconds", 60.0)),
            )
            self._send_json(HTTPStatus.OK, res)
            return

        if path == "/v1/trace/links":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            req_fields = ("source_id", "source_type", "relation", "target_id", "target_type")
            missing = [f for f in req_fields if not data.get(f)]
            if missing:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Missing required fields: {', '.join(missing)}"},
                )
                return

            try:
                link = services.record_causal_link(
                    source_id=str(data["source_id"]),
                    source_type=data["source_type"],
                    relation=data["relation"],
                    target_id=str(data["target_id"]),
                    target_type=data["target_type"],
                    metadata=data.get("metadata"),
                )
                self._send_json(HTTPStatus.CREATED, link)
            except CycleDetectedError as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": str(exc), "code": "cycle_detected"},
                )
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Failed to record link: {exc}"})
            return

        if path == "/v1/handoffs":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            handoff_req_fields = (
                "task_id",
                "initiator_agent_id",
                "assigned_agent_id",
                "verifier_agent_id",
            )
            missing = [f for f in handoff_req_fields if not data.get(f)]
            if missing:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Missing required fields: {', '.join(missing)}"},
                )
                return

            try:
                hnd = services.create_task_handoff(
                    task_id=str(data["task_id"]),
                    initiator_agent_id=str(data["initiator_agent_id"]),
                    assigned_agent_id=str(data["assigned_agent_id"]),
                    verifier_agent_id=str(data["verifier_agent_id"]),
                    allowed_verbs=data.get("allowed_verbs", ()),
                    allowed_resources=data.get("allowed_resources", ()),
                    prior_crossings=data.get("prior_crossings", ()),
                    prior_observations=data.get("prior_observations", ()),
                    assertions=data.get("assertions"),
                    ttl_seconds=float(data.get("ttl_seconds", 3600.0)),
                )
                self._send_json(HTTPStatus.CREATED, hnd)
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": f"Failed to create handoff: {exc}"}
                )
            return

        if path.startswith("/v1/handoffs/") and path.endswith("/advance"):
            hnd_id = path[len("/v1/handoffs/") : -len("/advance")]
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            caller_id = data.get("caller_agent_id")
            next_id = data.get("next_agent_id")
            if not caller_id or not next_id:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Fields 'caller_agent_id' and 'next_agent_id' are required"},
                )
                return

            try:
                advanced = services.advance_task_handoff(
                    hnd_id,
                    caller_agent_id=str(caller_id),
                    next_agent_id=str(next_id),
                    crossing_id=data.get("crossing_id"),
                    observation_id=data.get("observation_id"),
                    new_assertions=data.get("new_assertions"),
                    allowed_verbs=data.get("allowed_verbs"),
                    allowed_resources=data.get("allowed_resources"),
                    ttl_seconds=float(data.get("ttl_seconds", 3600.0)),
                )
                self._send_json(HTTPStatus.OK, advanced)
            except UnauthorizedAgentHandoffError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_agent"},
                )
            except ExpiredHandoffError as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": str(exc), "code": "expired_handoff"},
                )
            except HandoffError as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": str(exc), "code": "handoff_error"},
                )
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": f"Failed to advance handoff: {exc}"}
                )
            return

        if path.startswith("/v1/handoffs/") and path.endswith("/verify"):
            hnd_id = path[len("/v1/handoffs/") : -len("/verify")]
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            verifier_id = data.get("verifier_agent_id")
            if not verifier_id:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Field 'verifier_agent_id' is required"},
                )
                return

            try:
                result = services.verify_task_handoff(
                    hnd_id,
                    verifier_agent_id=str(verifier_id),
                )
                self._send_json(HTTPStatus.OK, result)
            except UnauthorizedAgentHandoffError as exc:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"error": str(exc), "code": "unauthorized_agent"},
                )
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST, {"error": f"Failed to verify handoff: {exc}"}
                )
            return

        if path == "/v1/freeze":
            self.server.boundary.freeze()
            self._send_json(
                HTTPStatus.OK,
                {"frozen": True, "message": "Kill switch activated: system frozen"},
            )
            return

        if path == "/v1/unfreeze":
            self.server.boundary.unfreeze()
            self._send_json(HTTPStatus.OK, {"frozen": False, "message": "System unfrozen"})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Route '{path}' not found"})

    def do_DELETE(self) -> None:
        if not self._check_auth():
            return

        parts = urlsplit(self.path)
        path = parts.path.rstrip("/")
        services = self.server.services

        origin = self.headers.get("Origin")
        if origin and not self._allowed_origin():
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "Forbidden: cross-origin browser request rejected"},
            )
            return

        if path.startswith("/v1/trace/links/"):
            link_id = path[len("/v1/trace/links/") :]
            deleted = services.delete_causal_link(link_id)
            if deleted:
                self._send_json(HTTPStatus.OK, {"deleted": True, "link_id": link_id})
            else:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": f"Causal link '{link_id}' not found"},
                )
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Route '{path}' not found"})

    def _render_dashboard_html(self) -> str:
        """Render the complete, self-contained Actentra Operator Console."""
        console_path = Path(__file__).parent / "console.html"
        if console_path.exists():
            return console_path.read_text(encoding="utf-8")
        return "<html><body><h2>Actentra Console HTML template missing</h2></body></html>"


class ActentraHTTPServer(ThreadingHTTPServer):
    """Threading HTTPServer for Actentra gateway with persistence and scoped executors."""

    def __init__(
        self,
        server_address: tuple[str, int],
        boundary: Boundary,
        *,
        executor_registry: ExecutorRegistry | None = None,
        approval_ttl_seconds: float = 300.0,
        auth_token: str | None = None,
        unsafe_allow_remote: bool = False,
    ) -> None:
        host = server_address[0]
        effective_token = auth_token or os.environ.get("ACTENTRA_GATEWAY_TOKEN")
        is_remote_allowed = unsafe_allow_remote or bool(
            os.environ.get("ACTENTRA_UNSAFE_ALLOW_REMOTE")
        )

        if host not in _LOOPBACK_HOSTS:
            if not is_remote_allowed:
                raise ValueError(
                    f"Refusing to bind Actentra Gateway to non-loopback address {host!r} "
                    "without explicit remote authorization (--unsafe-allow-remote)"
                )
            if not effective_token or not effective_token.strip():
                raise ValueError(
                    f"Refusing to bind Actentra Gateway to non-loopback address {host!r} "
                    "without an authentication token. Remote interfaces require "
                    "token authentication."
                )

        super().__init__(server_address, ActentraHTTPHandler)
        self.boundary = boundary
        self.approval_ttl_seconds = approval_ttl_seconds
        self.auth_token = effective_token
        self.services = AppServices(
            boundary,
            executor_registry=executor_registry,
            approval_ttl_seconds=approval_ttl_seconds,
        )

    def add_pending(self, envelope: Any, decision: Any) -> None:
        """Add pending approval to persistent SQLite store."""
        self.boundary.receipt_store.add_pending_approval(
            envelope=envelope,
            decision=decision,
            ttl_seconds=self.approval_ttl_seconds,
        )

    def clean_expired_pending(self) -> None:
        """Clean expired approvals in persistent SQLite store."""
        self.boundary.receipt_store.cleanup_expired_approvals()

    def resolve_pending(self, crossing_id: str, *, approved: bool) -> PendingCrossing | None:
        """Resolve pending approval in persistent store."""
        res = self.boundary.receipt_store.resolve_pending_approval(crossing_id, approved=approved)
        if res is None:
            return None
        if approved:
            self.boundary.grant_approval(
                canonical_hash=res.canonical_hash,
                session_id=res.session_id,
            )
        return PendingCrossing(
            crossing_id=res.crossing_id,
            session_id=res.session_id,
            canonical_hash=res.canonical_hash,
            tool=res.tool,
            verb=res.verb,
            resource=res.resource,
            risk_tags=res.risk_tags,
            reason=res.reason,
            ts=res.ts,
            expires_at=res.expires_at,
        )

    @property
    def pending_crossings(self) -> dict[str, PendingCrossing]:
        """In-memory dictionary compatibility view over persistent store."""
        records = self.boundary.receipt_store.list_pending_approvals(status="pending")
        return {
            r.crossing_id: PendingCrossing(
                crossing_id=r.crossing_id,
                session_id=r.session_id,
                canonical_hash=r.canonical_hash,
                tool=r.tool,
                verb=r.verb,
                resource=r.resource,
                risk_tags=r.risk_tags,
                reason=r.reason,
                ts=r.ts,
                expires_at=r.expires_at,
            )
            for r in records
        }


def create_gateway_server(
    boundary: Boundary,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    executor_registry: ExecutorRegistry | None = None,
    approval_ttl_seconds: float = 300.0,
    auth_token: str | None = None,
    unsafe_allow_remote: bool = False,
) -> ActentraHTTPServer:
    """Create a configured ActentraHTTPServer ready to serve."""
    return ActentraHTTPServer(
        (host, port),
        boundary,
        executor_registry=executor_registry,
        approval_ttl_seconds=approval_ttl_seconds,
        auth_token=auth_token,
        unsafe_allow_remote=unsafe_allow_remote,
    )


def serve_http(
    boundary: Boundary,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    executor_registry: ExecutorRegistry | None = None,
    approval_ttl_seconds: float = 300.0,
    auth_token: str | None = None,
    unsafe_allow_remote: bool = False,
) -> None:
    """Run the Actentra HTTP Gateway service synchronously."""
    server = create_gateway_server(
        boundary,
        host=host,
        port=port,
        executor_registry=executor_registry,
        approval_ttl_seconds=approval_ttl_seconds,
        auth_token=auth_token,
        unsafe_allow_remote=unsafe_allow_remote,
    )
    print(f"Actentra Gateway serving on http://{host}:{port} (Console: http://{host}:{port}/ui)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
