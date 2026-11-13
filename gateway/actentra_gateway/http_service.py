"""Lightweight, local-first HTTP service and Web Approval UI for Actentra."""

from __future__ import annotations

import html
import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from actentra.boundary import Boundary
from actentra_core.envelope import EnvelopeError, ProvenanceItem, build_envelope
from actentra_core.receipts import verify_log
from actentra_core.verdict import Decision, Verdict

_MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB bound on HTTP request body


class PendingCrossing:
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
            "expires_in_seconds": max(0.0, round(self.expires_at - time.monotonic(), 1)),
        }


class ActentraHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Actentra REST API and Local Web Approval UI."""

    server: ActentraHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default noisy access logs to keep terminal clean
        pass

    def _send_json(self, status: int, payload: dict[str, Any] | list[Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html_text: str) -> None:
        body = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any]:
        content_len_header = self.headers.get("Content-Length")
        if not content_len_header:
            raise ValueError("Missing Content-Length header")
        length = int(content_len_header)
        if length > _MAX_BODY_BYTES:
            raise ValueError(f"Request body exceeds {_MAX_BODY_BYTES} bytes limit")
        raw_bytes = self.rfile.read(length)
        parsed = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("JSON request body must be an object")
        return parsed

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"

        if path == "/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "policy_id": self.server.boundary.engine.policy.policy_id,
                    "policy_version": self.server.boundary.engine.policy.policy_version,
                    "mode": self.server.boundary.engine.policy.mode,
                    "frozen": self.server.boundary.engine.frozen,
                },
            )
            return

        if path == "/v1/crossings/pending":
            self.server.clean_expired_pending()
            pending_list = [p.to_dict() for p in self.server.pending_crossings.values()]
            self._send_json(HTTPStatus.OK, pending_list)
            return

        if path == "/v1/receipts":
            query = parse_qs(parts.query)
            limit = int(query.get("limit", ["100"])[0])
            records = self.server.boundary.receipt_store.iter_records()
            recent = records[-limit:] if len(records) > limit else records
            self._send_json(HTTPStatus.OK, [r.to_dict() for r in recent])
            return

        if path == "/v1/verify":
            vr = verify_log(self.server.boundary.receipt_store.db_path)
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": vr.ok,
                    "total_records": vr.total_records,
                    "head_hash": vr.last_hash,
                    "errors": list(vr.errors),
                },
            )
            return

        if path in ("/ui", "/"):
            self._send_html(HTTPStatus.OK, self._render_dashboard_html())
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/")

        if path == "/v1/crossings":
            try:
                data = self._read_json_body()
            except Exception as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid body: {exc}"})
                return

            prov_items = [
                ProvenanceItem(source=p["source"], trust=p["trust"])
                for p in data.get("provenance", [])
                if isinstance(p, dict) and "source" in p and "trust" in p
            ]

            try:
                envelope = build_envelope(
                    tool=str(data.get("tool", "")),
                    verb=str(data.get("verb", "other")),
                    resource=str(data.get("resource", "")),
                    params=data.get("params") or {},
                    session_id=str(data.get("session_id", "default")),
                    agent_id=str(data.get("agent_id", "http-client")),
                    provenance=prov_items,
                    user_goal=data.get("user_goal"),
                    idempotency_key=data.get("idempotency_key"),
                )
            except EnvelopeError as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Invalid ActionEnvelope: {exc}", "verdict": Verdict.HOLD.value},
                )
                return

            decision = self.server.boundary.engine.evaluate(envelope)

            # Record durable decision receipt (Invariant I5)
            self.server.boundary.receipt_store.record_decision(envelope, decision)

            if decision.verdict == Verdict.ASK:
                self.server.add_pending(envelope, decision)

            resp_data = decision.to_dict()
            resp_data["crossing_id"] = envelope.crossing_id
            self._send_json(HTTPStatus.OK, resp_data)
            return

        if path.startswith("/v1/crossings/") and path.endswith("/approve"):
            crossing_id = path[len("/v1/crossings/") : -len("/approve")]
            try:
                data = self._read_json_body()
            except Exception:
                data = {}

            approved = bool(data.get("approved", True))
            res = self.server.resolve_pending(crossing_id, approved=approved)
            if res is None:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": f"Pending crossing '{crossing_id}' not found or expired"},
                )
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "crossing_id": crossing_id,
                    "status": "approved" if approved else "rejected",
                    "canonical_hash": res.canonical_hash,
                },
            )
            return

        if path == "/v1/freeze":
            self.server.boundary.freeze()
            self._send_json(HTTPStatus.OK, {"frozen": True, "message": "Kill switch activated"})
            return

        if path == "/v1/unfreeze":
            self.server.boundary.unfreeze()
            self._send_json(HTTPStatus.OK, {"frozen": False, "message": "System unfrozen"})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def _render_dashboard_html(self) -> str:
        self.server.clean_expired_pending()
        pending = list(self.server.pending_crossings.values())
        b = self.server.boundary

        vr = verify_log(b.receipt_store.db_path)
        status_color = "#10b981" if vr.ok else "#ef4444"
        status_text = "VERIFIED (OK)" if vr.ok else "TAMPER DETECTED"

        pending_cards_html = []
        for p in pending:
            risk_badges = " ".join(
                f"<span class='badge risk'>{html.escape(t)}</span>" for t in p.risk_tags
            )
            cid = html.escape(p.crossing_id)
            tool_name = html.escape(p.tool)
            verb_name = html.escape(p.verb)
            res_name = html.escape(p.resource)
            exp_secs = p.to_dict()["expires_in_seconds"]
            reason_text = html.escape(p.reason)
            badge_fallback = '<span style="color:#9ca3af">no risk tags</span>'
            pending_cards_html.append(
                f"""
                <div class="card pending-card" id="card-{cid}">
                    <div style="display:flex; justify-content:space-between;
                                align-items:flex-start;">
                        <div>
                            <div class="stat-label">Crossing: <code>{cid}</code></div>
                            <h3 style="margin-top:0.25rem;">
                              {tool_name}
                              <span style="font-weight:normal; color:#9ca3af">({verb_name})</span>
                            </h3>
                            <div style="margin-top:0.25rem;"><code>{res_name}</code></div>
                        </div>
                        <div>
                            <span class="badge" style="background:#78350f; color:#fde68a;">
                              EXPIRES IN {exp_secs}s
                            </span>
                        </div>
                    </div>
                    <div style="margin: 0.75rem 0; font-size: 0.85rem; color: #d1d5db;">
                        <strong>Reason:</strong> {reason_text}
                    </div>
                    <div>{risk_badges or badge_fallback}</div>
                    <div style="margin-top: 1rem; display: flex; gap: 0.75rem;">
                        <button class="btn btn-approve"
                                onclick="resolveCrossing('{cid}', true)">
                          Approve Action
                        </button>
                        <button class="btn btn-deny"
                                onclick="resolveCrossing('{cid}', false)">
                          Deny
                        </button>
                    </div>
                </div>
                """
            )

        no_crossings = (
            "<div style='color:#9ca3af; padding: 1.5rem 0;'>"
            "No actions currently awaiting human approval.</div>"
        )
        cards_section = "\n".join(pending_cards_html) if pending_cards_html else no_crossings

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Actentra Gateway — Operator Console</title>
<style>
  :root {{
    --bg: #0b0f19;
    --card-bg: #111827;
    --border: #1f2937;
    --text: #f3f4f6;
    --teal: #13bfa6;
    --red: #ef4444;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, sans-serif;
    padding: 2rem;
    line-height: 1.5;
  }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1rem;
    margin-bottom: 2rem;
  }}
  .card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    margin-bottom: 1.5rem;
  }}
  .stat-label {{ font-size: 0.75rem; color: #9ca3af; text-transform: uppercase; }}
  code {{ font-family: monospace; color: #93c5fd; font-size: 0.85rem; }}
  .badge {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
  }}
  .badge.risk {{ background: #312e81; color: #c7d2fe; margin-right: 0.25rem; }}
  .btn {{
    padding: 0.5rem 1.25rem;
    border-radius: 6px;
    font-weight: 600;
    cursor: pointer;
    border: none;
    font-size: 0.85rem;
  }}
  .btn-approve {{ background: var(--teal); color: #0b0f19; }}
  .btn-deny {{ background: #374151; color: #f3f4f6; }}
  .btn:hover {{ opacity: 0.9; }}
</style>
<script>
async function resolveCrossing(cid, approved) {{
    try {{
        const resp = await fetch('/v1/crossings/' + cid + '/approve', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ approved: approved }})
        }});
        if (resp.ok) {{
            const el = document.getElementById('card-' + cid);
            if (el) {{
                el.style.opacity = '0.4';
                const actionText = approved ? 'APPROVED' : 'DENIED';
                el.innerHTML = '<strong>' + actionText + '</strong> — Crossing resolved.';
            }}
        }} else {{
            alert('Failed to resolve crossing');
        }}
    }} catch (e) {{
        alert('Error: ' + e);
    }}
}}
</script>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h2><span style="color:var(--teal)">Actentra</span> Operator Console</h2>
      <div style="font-size:0.85rem; color:#9ca3af;">
        Policy: <code>{html.escape(b.engine.policy.policy_id)}</code>
        &bull; Mode: <code>{b.engine.policy.mode}</code>
      </div>
    </div>
    <div>
      <span class="badge"
            style="background:{status_color}22; color:{status_color};
                   border:1px solid {status_color}">
        {status_text}
      </span>
    </div>
  </header>

  <section>
    <h3 style="margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem;">
      Pending Human Approvals (ASK)
      <span class="badge" style="background:#78350f; color:#fde68a;">{len(pending)}</span>
    </h3>
    {cards_section}
  </section>
</div>
</body>
</html>
"""


class ActentraHTTPServer(ThreadingHTTPServer):
    """Threading HTTPServer for Actentra gateway."""

    def __init__(
        self,
        server_address: tuple[str, int],
        boundary: Boundary,
        *,
        approval_ttl_seconds: float = 300.0,
    ) -> None:
        super().__init__(server_address, ActentraHTTPHandler)
        self.boundary = boundary
        self.approval_ttl_seconds = approval_ttl_seconds
        self.pending_crossings: dict[str, PendingCrossing] = {}

    def add_pending(self, envelope: Any, decision: Decision) -> None:
        self.pending_crossings[envelope.crossing_id] = PendingCrossing(
            crossing_id=envelope.crossing_id,
            session_id=envelope.session_id,
            canonical_hash=envelope.canonical_hash,
            tool=envelope.action.tool,
            verb=envelope.action.verb,
            resource=envelope.action.resource,
            risk_tags=decision.risk_tags,
            reason=decision.reason,
            ts=envelope.ts,
            expires_at=time.monotonic() + self.approval_ttl_seconds,
        )

    def clean_expired_pending(self) -> None:
        now = time.monotonic()
        expired = [cid for cid, p in self.pending_crossings.items() if now >= p.expires_at]
        for cid in expired:
            del self.pending_crossings[cid]

    def resolve_pending(self, crossing_id: str, *, approved: bool) -> PendingCrossing | None:
        self.clean_expired_pending()
        p = self.pending_crossings.pop(crossing_id, None)
        if p is None:
            return None
        if approved:
            self.boundary.grant_approval(
                canonical_hash=p.canonical_hash,
                session_id=p.session_id,
            )
        return p


def create_gateway_server(
    boundary: Boundary,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    approval_ttl_seconds: float = 300.0,
) -> ActentraHTTPServer:
    """Create a configured ActentraHTTPServer ready to serve."""
    return ActentraHTTPServer((host, port), boundary, approval_ttl_seconds=approval_ttl_seconds)


def serve_http(
    boundary: Boundary,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    approval_ttl_seconds: float = 300.0,
) -> None:
    """Run the Actentra HTTP Gateway service synchronously."""
    server = create_gateway_server(
        boundary,
        host=host,
        port=port,
        approval_ttl_seconds=approval_ttl_seconds,
    )
    print(f"Actentra Gateway serving on http://{host}:{port} (Console: http://{host}:{port}/ui)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
