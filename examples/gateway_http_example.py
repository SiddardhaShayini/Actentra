"""HTTP Gateway usage example (loopback server + stdlib HTTP client).

Starts a local Actentra HTTP gateway on 127.0.0.1 with an ephemeral port,
submits an allowed read and a denied .env read over HTTP, inspects the
receipts endpoint, and shuts down cleanly.
"""

from __future__ import annotations

import http.client
import json
import tempfile
import threading
from pathlib import Path
from typing import Any

from actentra import Boundary, path_resource
from actentra_gateway import create_gateway_server
from actentra_gateway.services import ExecutorRegistry


def _http_json(
    port: int,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Host": f"127.0.0.1:{port}", "X-Actentra-Client": "example-client"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read().decode("utf-8"))
    finally:
        conn.close()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="actentra-http-example-") as tmp:
        root = Path(tmp)
        workspace = root / "workspace"
        workspace.mkdir()
        (workspace / "readme.txt").write_text("Gateway workspace file\n", encoding="utf-8")
        (workspace / ".env").write_text("SECRET=never_expose\n", encoding="utf-8")
        ws_pattern = path_resource(workspace).removeprefix("path:")

        policy_yaml = f"""\
version: 1
policy_id: gateway-example-policy
mode: enforce

defaults:
  verdict: deny
  reason: "Denied by default policy"

rules:
  - id: block-privilege-escalation
    match:
      risk_any: [privilege-escalation]
    verdict: deny
    reason: "Sensitive credential access is blocked"

  - id: allow-workspace-read
    match:
      tool: fs.read
      verb: read
      resource: "path:{ws_pattern}/**"
    verdict: allow
    reason: "Allow workspace reads"
"""

        boundary = Boundary.from_yaml(
            policy_yaml=policy_yaml,
            receipts_db=root / "receipts.db",
            session_id="http-example-session",
            agent_id="http-example-agent",
        )
        registry = ExecutorRegistry()
        registry.register_fs(workspace)

        server = create_gateway_server(
            boundary,
            host="127.0.0.1",
            port=0,
            executor_registry=registry,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = int(server.server_address[1])

        try:
            # 1. Health check
            status, health = _http_json(port, "/health")
            print(f"[GET /health] status={status} db_status={health.get('db_status')}")

            # 2. Submit allowed crossing with execute=True
            status, allow_res = _http_json(
                port,
                "/v1/crossings",
                method="POST",
                payload={
                    "tool": "fs.read",
                    "verb": "read",
                    "resource": path_resource("readme.txt", workspace_root=workspace),
                    "params": {"path": "readme.txt"},
                    "execute": True,
                },
            )
            print(
                f"[POST /v1/crossings ALLOW] http={status} verdict={allow_res.get('verdict')} "
                f"outcome={allow_res.get('outcome', {}).get('status')} "
                f"result={allow_res.get('outcome', {}).get('result')!r}"
            )

            # 3. Submit denied crossing (.env)
            status, deny_res = _http_json(
                port,
                "/v1/crossings",
                method="POST",
                payload={
                    "tool": "fs.read",
                    "verb": "read",
                    "resource": path_resource(".env", workspace_root=workspace),
                    "params": {"path": ".env"},
                    "execute": True,
                },
            )
            print(
                f"[POST /v1/crossings DENY ] http={status} verdict={deny_res.get('verdict')} "
                f"rule={deny_res.get('rule_id')}"
            )

            # 4. Query recorded receipts & verify hash chain
            status, receipts = _http_json(port, "/v1/receipts?limit=10&offset=0")
            total = receipts["total_count"] if isinstance(receipts, dict) else len(receipts)
            print(f"[GET /v1/receipts] http={status} total={total}")
            status, verify = _http_json(port, "/v1/verify")
            print(f"[GET /v1/verify] http={status} ok={verify.get('ok')}")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)


if __name__ == "__main__":
    main()
