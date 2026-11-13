"""Security and functional tests for ScopedHTTPExecutor and SSRF defense."""

from __future__ import annotations

import http.server
import threading
from pathlib import Path

import pytest

from actentra import ActionBlockedError, Boundary
from actentra_core.canonicalize import CanonicalizationError
from actentra_core.envelope import ProvenanceItem
from actentra_core.policy import load_policy_yaml
from actentra_core.receipts import ReceiptStore, verify_log
from actentra_executors.fs import ExecutorError
from actentra_executors.http import (
    ScopedHTTPExecutor,
    ScopedHTTPTools,
    canonicalize_url,
)


def test_url_canonicalization_and_safety_checks() -> None:
    assert (
        canonicalize_url("HTTP://Example.COM:80/api//v1/?b=2&a=1")
        == "http://example.com/api/v1/?b=2&a=1"
    )
    assert canonicalize_url("https://example.com:443/docs") == "https://example.com/docs"

    with pytest.raises(CanonicalizationError, match="Unsupported URL scheme"):
        canonicalize_url("file:///etc/passwd")

    with pytest.raises(CanonicalizationError, match="Embedded credentials"):
        canonicalize_url("https://admin:secret@example.com/dashboard")

    with pytest.raises(CanonicalizationError, match="valid hostname"):
        canonicalize_url("http://")


def test_ssrf_blocks_private_and_metadata_ips(tmp_path: Path) -> None:
    executor = ScopedHTTPExecutor(allow_private_ips=False)
    policy = load_policy_yaml(
        """
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-http
    match: { tool: "http.*", verb: "network" }
    verdict: allow
"""
    )
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(tmp_path / "ssrf.db"))

    # Direct IP blocked by SSRF defense
    with pytest.raises(ExecutorError, match="SSRF"):
        boundary.execute(
            tool="http.get",
            verb="network",
            resource="http://169.254.169.254/latest/meta-data/",
            fn=executor.execute,
        )

    with pytest.raises(ExecutorError, match="SSRF"):
        boundary.execute(
            tool="http.get",
            verb="network",
            resource="http://127.0.0.1:8080/admin",
            fn=executor.execute,
        )


def test_host_allowlist_enforcement(tmp_path: Path) -> None:
    executor = ScopedHTTPExecutor(
        allowed_hosts=["api.github.com", "*.weather.gov"],
        allow_private_ips=True,
    )
    policy = load_policy_yaml(
        """
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-http
    match: { tool: "http.*", verb: "network" }
    verdict: allow
"""
    )
    boundary = Boundary(policy=policy, receipt_store=ReceiptStore(tmp_path / "hosts.db"))

    with pytest.raises(ExecutorError, match="not in the allowed hosts list"):
        boundary.execute(
            tool="http.get",
            verb="network",
            resource="https://evil.example/exfil",
            fn=executor.execute,
        )


class _LocalTestServer(http.server.ThreadingHTTPServer):
    pass


class _TestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        if self.path == "/data":
            body = b"hello from local test server"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/large":
            body = b"A" * 100
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode("utf-8")
        resp = f"echo:{data}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def test_http_executor_local_server_roundtrip(tmp_path: Path) -> None:
    server = _LocalTestServer(("127.0.0.1", 0), _TestHandler)
    port = server.server_port
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()

    try:
        db_path = tmp_path / "receipts.db"
        policy = load_policy_yaml(
            f"""
version: 1
defaults: {{ verdict: deny }}
rules:
  - id: allow-test-server
    match: {{ tool: "http.*", resource: "http://127.0.0.1:{port}/*" }}
    verdict: allow
  - id: deny-untrusted-egress
    match: {{ tool: "http.*", taint: untrusted }}
    verdict: deny
"""
        )
        boundary = Boundary(policy=policy, receipt_store=ReceiptStore(db_path))
        executor = ScopedHTTPExecutor(allow_private_ips=True)
        tools = ScopedHTTPTools(boundary, executor)

        # 1. Successful GET
        try:
            res_get = tools.get(f"http://127.0.0.1:{port}/data")
        except (OSError, ExecutorError) as exc:
            if "10013" in str(exc) or "forbidden" in str(exc).lower():
                pytest.skip(f"Loopback socket access restricted by sandbox: {exc}")
            raise
        assert res_get["status_code"] == 200
        assert res_get["body"] == "hello from local test server"

        # 2. Successful POST
        res_post = tools.post(f"http://127.0.0.1:{port}/post", body="hello world")
        assert res_post["status_code"] == 200
        assert res_post["body"] == "echo:hello world"

        # 3. Untrusted provenance is blocked by policy before HTTP call
        with pytest.raises(ActionBlockedError):
            tools.get(
                f"http://127.0.0.1:{port}/data",
                provenance=[ProvenanceItem(source="email", trust="untrusted")],
            )

        vr = verify_log(db_path)
        assert vr.ok is True
        assert vr.total_records == 5  # 2 success (dec+out) + 1 blocked dec
    finally:
        server.shutdown()
        server.server_close()
