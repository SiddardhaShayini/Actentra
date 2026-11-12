"""MCP stdio proxy for Actentra: intercepts ``tools/call`` and pins ``tools/list``."""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import IO, Any

from actentra.boundary import ActionBlockedError, Boundary
from actentra_core.canonicalize import hash_canonical
from actentra_core.envelope import EnvelopeError, ProvenanceItem, build_envelope
from actentra_core.receipts import ReceiptError
from actentra_core.verdict import Decision, Verdict

_MAX_LINE_BYTES = 2 * 1024 * 1024  # 2 MiB bound per JSON-RPC message


class MCPProxyError(RuntimeError):
    """Raised on downstream MCP transport or protocol errors."""


@dataclass(frozen=True, slots=True)
class MCPToolMapping:
    tool: str
    verb: str
    resource: str


ToolMapper = Callable[[str, dict[str, Any]], MCPToolMapping]
ForwardFn = Callable[[dict[str, Any]], dict[str, Any]]

_DEFAULT_TOOL_MAP: dict[str, tuple[str, str]] = {
    "read_file": ("fs.read", "read"),
    "fs.read": ("fs.read", "read"),
    "list_dir": ("fs.list", "read"),
    "list_directory": ("fs.list", "read"),
    "fs.list": ("fs.list", "read"),
    "write_file": ("fs.write", "write"),
    "edit_file": ("fs.write", "write"),
    "fs.write": ("fs.write", "write"),
    "delete_file": ("fs.delete", "delete"),
    "remove_file": ("fs.delete", "delete"),
    "fs.delete": ("fs.delete", "delete"),
    "http_request": ("http.request", "network"),
    "http_get": ("http.get", "network"),
    "http_post": ("http.post", "network"),
    "fetch": ("http.get", "network"),
    "sql_query": ("sql.execute", "other"),
    "sql_execute": ("sql.execute", "other"),
    "execute_command": ("shell.exec", "exec"),
    "run_command": ("shell.exec", "exec"),
}


def default_mcp_tool_mapper(name: str, arguments: dict[str, Any]) -> MCPToolMapping:
    """Map an MCP tool name and arguments into an Actentra (tool, verb, resource)."""
    norm_name = name.strip().lower()
    mapped_tool, mapped_verb = _DEFAULT_TOOL_MAP.get(norm_name, (f"mcp.{norm_name}", "other"))

    for key in ("path", "file_path", "target_file", "directory", "dir"):
        val = arguments.get(key)
        if isinstance(val, str):
            return MCPToolMapping(tool=mapped_tool, verb=mapped_verb, resource=f"path:{val}")

    for key in ("url", "uri", "endpoint"):
        val = arguments.get(key)
        if isinstance(val, str):
            return MCPToolMapping(tool=mapped_tool, verb=mapped_verb, resource=val)

    query = arguments.get("query") or arguments.get("sql")
    if isinstance(query, str):
        upper = query.lstrip().upper()
        if mapped_verb == "other":
            mapped_verb = (
                "read"
                if upper.startswith(("SELECT", "PRAGMA", "EXPLAIN"))
                else "delete"
                if upper.startswith(("DROP", "TRUNCATE", "DELETE"))
                else "write"
            )
        db_res = str(arguments.get("database", "sqlite:///default.db"))
        return MCPToolMapping(tool=mapped_tool, verb=mapped_verb, resource=db_res)

    return MCPToolMapping(tool=mapped_tool, verb=mapped_verb, resource=f"mcp:{norm_name}")


class MCPStdioProxy:
    """Mediates JSON-RPC 2.0 MCP traffic between a client and a downstream server."""

    def __init__(
        self,
        *,
        boundary: Boundary,
        forward: ForwardFn,
        tool_mapper: ToolMapper | None = None,
        taint_on_untrusted_tool: bool = True,
    ) -> None:
        self._boundary = boundary
        self._forward = forward
        self._tool_mapper = tool_mapper or default_mcp_tool_mapper
        self._taint_on_untrusted_tool = taint_on_untrusted_tool
        self._pinned_tool_hashes: dict[str, str] = {}
        self._poisoned_tools: set[str] = set()

    @property
    def pinned_tools(self) -> dict[str, str]:
        return dict(self._pinned_tool_hashes)

    @property
    def poisoned_tools(self) -> frozenset[str]:
        return frozenset(self._poisoned_tools)

    def _inspect_tools_list(self, response: dict[str, Any]) -> None:
        result = response.get("result")
        if not isinstance(result, dict):
            return
        tools = result.get("tools")
        if not isinstance(tools, list):
            return
        for tool_def in tools:
            if not isinstance(tool_def, dict):
                continue
            name = tool_def.get("name")
            if not isinstance(name, str) or not name:
                continue
            digest = hash_canonical(
                {
                    "name": name,
                    "description": tool_def.get("description", ""),
                    "inputSchema": tool_def.get("inputSchema", {}),
                }
            )
            prev = self._pinned_tool_hashes.get(name)
            if prev is None:
                self._pinned_tool_hashes[name] = digest
            elif prev != digest:
                self._poisoned_tools.add(name)

    def handle_message(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Process one JSON-RPC message from the MCP client."""
        method = msg.get("method")
        req_id = msg.get("id")

        if method != "tools/call":
            # Forward non-call MCP messages (initialize, tools/list, notifications)
            if req_id is None:
                self._forward(msg)
                return None
            resp = self._forward(msg)
            if method == "tools/list":
                self._inspect_tools_list(resp)
            return resp

        params = msg.get("params")
        if not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "Invalid params for tools/call"},
            }

        raw_name = params.get("name")
        raw_args = params.get("arguments") or {}
        if not isinstance(raw_name, str) or not raw_name.strip() or not isinstance(raw_args, dict):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": "tools/call requires string name and object arguments",
                },
            }

        mapped = self._tool_mapper(raw_name, raw_args)

        # Anti-rug-pull guard (CVE-2025-54136): reject tools whose schema/description changed.
        if raw_name in self._poisoned_tools:
            try:
                env = build_envelope(
                    tool=mapped.tool,
                    verb=mapped.verb,
                    resource=mapped.resource,
                    params=raw_args,
                    provenance=[ProvenanceItem(source=f"mcp:{raw_name}", trust="untrusted")],
                )
                canon_hash = env.canonical_hash
                crossing_id = env.crossing_id
            except EnvelopeError:
                env = None
                canon_hash = "sha256:" + ("0" * 64)
                crossing_id = "MCP-RUGPULL"

            blocked_dec = Decision(
                verdict=Verdict.DENY,
                rule_id="mcp:tool-definition-changed",
                reason=f"MCP tool '{raw_name}' changed definition mid-session (possible rug-pull)",
                policy_version=self._boundary.engine.policy.policy_version,
                canonical_hash=canon_hash,
                risk_tags=("untrusted-provenance",),
            )
            if env is not None:
                with contextlib.suppress(ReceiptError):
                    self._boundary.receipt_store.record_decision(env, blocked_dec)
            err = ActionBlockedError(blocked_dec, crossing_id)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Actentra blocked action: {err}"}],
                    "isError": True,
                },
            }

        provenance: list[ProvenanceItem] = []
        if self._taint_on_untrusted_tool and raw_name not in self._pinned_tool_hashes:
            provenance.append(ProvenanceItem(source=f"mcp:{raw_name}", trust="unknown"))

        try:
            response = self._boundary.execute(
                tool=mapped.tool,
                verb=mapped.verb,
                resource=mapped.resource,
                params=raw_args,
                provenance=provenance,
                fn=lambda _env, _dec: self._forward(msg),
            )
            return dict(response) if isinstance(response, dict) else response
        except ActionBlockedError as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Actentra blocked action: {exc}"}],
                    "isError": True,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32603,
                    "message": f"Downstream MCP execution failed ({type(exc).__name__})",
                },
            }


def serve_stdio(
    *,
    boundary: Boundary,
    server_cmd: list[str],
    client_in: IO[str] | None = None,
    client_out: IO[str] | None = None,
    tool_mapper: ToolMapper | None = None,
) -> int:
    """Spawn downstream MCP server (no shell=True) and proxy JSON-RPC lines."""
    if not server_cmd:
        raise MCPProxyError("server_cmd must be non-empty")

    in_stream = client_in or sys.stdin
    out_stream = client_out or sys.stdout

    proc = subprocess.Popen(  # noqa: S603
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    def forward(msg: dict[str, Any]) -> dict[str, Any]:
        line = json.dumps(msg, ensure_ascii=False)
        if len(line.encode("utf-8")) > _MAX_LINE_BYTES:
            raise MCPProxyError("Outgoing JSON-RPC message exceeds 2 MiB limit")
        proc.stdin.write(line + "\n")  # type: ignore[union-attr]
        proc.stdin.flush()  # type: ignore[union-attr]
        if msg.get("id") is None:
            return {}
        resp_line = proc.stdout.readline()  # type: ignore[union-attr]
        if not resp_line:
            raise MCPProxyError("Downstream MCP server closed stdout unexpectedly")
        if len(resp_line.encode("utf-8")) > _MAX_LINE_BYTES:
            raise MCPProxyError("Incoming JSON-RPC response exceeds 2 MiB limit")
        loaded = json.loads(resp_line)
        if not isinstance(loaded, dict):
            raise MCPProxyError("Downstream MCP response must be a JSON object")
        return loaded

    proxy = MCPStdioProxy(boundary=boundary, forward=forward, tool_mapper=tool_mapper)
    try:
        for raw_line in in_stream:
            stripped = raw_line.strip()
            if not stripped:
                continue
            if len(stripped.encode("utf-8")) > _MAX_LINE_BYTES:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Request exceeds 2 MiB limit"},
                }
                out_stream.write(json.dumps(err_resp) + "\n")
                out_stream.flush()
                continue
            try:
                msg = json.loads(stripped)
            except json.JSONDecodeError:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                }
                out_stream.write(json.dumps(err_resp) + "\n")
                out_stream.flush()
                continue
            if not isinstance(msg, dict):
                continue
            reply = proxy.handle_message(msg)
            if reply is not None:
                out_stream.write(json.dumps(reply, ensure_ascii=False) + "\n")
                out_stream.flush()
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        if proc.stdout is not None:
            proc.stdout.close()
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    return int(proc.returncode or 0)
