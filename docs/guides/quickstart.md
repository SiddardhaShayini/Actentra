# Actentra Quickstart Guide

> Get started with Actentra in under 5 minutes — in-process Python SDK, CLI, or local HTTP gateway.

---

## 1. Installation

Actentra is currently distributed from source / wheel (`0.1.0a0`, **not yet published on PyPI**).
Requires **Python 3.12+**.

### From a local clone (editable or standard)

```powershell
git clone https://github.com/SiddardhaShayini/Actentra.git
cd Actentra

# Option A: using uv
uv sync

# Option B: using pip in a virtual environment
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

### Installing into another Python project (without cloning manually)

```powershell
# Install directly from GitHub
pip install "git+https://github.com/SiddardhaShayini/Actentra.git"

# Or install a built wheel (created with `uv build` or `python -m build`)
pip install dist/actentra-0.1.0a0-py3-none-any.whl
```

Verify installation:
```powershell
actentra --help
python -c "from actentra import Boundary, path_resource; print('Actentra ready')"
```

---

## 2. Minimal Local Python Workflow (No Server Required)

The simplest way to protect file operations in a Python application is `Boundary.from_yaml()` (or `Boundary.from_files()`) with `workspace_root` and `boundary.run()`:

```python
from pathlib import Path
from actentra import Boundary, path_resource

workspace = Path("./workspace").resolve()
workspace.mkdir(exist_ok=True)
ws = path_resource(workspace).removeprefix("path:")

POLICY_YAML = f"""
version: 1
policy_id: local-quickstart
mode: enforce

defaults:
  verdict: deny
  reason: "Denied by default policy"

rules:
  - id: allow-workspace-reads
    match:
      tool: fs.read
      verb: read
      resource: "path:{ws}/**"
    verdict: allow
    reason: "Allow workspace reads"

  - id: ask-workspace-writes
    match:
      tool: fs.write
      verb: write
      resource: "path:{ws}/**"
    verdict: ask
    reason: "Workspace writes require explicit approval"
"""

# Initialize in-process Boundary with LocalFSExecutor + WorkspaceFileVerifier
boundary = Boundary.from_yaml(
    policy_yaml=POLICY_YAML,
    receipts_db="receipts.db",
    workspace_root=workspace,
    approval_callback=lambda env, dec: True,  # or `cli_approval_prompt` for terminal confirmation
)

# Authorize, execute, verify digest postcondition, and inspect the receipt
res = boundary.run(
    tool="fs.write",
    verb="write",
    resource=path_resource("notes.txt", workspace_root=workspace),
    params={"content": "Hello from Actentra!\n", "create_parents": True},
    verify_postcondition=True,
    raise_on_postcondition_failure=True,
)
print(res.crossing_id, res.verdict.value, res.status, res.evidence_status, res.verified)

# Inspect durable receipt & verify SQLite SHA-256 hash chain
receipt = boundary.inspect_crossing(res.crossing_id)
print("Lifecycle:", receipt.lifecycle_state, "Chain OK:", boundary.verify_receipts().ok)
```

See the runnable scripts in `examples/`:
- [`examples/minimal_file_write.py`](../../examples/minimal_file_write.py) — approved, postcondition-verified file write + receipt inspection
- [`examples/minimal_blocked_action.py`](../../examples/minimal_blocked_action.py) — `.env` privilege escalation `DENY`, unapproved `ASK`, and path traversal rejection

---

## 3. Protecting Custom Python Functions (`@guard` & Executors)

```python
from actentra import Boundary, path_resource

@boundary.guard(
    tool="fs.read",
    verb="read",
    resource_fn=lambda path: path_resource(path, workspace_root=workspace),
)
def protected_reader(path: str) -> str:
    return (workspace / path).read_text(encoding="utf-8")

data = protected_reader("notes.txt")
```

You can also register built-in scoped executors on any `Boundary`:
- `boundary.register_fs(workspace_root)` — `fs.list`, `fs.read`, `fs.write`, `fs.delete` + `WorkspaceFileVerifier`
- `boundary.register_sqlite(db_path)` — `sql.execute` (single-statement, authorizer-enforced)
- `boundary.register_http(allowed_hosts=[...])` — `http.get`, `http.post`, `http.request` (SSRF & DNS-rebinding defended)
- `boundary.register_executor("my.tool", fn)` — custom `Callable[[ActionEnvelope, Decision], Any]`

---

## 4. AI-Agent Integration (OpenAI Function Calling & LangChain)

### OpenAI / Anthropic Function Calling Adapter

```python
from actentra import Boundary, FunctionCallAdapter, ProvenanceItem, path_resource

adapter = FunctionCallAdapter(boundary)
adapter.register_tool(
    "read_note",
    lambda path: (workspace / path).read_text(encoding="utf-8"),
    verb="read",
    resource_fn=lambda args: path_resource(args["path"], workspace_root=workspace),
)

tool_call = {
    "id": "call_abc123",
    "type": "function",
    "function": {"name": "read_note", "arguments": '{"path": "notes.txt"}'},
}
response_message = adapter.execute_call(tool_call)
```

See [`examples/agent_function_calling.py`](../../examples/agent_function_calling.py) for an end-to-end example showing prompt-injected outbound HTTP calls blocked deterministically via `ProvenanceItem(..., trust="untrusted")`.

### LangChain Tool Wrapper

```python
from actentra import wrap_langchain_tool

safe_tool = wrap_langchain_tool(existing_langchain_tool, boundary, verb="read")
safe_tool.invoke({"path": "notes.txt"})
```

---

## 5. CLI Policy Setup & Simulation

Generate a starter policy scoped to your current workspace:

```powershell
actentra init --workspace .
actentra policy check actentra.policy.yaml
```

Simulate actions without executing them:

```powershell
# Test an allowed read
actentra dry-run -p actentra.policy.yaml -t fs.read -r "path:C:/work/notes.txt" -v read

# Test a blocked sensitive file (.env)
actentra dry-run -p actentra.policy.yaml -t fs.read -r "path:C:/work/.env" -v read
```

---

## 6. Local HTTP Gateway & Operator Console

For multi-process agents or human-in-the-loop review via the web console:

```powershell
actentra serve --policy actentra.policy.yaml --workspace . --port 8080
```

- **REST API Endpoint**: `http://127.0.0.1:8080/v1/crossings`
- **Operator Console UI**: `http://127.0.0.1:8080/ui`
- **Health Check**: `http://127.0.0.1:8080/health`

See [`examples/gateway_http_example.py`](../../examples/gateway_http_example.py) for programmatic HTTP server + client usage, and [`examples/gateway_demo.py`](../../examples/gateway_demo.py) for the restart-safe approval lifecycle demo.

> **Controlled-Pilot / Production Note:** Remote non-loopback bindings require TLS/mTLS (`--cert`, `--key`, `--ca-certs`, `--require-client-cert`), mapped principal credentials, and an external `CheckpointAnchor` + `KeyRing`. See [docs/security/audits/ACTENTRA_POST_REMEDIATION_AUDIT.md](../security/audits/ACTENTRA_POST_REMEDIATION_AUDIT.md) and [docs/security/guarantees-and-limits.md](../security/guarantees-and-limits.md).

---

## 7. Audit Reports & Hash-Chain Verification

```powershell
actentra report receipts.db --html audit_report.html
actentra verify-log receipts.db --verify-envelopes
```
