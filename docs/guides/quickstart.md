# Actentra Installation & Quickstart Guide

Get started with Actentra in under 5 minutes — verified installation, local `Boundary`, policy configuration, executor registration, authorized vs. blocked actions, postcondition verification, and receipt inspection.

---

## 1. Installation

Requires **Python 3.12+**.

```powershell
pip install actentra
```

Or with `uv`:

```powershell
uv add actentra
```

### From a local clone (for development)

```powershell
git clone https://github.com/SiddardhaShayini/Actentra.git
cd Actentra

# Option A: using uv
uv sync --extra dev

# Option B: using pip in a virtual environment
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

Verify installation:

```powershell
uv run actentra --help
uv run python -c "from actentra import Boundary, path_resource; print('Actentra ready')"
```

---

## 2. Complete Local Python Workflow (Authorized + Blocked + Verified + Receipt)

The example below creates a local `Boundary`, configures a YAML policy, registers `LocalFSExecutor` and `WorkspaceFileVerifier` (via `workspace_root`), performs an authorized postcondition-verified write, blocks an unauthorized `.env` read, and inspects the hash-chained SQLite receipts:

```python
from pathlib import Path
from actentra import ActionBlockedError, Boundary, path_resource

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
  - id: deny-env-files
    match:
      resource: "**/.env*"
    verdict: deny
    reason: "Sensitive .env access denied"

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

# 1. Create a local Boundary (automatically registers fs.* executors and WorkspaceFileVerifier)
boundary = Boundary.from_yaml(
    policy_yaml=POLICY_YAML,
    receipts_db="receipts.db",
    workspace_root=workspace,
    approval_callback=lambda env, dec: True,  # or `cli_approval_prompt` for interactive CLI
)

# 2. Perform an authorized action with strict digest postcondition verification
res = boundary.run(
    tool="fs.write",
    verb="write",
    resource=path_resource("notes.txt", workspace_root=workspace),
    params={"content": "Hello from Actentra!\n", "create_parents": True},
    verify_postcondition=True,
    raise_on_postcondition_failure=True,
)
print("Authorized:", res.crossing_id, res.verdict.value, res.status, res.evidence_status, res.verified)

# 3. Attempt an unauthorized action (.env read) — fails closed with ActionBlockedError
try:
    boundary.run(
        tool="fs.read",
        verb="read",
        resource=path_resource(".env", workspace_root=workspace),
    )
except ActionBlockedError as exc:
    print("Blocked:", exc.decision.verdict.value, exc.decision.rule_id)

# 4. Inspect durable receipt & verify SQLite SHA-256 hash chain
receipt = boundary.inspect_crossing(res.crossing_id)
print("Lifecycle:", receipt.lifecycle_state, "Chain OK:", boundary.verify_receipts().ok)
```

You can also register additional built-in executors on any `Boundary`:
- `boundary.register_fs(workspace_root)` — `fs.list`, `fs.read`, `fs.write`, `fs.delete` + `WorkspaceFileVerifier`
- `boundary.register_sqlite(db_path)` — `sql.execute` (single-statement, authorizer-enforced)
- `boundary.register_http(allowed_hosts=[...])` — `http.get`, `http.post`, `http.request` (SSRF & DNS-rebinding defended)
- `boundary.register_executor("my.tool", fn)` — custom `Callable[[ActionEnvelope, Decision], Any]`

See runnable scripts in [`examples/`](../../examples/):
- [`examples/minimal_file_write.py`](../../examples/minimal_file_write.py)
- [`examples/minimal_blocked_action.py`](../../examples/minimal_blocked_action.py)
- [`examples/agent_function_calling.py`](../../examples/agent_function_calling.py)

---

## 3. CLI Policy Check, Dry-Run, & Log Verification

```powershell
# Generate a starter policy scoped to your current workspace
uv run actentra init --workspace .
uv run actentra policy check actentra.policy.yaml

# Simulate an allowed read vs. a blocked .env read
uv run actentra dry-run -p actentra.policy.yaml -t fs.read -r "path:C:/work/notes.txt" -v read
uv run actentra dry-run -p actentra.policy.yaml -t fs.read -r "path:C:/work/.env" -v read

# Verify SQLite hash-chain & envelope integrity
uv run actentra verify-log receipts.db -e
```

---

## 4. Next Steps

- [AI-Agent Integration Guide](ai-agent-integration.md) — `FunctionCallAdapter`, `LangChainToolWrapper`, and `MCPStdioProxy`.
- [Developer Guide](developer-guide.md) — Custom executors, policies, approvals, and error handling.
- [Deployment Guide](deployment.md) — Remote gateway with TLS/mTLS, checkpoints, and controlled-pilot restrictions.
- [Formal Security Model](../../ACTENTRA_SECURITY_MODEL.md) — Complete security contract and trust boundaries.
