# Actentra Quickstart Guide

> Get started with Actentra in under 5 minutes. Time-to-first-block: < 10 minutes.

---

## 1. Installation

Actentra is designed for local-first, low-overhead environments (Windows 11, Intel i5, 8 GB RAM, CPU-only):

```powershell
# Clone the repository
git clone https://github.com/SiddardhaShayini/Actentra.git
cd Actentra

# Install Actentra in editable mode
pip install -e .
```

Verify installation:
```powershell
actentra --help
```

---

## 2. Initialize Starter Policy

Generate a fail-closed starter policy pack:

```powershell
actentra init
```

This creates `actentra.policy.yaml` with safe defaults:
- **Default verdict**: `deny` (strictly fail-closed)
- **Session rate limits**: 60 actions/minute
- **Session cumulative budgets**: max 100 actions, max 20 external calls
- **Allowed rules**: Read-only workspace queries
- **Blocked rules**: Traversal escapes, sensitive credential files (`.env`, `.ssh`), and unapproved deletions

Validate the policy:
```powershell
actentra policy check actentra.policy.yaml
```

---

## 3. Protecting Your Python Agent Tools

### Option A: Direct Boundary Execution

```python
from pathlib import Path
from actentra import Boundary
from actentra_core.policy import load_policy_file
from actentra_core.receipts import ReceiptStore

# Load policy and durable receipt store
policy = load_policy_file("actentra.policy.yaml")
store = ReceiptStore("receipts.db")
boundary = Boundary(policy=policy, receipt_store=store, session_id="session-001")

def read_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")

# Execute safely through the boundary
content = boundary.execute(
    tool="fs.read",
    verb="read",
    resource=f"path:{Path('notes.txt').resolve().as_posix()}",
    params={"path": "notes.txt"},
    fn=lambda _env, _dec: read_file("notes.txt"),
)
print("File content:", content)
```

### Option B: The `@guard` Decorator

```python
@boundary.guard(
    tool="fs.read",
    verb="read",
    resource_fn=lambda path: f"path:{Path(path).resolve().as_posix()}",
)
def protected_reader(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")

# Calls are intercepted, evaluated against policy, and receipts are recorded
data = protected_reader("notes.txt")
```

---

## 4. Using Adapters (LangChain & OpenAI)

### OpenAI Function Calling Adapter
```python
from actentra import Boundary, FunctionCallAdapter

adapter = FunctionCallAdapter(boundary)
adapter.register_tool("fetch_data", my_tool_function, verb="read")

# Intercept tool calls returned by OpenAI API
tool_call = {
    "id": "call_abc123",
    "type": "function",
    "function": {"name": "fetch_data", "arguments": '{"query": "revenue"}'}
}
response_message = adapter.execute_call(tool_call)
```

### LangChain Tool Wrapper
```python
from actentra import wrap_langchain_tool

# Wrap any existing LangChain tool
safe_tool = wrap_langchain_tool(existing_langchain_tool, boundary, verb="read")
safe_tool.invoke({"path": "C:/work/data.csv"})
```

---

## 5. Simulating with Dry-Run Mode

Predict policy verdicts without executing actions or modifying system state:

```powershell
# Test an allowed action
actentra dry-run -p actentra.policy.yaml -t fs.read -r "path:C:/work/notes.txt" -v read

# Test a blocked sensitive action
actentra dry-run -p actentra.policy.yaml -t fs.read -r "path:C:/work/.env" -v read
```

---

## 6. Running the Local HTTP Gateway & Operator Console

Launch the zero-dependency background HTTP service and human approval web UI:

```powershell
actentra serve --policy actentra.policy.yaml --port 8080
```

- **REST API Endpoint**: `http://127.0.0.1:8080/v1/crossings`
- **Operator Console UI**: `http://127.0.0.1:8080/ui`
- **Health Check**: `http://127.0.0.1:8080/health`

When an action triggers an `ASK` verdict, it appears in the Operator Console where a human operator can review the exact diff, tool parameters, and risk tags before granting approval.

---

## 7. Generating Standalone HTML Audit Reports

Generate a self-contained, offline HTML report from your receipt database:

```powershell
actentra report receipts.db --html audit_report.html
```

Open `audit_report.html` in any browser to inspect:
- SHA-256 hash-chain verification status
- Allowed vs. Denied vs. Asked breakdown
- Chronological timeline table with canonical hashes and risk badges

---

## 8. Verifying Hash-Chain Integrity

Verify that logs have not been tampered with or truncated:

```powershell
actentra verify-log receipts.db
```
Outputs:
```
OK verified 42 record(s); head=sha256:7f83b165...
```
