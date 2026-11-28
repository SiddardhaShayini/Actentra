<p align="center">
  <img src="assets/actentra-logo-dark.svg" alt="Actentra" width="260" />
</p>

# Actentra

> *Intelligence proposes. Actentra decides.*

**Actentra** is a lightweight, local-first deterministic execution boundary for AI agents. It sits between any model or agent framework and real-world tools—canonicalizing each tool call, evaluating deterministic YAML policies and risk tags, binding human approvals to an exact action hash, verifying postconditions, and writing tamper-evident hash-chained receipts.

> **Documentation:** Start with the **[Documentation Index](docs/README.md)**, **[Quickstart Guide](docs/guides/quickstart.md)**, and **[Formal Security Model](ACTENTRA_SECURITY_MODEL.md)**.

### How Actentra Differs & What It Does Not Solve
- **Unlike agent frameworks or tool routers:** Actentra puts **zero LLMs** in the enforcement path; every decision is deterministic, canonicalized, and persisted before execution.
- **Unlike simple permission checks:** Actentra binds approvals to exact `canonical_hash` values, tracks durable principal taint/budgets across restarts, gates success on postcondition verification, and records hash-chained receipts.
- **Explicit non-goals:** Actentra is an in-process Python execution boundary, **not** an OS-level sandbox or container. It cannot protect unmediated OS/API paths outside Actentra, make an LLM reason correctly within allowed bounds, or defend against a compromised host administrator. See [ACTENTRA_SECURITY_MODEL.md](ACTENTRA_SECURITY_MODEL.md) and [ACTENTRA_POST_REMEDIATION_AUDIT.md](docs/security/audits/ACTENTRA_POST_REMEDIATION_AUDIT.md) (controlled-pilot verdict).

---

## Key Highlights

- **Persistent Pending Approvals:** Human approval requests (`ASK`) are durably stored in SQLite WAL, surviving process restarts and power cycles with strict single-use hash binding and TTL expiration.
- **Transactional Action Lifecycle State Machine:** Strict formal state transitions (`created` -> `authorized` -> `approved` -> `claimed` -> `executing` -> `verification_pending` -> `succeeded`/`failed`/`unknown`/`reconciliation_required`) with historical state transition auditing.
- **Durable Idempotency Engine:** Prevents replay side effects across process boundaries, returns cached results on exact replay without re-dispatching tools, and flags interrupted executions for reconciliation.
- **Typed Application Services:** Modular `AppServices` and `ExecutorRegistry` unifying CLI, SDK, and Web UI.
- **Unified Local Operator Console:** 7-tab embedded offline web application at `/ui` (Overview, Approvals Inbox, Policy Viewer & Linter, Dry-Run Simulator, Paginated Receipts Explorer, Integrations, Settings).
- **Bounded Paged Receipts & Offline Audit Bundles:** Paged queries, keyword search, and one-click JSON/JSONL export bundles with integrity verification.
- **Zero LLM in the Enforcement Path:** Policy evaluation is 100% deterministic, reproducible, and explainable in sub-millisecond time.
- **Strictly Fail-Closed & Local-Only Posture:** Loopback binding by default (`127.0.0.1`), strictly typed fail-closed approval API, origin isolation rejecting untrusted cross-origin browser requests, compulsory token auth for remote binding.
- **SSRF-Defended HTTP & Scoped Executors:** Built-in executors for Filesystem, SQLite, and HTTP with private IP / metadata blocking and parameter constraints.
- **DPAPI Secrets Broker & Credential Resolution:** Encrypts tool secrets with Windows DPAPI at rest, resolves credential references (`secret:<NAME>`) dynamically during HTTP execution, and scrubs secrets from logs, errors, and responses.
- **Dynamic Session Taint Tracking:** Automatically labels sessions tainted upon reading untrusted content (indirect prompt injection defense) and blocks untrusted network egress.
- **Cumulative Session Budgets:** Enforces caps on total actions, write bytes, and external calls across both gateway and external executions to prevent infinite loops and slow-drip exfiltration.
- **Cryptographic Capability Warrants:** Scoped, expiring Ed25519-signed delegation tokens for subagents with cryptographic signature verification, holder matching, scope enforcement, and use-quota tracking integrated into Boundary.
- **Bounded Streaming Audit Log & Archival:** Memory-bounded streaming log iteration, chunked export, envelope-integrity verification, and standalone SQLite archive partitioning.
- **Policy Canary Diff Engine:** Replays recorded agent traffic against proposed policies to detect regressions with context integrity, provenance, and temporal window modeling.
- **Standalone HTML Audit Reports:** Generates zero-external-CDN audit reports with SVG security badges and chronological timelines.
- **Operational Metrics & Telemetry:** Built-in latency percentiles (p50, p95, p99, max), failure counters, and secret scrubbing exposed via `GET /v1/metrics` and `actentra metrics`.
- **Agent Framework & MCP Adapters:** First-class adapters for LangChain, OpenAI function calling, and MCP stdio proxy with anti-rug-pull schema pinning (CVE-2025-54136) and caller context propagation.

---

## Repository Layout

- [`core/actentra_core/`](core/actentra_core/) — Pure, deterministic enforcement kernel:
  - Envelope builder, Windows path, URL, SQL, and JSON canonicalizers
  - Deterministic risk tagger (`destructive`, `external-egress`, `privilege-escalation`, `budget-exceeded`)
  - Deny-overrides YAML policy engine with session rate limits and cumulative budgets
  - Hash-chained SQLite WAL receipt store with outcome recovery
  - Ed25519 signed checkpoints (`sign_checkpoint`, `verify_checkpoint`)
  - Policy Canary diff engine (`run_policy_canary`)
  - Standalone HTML audit report renderer (`render_html_report`)
  - Cryptographic capability tokens (`Warrant`, `issue_warrant`, `verify_warrant`)
- [`executors/actentra_executors/`](executors/actentra_executors/) — Scoped, defended executors:
  - `LocalFSExecutor` & `ScopedFSTools` (directory traversal rejection, ADS/8.3 rejection, constraints)
  - `ScopedSQLiteExecutor` & `ScopedSQLiteTools` (single-statement SQL, parameterized queries, `read_only`, `max_rows`)
  - `ScopedHTTPExecutor` & `ScopedHTTPTools` (SSRF defense, metadata & private IP blocking, wildcard host allowlists)
- [`gateway/actentra_gateway/`](gateway/actentra_gateway/) — Integration gateways:
  - `MCPStdioProxy` & `serve_stdio` (anti-rug-pull schema pinning for CVE-2025-54136)
  - `ActentraHTTPServer` & `serve_http` (`/v1/crossings` REST API + `/ui` Operator Console)
- [`sdk/python/actentra/`](sdk/python/actentra/) — Thin in-process Python SDK:
  - `Boundary` & `@guard` decorator
  - `SecretsBroker` (Windows DPAPI encryption + secret redaction)
  - `FunctionCallAdapter` (OpenAI / Anthropic function calling format)
  - `LangChainToolWrapper` (duck-typed wrapper for LangChain tools)
- [`cli/actentra_cli/`](cli/actentra_cli/) — Typer CLI commands:
  - `init`, `policy check`, `policy canary`, `dry-run`, `serve`, `report`, `run`, `replay`, `mcp-proxy`, `checkpoint`, `warrant`, `verify-log`, `export-log`, `demo`, `lifecycle`, `metrics`
- [`spec/`](spec/) — Draft 2020-12 JSON Schemas for Envelope, Policy, and Receipt v1
- [`policies/examples/`](policies/examples/) — Starter policy packs
- [`corpus/`](corpus/) — Documented real-world agent incident corpus (32 incidents), red-team attacks, and benign actions
- [`docs/`](docs/) — [Quickstart Guide](docs/guides/quickstart.md), [Architecture & Design](docs/architecture/architecture.md), [Threat Model](docs/security/threat-model.md), [Guarantees & Limits](docs/security/guarantees-and-limits.md), [Product Status](docs/product-status.md), [Naming Clearance Checklist](docs/development/naming-clearance.md)
- [`scripts/windows/`](scripts/windows/) — Resilient background runner (`run_gateway.ps1`) for Windows Task Scheduler
- [`tests/`](tests/) — Complete test suite (unit, golden, chaos, replay, Hypothesis properties, performance)

---

## Quick Start (5 Minutes)

> **Installation:** Install Actentra (`>=3.12`) with `pip install actentra` (or `uv add actentra`). See [docs/guides/quickstart.md](docs/guides/quickstart.md) for source/editable and gateway setup.

### 1. Verification & Test Suite

```powershell
# Run Ruff linting, Mypy strict type-checking, and full test suite
.venv\Scripts\ruff check core executors gateway sdk cli tests
.venv\Scripts\mypy
.venv\Scripts\pytest -v
```

### 2. Simulate Actions with Dry-Run Mode

```powershell
# Allowed workspace read
.venv\Scripts\actentra dry-run -p policies/examples/starter.yaml -t fs.read -r "path:C:/work/notes.txt" -v read

# Blocked privilege escalation attempt (.env file)
.venv\Scripts\actentra dry-run -p policies/examples/starter.yaml -t fs.read -r "path:C:/work/.env" -v read
```

### 3. Run the Restart-Safe Action Demonstration

```powershell
# Execute the complete end-to-end restart-safe lifecycle demonstration
# (Allowed read -> ASK delete -> process restart -> approval -> restart -> execution -> duplicate rejection -> verify)
.venv\Scripts\actentra demo --gateway
```

### 4. Launch the Local Operator Console

```powershell
.venv\Scripts\actentra serve --policy policies/examples/starter.yaml --port 8080
```
- Open `http://127.0.0.1:8080/ui` in your browser to view pending approvals, verify hash-chain integrity, and inspect active crossings.

### 5. Generate an HTML Audit Report

```powershell
.venv\Scripts\actentra report receipts.db --html audit_report.html
```

### 6. Replay 32 Documented Agent Incidents

```powershell
.venv\Scripts\actentra replay corpus/incidents/agent_incidents.jsonl --policy policies/examples/starter.yaml
```

---

## Python SDK Example

```python
from pathlib import Path
from actentra import Boundary, path_resource

workspace = Path("./workspace").resolve()
workspace.mkdir(exist_ok=True)
ws = path_resource(workspace).removeprefix("path:")

policy_yaml = f"""
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
"""

boundary = Boundary.from_yaml(
    policy_yaml=policy_yaml,
    receipts_db="receipts.db",
    workspace_root=workspace,
)

# Evaluate, execute through LocalFSExecutor, and inspect the durable receipt
res = boundary.run(
    tool="fs.read",
    verb="read",
    resource=path_resource("notes.txt", workspace_root=workspace),
)
print(res.verdict.value, res.status, res.result)
```

For runnable examples (file writes with postcondition verification, blocked actions, HTTP gateway, and AI-agent function-calling integration), see [`examples/`](examples/).

---

## Guarantees and Limits

Actentra is designed to **fail closed**, bind approvals to exact `sha256` action hashes, and persist durable decision records before execution. See [docs/security/guarantees-and-limits.md](docs/security/guarantees-and-limits.md) for explicit architectural boundaries and non-goals.
