# Public API Reference

This reference documents Actentra's **public Python SDK (`actentra`)** and **CLI (`actentra`)**. Internal modules and private helpers (such as `_execute_internal`, `_dispatch_and_record`, and internal SQLite row helpers) are not guaranteed public interfaces.

---

## 1. Python SDK (`actentra`)

Public exports in `actentra.__all__`:

### `Boundary`

Deterministic execution boundary mediating tool calls against policy, approvals, warrants, postconditions, and SQLite WAL receipts.

#### `Boundary.from_yaml(...) -> Boundary`
- **Purpose:** Construct a `Boundary` from an inline YAML policy string and SQLite receipt database path.
- **Key Parameters:**
  - `policy_yaml: str` — YAML policy document.
  - `receipts_db: str | Path` — Path to SQLite receipt database.
  - `workspace_root: str | Path | None = None` — If provided, registers `LocalFSExecutor` and `WorkspaceFileVerifier`.
  - `session_id: str = "default"`, `agent_id: str = "default-agent"`, `framework: str = "python-sdk"`, `model: str = "unknown"`.
  - `approval_callback: ApprovalCallback | None = None`, `approval_ttl_seconds: float = 300.0`.
  - `secrets_broker: SecretsBroker | None = None`, `warrant_public_key: bytes | None = None`, `warrant_registry: WarrantRegistry | None = None`, `verifier: Any | None = None`, `caller_context: CallerContext | None = None`.
- **Errors:** `PolicyValidationError`, `DatabaseUnavailableError`.
- **Security Implications:** Fails closed if the policy is invalid or the receipt database is corrupted. Automatically runs `recover_system_state()` on startup.

#### `Boundary.from_files(*, policy_path, receipts_db, ...) -> Boundary`
- **Purpose:** Construct a `Boundary` from a YAML policy file on disk and SQLite DB path.
- **Errors:** `FileNotFoundError`, `PolicyValidationError`, `DatabaseUnavailableError`.

#### `Boundary.register_fs(workspace_root, *, configure_verifier=True) -> LocalFSExecutor`
- **Purpose:** Register `LocalFSExecutor` for `fs.list`, `fs.read`, `fs.write`, `fs.delete` and optionally configure `WorkspaceFileVerifier`.
- **Security Implications:** Confines filesystem operations to `workspace_root`; rejects traversal, ADS, 8.3 names, and reparse points.

#### `Boundary.register_sqlite(db_path) -> ScopedSQLiteExecutor`
- **Purpose:** Register `ScopedSQLiteExecutor` for `sql.execute`.
- **Security Implications:** Enforces single-statement SQL and `sqlite3.set_authorizer` table/command restrictions.

#### `Boundary.register_http(allowed_hosts=None) -> ScopedHTTPExecutor`
- **Purpose:** Register `ScopedHTTPExecutor` for `http.get`, `http.post`, `http.request`.
- **Security Implications:** Enforces HTTP/HTTPS only, `PinningDNSResolver`, and `SSRFSafeRedirectHandler` blocking private/loopback/metadata IPs.

#### `Boundary.register_executor(tool_name, fn) -> None`
- **Purpose:** Register a custom callable `(ActionEnvelope, Decision) -> Any` for `Boundary.run()`.
- **Errors:** `ValueError` if `tool_name` is empty.

#### `Boundary.run(*, tool, verb, resource, params=None, fn=None, ..., verify_postcondition=False, postcondition_claim=None, postcondition_expected_digest=None, raise_on_postcondition_failure=False, strict_postconditions=False, caller_context=None, raise_on_blocked=True) -> ExecutionResult`
- **Purpose:** Evaluate policy, enforce approvals/warrants, execute the registered tool (or `fn`), verify postconditions if requested, and return an `ExecutionResult`.
- **Errors:** `ActentraError` (missing executor), `ActionBlockedError` (if `raise_on_blocked=True`), `PostconditionFailedError` (if `raise_on_postcondition_failure=True`), `CanonicalizationError`, `ExecutorError`, `IdempotencyError`.
- **Security Implications:** Enforces Invariants I1–I5, I13, I14, and I16. Never promotes unverified required postconditions to `succeeded`.

#### `Boundary.execute(*, tool, verb, resource, params=None, fn, ...) -> Any`
- **Purpose:** Lower-level execution method returning the raw callable result directly (raises `ActionBlockedError` on block).

#### `Boundary.dry_run(*, tool, verb, resource, params=None, ..., record_receipt=False) -> Decision`
- **Purpose:** Simulate policy, warrant, risk, and budget evaluation without executing or consuming rate-limit buckets.

#### `Boundary.guard(*, tool, verb, resource_fn) -> Callable[[F], F]`
- **Purpose:** Decorator wrapping a Python function behind `Boundary.execute()`.

#### `Boundary.inspect_crossing(crossing_id: str) -> CrossingReceipt`
- **Purpose:** Retrieve decision receipt, outcome receipt, observation, envelope, lifecycle state, and `verified` flag for a crossing.

#### `Boundary.verify_receipts(*, verify_envelopes=True) -> VerificationResult`
- **Purpose:** Verify local SQLite SHA-256 hash-chain and envelope integrity (`verify_log`).
- **Security Implications:** Detects local corruption/edits; does not replace externally anchored `CheckpointAnchor` verification against a DB editor.

#### `Boundary.verify_state(resource, claim="exists", *, crossing_id=None, expected_digest=None, ttl_seconds=60.0) -> ObservationRecord`
- **Purpose:** Run the configured verifier (e.g., `WorkspaceFileVerifier`) and persist an `ObservationRecord` (and `EvidenceRecord` if verified for a crossing).
- **Errors:** `ValueError` if no verifier is configured.

#### `Boundary.reconcile_outcome(crossing_id: str, observation: ObservationRecord | None = None) -> Any`
- **Purpose:** Reconcile an `unknown` outcome using verified observation evidence.
- **Errors:** `ReceiptError` if crossing is not in `unknown` state or observation is invalid.

```python
from pathlib import Path
from actentra import Boundary, path_resource

ws = Path("./workspace").resolve()
ws.mkdir(exist_ok=True)
boundary = Boundary.from_yaml(
    policy_yaml=f"""
version: 1
policy_id: ref-ex
mode: enforce
defaults: {{verdict: deny, reason: "deny"}}
rules:
  - id: allow-read
    match: {{tool: fs.read, verb: read, resource: "path:{path_resource(ws).removeprefix('path:')}/**"}}
    verdict: allow
""",
    receipts_db="receipts.db",
    workspace_root=ws,
)
```

---

### Helper Functions & Data Models

- **`path_resource(path: str | Path, *, workspace_root: str | Path | None = None) -> str`**
  - Canonicalizes a path into `path:<canonical_path>`, anchoring relative paths to `workspace_root` and rejecting `..` escapes (`CanonicalizationError`).
- **`cli_approval_prompt(envelope: ActionEnvelope, decision: Decision) -> bool`**
  - Interactive terminal prompt for `ASK` verdicts binding approval to exact `canonical_hash`.
- **`ExecutionResult`** — Frozen dataclass with `crossing_id`, `allowed`, `verdict`, `rule_id`, `reason`, `status`, `evidence_status`, `verified`, `result`, `result_hash`, `canonical_hash`, `decision_receipt`, `outcome_receipt`, `observation`, and `.to_dict()`.
- **`CrossingReceipt`** — Frozen dataclass with `crossing_id`, `decision`, `outcome`, `observation`, `envelope`, `lifecycle_state`, `verified`, and `.to_dict()`.
- **`ProvenanceItem(source: str, trust: Literal["trusted", "untrusted", "unknown"])`** — Attaches provenance metadata to actions; `"untrusted"` taints the session and principal.
- **`Verdict`** (`ALLOW`, `ALLOW_WITH_CONSTRAINTS`, `ASK`, `DENY`, `HOLD`) and **`Decision`**.
- **`PolicyPack`**, **`load_policy_file(path)`**, **`load_policy_yaml(yaml_str)`**.
- **`ReceiptStore(db_path)`**, **`ReceiptRecord`**, **`VerificationResult`**, **`verify_log(db_path, *, verify_envelopes=True)`**.

---

### Agent Adapters

- **`FunctionCallAdapter(boundary, *, raise_on_blocked=False, caller_context=None)`**
  - `register_tool(name, fn, *, verb=None, resource_fn=None, description="") -> None`
  - `execute_call(tool_call, *, provenance=(), user_goal=None, caller_context=None, idempotency_key=None) -> dict[str, Any]`
  - Returns an OpenAI-compatible `{"role": "tool", "tool_call_id": ..., "name": ..., "content": ...}` dict; blocks return JSON error payloads unless `raise_on_blocked=True`.
- **`LangChainToolWrapper(tool, boundary, ...)`** / **`wrap_langchain_tool(tool, boundary, ...)`**
  - Mediates `.invoke(...)` and `.run(...)` through `Boundary.execute()`.

---

### Executors, Verifiers & Secrets

- **`LocalFSExecutor` / `ScopedFSTools`** — Confined filesystem operations (`fs.list`, `fs.read`, `fs.write`, `fs.delete`). Raises `ExecutorError` / `CanonicalizationError`.
- **`ScopedSQLiteExecutor` / `ScopedSQLiteTools`** — Single-statement SQLite execution with `set_authorizer`. Raises `ExecutorError`.
- **`ScopedHTTPExecutor` / `ScopedHTTPTools`** — SSRF-defended HTTP/HTTPS requests. Raises `ExecutorError`.
- **`WorkspaceFileVerifier(workspace_root, *, default_ttl_seconds=60.0)`** — Read-only file existence, absence, and SHA-256 digest verifier (50 MiB cap).
- **`SecretsBroker`**, **`dpapi_protect`**, **`dpapi_unprotect`**, **`SecretsError`** — Encrypts credentials at rest (Windows DPAPI; AES-256-GCM fallback on POSIX) and scrubs secrets from logs/errors.

---

### Errors

`ActentraError`, `ActionBlockedError`, `PostconditionFailedError`, `CanonicalizationError`, `ExecutorError`, `PolicyValidationError`, `SecretsError`.

---

## 2. CLI (`actentra`)

Run `actentra --help` or `actentra <command> --help` for full flags:
- **Setup & Policy:** `actentra init`, `actentra policy check`, `actentra policy canary`, `actentra dry-run`
- **Execution & Gateways:** `actentra run`, `actentra serve`, `actentra mcp-proxy`, `actentra demo`, `actentra demo-gateway`, `actentra replay`
- **Audit & Verification:** `actentra verify-log`, `actentra export-log`, `actentra archive-log`, `actentra report`, `actentra bundle export`, `actentra bundle verify`
- **Checkpoints & Warrants:** `actentra checkpoint keygen|sign|verify|verify-trail`, `actentra warrant issue|verify`
- **Approvals, Lifecycle & Metrics:** `actentra approvals list|resolve`, `actentra lifecycle show|transitions`, `actentra metrics`
- **Coordination & Evidence:** `actentra observation verify|list|show`, `actentra evidence list|show`, `actentra lease acquire|release|list|show`, `actentra handoff create|advance|verify|show|list`, `actentra trace show|link|list|delete`
