# Actentra — Project Memory

## Project summary

Actentra is a planned lightweight, local-first execution boundary for AI agents. It mediates consequential tool actions through deterministic policy checks, optional human approval, constrained execution, and tamper-evident audit records. Enforcement must not depend on an LLM. The current plan prioritizes an in-process Python SDK and a narrowly scoped MVP before adding a daemon, HTTP API, or more connectors.

The project has evolved into a functional local-first authorization engine and operator console prototype (V3 Foundation & Core). See [PLAN_V3.md](./PLAN_V3.md) for the strategic engineering roadmap and current backlog, [docs/product-status.md](./docs/product-status.md) for the authoritative capability matrix, and [PLAN.md](./PLAN.md) for architectural foundations.

## Required context for agents

1. Before making project changes, read **both `PLAN.md` and `PROJECT_MEMORY.md`**. Use `PLAN.md` for product and technical direction; use this file for durable project context and change history.
2. Keep the implementation aligned with the plan. If new information requires changing direction, explain the reason and update the relevant plan and this memory file.
3. Keep changes focused, preserve existing work, and validate changes with the lightest relevant checks.

## Hardware and lightweight-work rules

Development is on a **Windows 11 laptop with 8 GB RAM, an Intel i5 CPU, and no GPU**. Lightweight operation is a core requirement:

- Avoid actions likely to cause out-of-memory conditions, sustained high memory use, CPU saturation, or disruptive lag.
- Prefer small, incremental work and bounded processes, workers, queues, test data, and timeouts. Avoid unnecessary parallel builds or test runs.
- Do not start heavy VMs, Docker, large model downloads, GPU/ML stacks, load tests, fuzzing, or other resource-intensive jobs on the laptop by default. Keep heavy or long-running checks opt-in or in CI where practical.
- Do not enable a background daemon or automatic startup by default. Ask before an action whose resource impact is uncertain or potentially disruptive.
- Treat resource figures in `PLAN.md` as targets to measure on the actual device, not guarantees.

## Memory maintenance rules

Agents working on this project must maintain this file as the durable handoff:

- After creating, editing, moving, or deleting project files, add a dated and timed log entry describing **what changed and why**.
- Record relevant decisions, assumptions, mistakes, corrections, and lessons learned. Clearly label unverified assumptions; do not present guesses as facts.
- Keep entries concise but useful to the next agent. Include affected paths and validation performed or explain why validation was not run.
- Preserve earlier history; append new entries rather than silently replacing prior logs. Correct inaccuracies with a follow-up entry.
- Do not record secrets, credentials, or unnecessary personal data here.

## Change log

### 2026-11-12 16:29 IST

- Created `PROJECT_MEMORY.md` with an Actentra overview, mandatory reading and update rules, and laptop resource safeguards.
- Why: provide future agents a concise durable handoff and reinforce the 8 GB Windows laptop constraint.
- Assumptions/lessons: the project remains in Phase 0 and Actentra is the chosen name, but clearance is still pending as stated in `PLAN.md`.
- Validation: documentation-only; no tests run.

### 2026-11-12 18:22 IST

- Initialized git repository and built Phase 0 + early Phase 1 kernel/SDK/CLI foundations in `d:\Actentra`:
  - Repo & docs: `.gitignore`, `LICENSE` (Apache-2.0), `SECURITY.md`, `README.md`, `pyproject.toml`, `.github/workflows/ci.yml`, `docs/threat-model.md`, `docs/guarantees-and-limits.md`, `docs/naming-clearance.md`, `policies/examples/starter.yaml`, `corpus/README.md`, `corpus/redteam/windows_paths.jsonl`, `corpus/benign/sample_actions.jsonl`.
  - JSON Schemas (`spec/`): `envelope.v1.schema.json`, `policy.v1.schema.json`, `receipt.v1.schema.json`.
  - Enforcement kernel (`core/actentra_core/`): `verdict.py`, `canonicalize.py` (strict Windows path canonicalizer, NFC unicode, deterministic JSON/SHA-256, segment-aware globbing), `envelope.py` (ULID `crossing_id`, `ActionEnvelope`, `canonical_hash`), `risk.py`, `policy.py` (deny-overrides YAML evaluator, bounded rate limits, shadow mode, kill switch, last-known-good `PolicyStore`), `receipts.py` (SQLite WAL append-only hash-chained decision/outcome records, crash recovery to `unknown`, `verify_log`, `export_jsonl`). Total kernel size: 1,762 lines.
  - SDK & CLI: `sdk/python/actentra/` (`Boundary`, `@guard`, hash-bound one-time `ApprovalGrant`, fail-closed handling) and `cli/actentra_cli/main.py` (`init`, `policy check`, `verify-log`, `export-log`, `demo`).
  - Tests (`tests/`): `unit/test_canonicalize.py`, `unit/test_policy.py`, `unit/test_receipts.py`, `golden/test_golden_sdk_cli.py`, `perf/test_resource_budget.py`.
- Why: establish the spec-first, fail-closed, local-first deterministic core and test harness before adding the first MVP connector.
- Mistakes/lessons caught during verification:
  1. `canonicalize_windows_path` initially called `.strip()` before segment validation, silently stripping a trailing space (`C:\work\trailing_space `) instead of rejecting it; fixed by rejecting leading/trailing whitespace prior to normalization.
  2. In `ReceiptStore._init_db`, `with self._connect() as conn:` did not close the SQLite handle (Python `sqlite3` context manager commits/rolls back rather than closing), causing a Windows `PermissionError` during temp-dir cleanup; fixed with explicit `try ... finally: conn.close()`.
- Assumptions & open items:
  - Used Apache-2.0 default license, in-process Python SDK first, and `PyYAML`/`typer`/`pytest`/`jsonschema`/`psutil` already present in the Python 3.12.8 environment (`hypothesis`, `mypy`, and `ruff` are listed in `pyproject.toml` `[project.optional-dependencies].dev` and CI, not yet installed locally).
  - Real-world incident corpus (`corpus/incidents/`), trademark/name clearance searches, and selection of the first MVP connector (`fs` vs `sqlite` vs `http`) remain open for user confirmation (see `PLAN.md` Section 15).
- Validation: `python -m pytest -v` passed all 37 tests in 0.43s; standalone measurement of `actentra_core` showed 69.04 ms cold start and 23.34 MB RSS.

### 2026-11-12 18:32 IST

- Built the narrowly scoped Phase 1 MVP filesystem connector, expanded CLI/corpus/chaos/property tests, and set up the local `uv` `.venv`:
  - Connector (`executors/actentra_executors/`): `LocalFSExecutor` and `ScopedFSTools` supporting `fs.list`, `fs.read`, `fs.write`, `fs.delete` with strict `workspace_root` containment (`resolve_fs=True` and parent reparse check), `ALLOW_WITH_CONSTRAINTS` (`read_only`, `max_read_bytes`, `max_write_bytes`, `allowed_extensions`), and non-recursive single-file delete. Updated `pyproject.toml`, `policies/examples/starter.yaml`, and `README.md`.
  - CLI (`cli/actentra_cli/main.py`): added `actentra run` (end-to-end `LocalFSExecutor` + `Boundary` demo) and `actentra replay` (JSONL corpus replay against policy). Converted Typer parameters to `Annotated` form for Ruff `B008`.
  - Corpora & tests: added `corpus/incidents/README.md`, `corpus/incidents/agent_incidents.jsonl` (14 documented incident cases including CVE-2025-32711 EchoLeak, CVE-2025-54136 MCP Tool Poisoning, Replit DB wipe, `.env`/`.ssh`, Windows traversal/ADS/reserved names), expanded `corpus/benign/sample_actions.jsonl` (10 cases), and added `tests/unit/test_fs_executor.py`, `tests/chaos/test_chaos.py`, `tests/replay/test_replay_metrics.py`, and `tests/property/test_properties.py` (Hypothesis).
- Mistakes/lessons caught during verification:
  1. `canonicalize_resource` previously called `.strip()` before passing `path:...` to `canonicalize_windows_path`, which stripped trailing whitespace in `ScopedFSTools` calls (`"note.txt "`) instead of failing closed; fixed by not stripping `path:` payloads before `canonicalize_windows_path`.
  2. `LocalFSExecutor._resolve_target` initially checked `target.parent` containment even when `target == workspace_root` (breaking `fs.list(".")`); fixed by skipping parent check when `target == self._root_path`.
  3. Windows symlink/junction creation (`os.symlink`, `_winapi.CreateJunction`) raises `OSError`/`PermissionError` in restricted sandboxes; added a deterministic `monkeypatch` `realpath` reparse-escape test alongside the OS-privilege-gated junction/symlink tests.
- Validation (after final edit):
  - `.venv\Scripts\ruff check core executors sdk cli tests`: All checks passed.
  - `.venv\Scripts\mypy`: Success, 0 issues across 13 source files (`strict = true`).
  - `.venv\Scripts\pytest -v`: 52 passed, 2 skipped (OS-privileged symlink/junction creation) in 2.24s (note: `test_replay_metrics.py` verified 14/14 = 100% dangerous incidents stopped/escalated and 0/10 = 0% benign false positives).

### 2026-11-12 18:37 IST

- Added the Phase 2 MCP stdio proxy, expanded policy linting, and expanded the Phase 0 incident corpus to 32 cases:
  - Gateway (`gateway/actentra_gateway/mcp_proxy.py`): implemented `MCPStdioProxy`, `default_mcp_tool_mapper`, and `serve_stdio` (spawns downstream server without `shell=True`, intercepts `tools/call` through `Boundary`, pins `tools/list` tool-definition SHA-256 hashes to detect mid-session rug-pulls per CVE-2025-54136, and persists decision/outcome receipts).
  - Policy & CLI (`core/actentra_core/policy.py`, `cli/actentra_cli/main.py`): added `lint_policy` (flags shadow mode, missing limits, unscoped allow rules, missing reasons, and shadowed rules) surfaced via `actentra policy check`, plus `actentra mcp-proxy`. Updated `pyproject.toml`, `.github/workflows/ci.yml`, and `README.md`.
  - Incident corpus (`corpus/incidents/agent_incidents.jsonl`): expanded from 14 to 32 documented incidents spanning all four Section 3 failure classes (`mistake`, `manipulation`, `over-privilege`, `runaway`).
  - Tests: added `tests/unit/test_mcp_proxy.py` (including real subprocess pipe round-trip), `lint_policy` unit test in `tests/unit/test_policy.py`, and updated `tests/replay/test_replay_metrics.py` (`>= 30` incidents + all 4 failure classes).
- Validation (after final edit & editable reinstall via `uv pip install --python .venv\Scripts\python.exe -e . --no-deps --offline`):
  - `.venv\Scripts\ruff check core executors gateway sdk cli tests`: All checks passed.
  - `.venv\Scripts\mypy`: Success, 0 issues in 15 source files (`strict = true`).
  - `.venv\Scripts\pytest -v`: 56 passed, 2 skipped (OS-privileged symlink/junction creation) in 4.23s.
  - `.venv\Scripts\actentra replay corpus/incidents/agent_incidents.jsonl --policy policies/examples/starter.yaml`: `Replay complete: total=32 passed=32 failed=0`.
  - `.venv\Scripts\actentra policy check policies/examples/starter.yaml`: `OK policy=starter-local-v1 mode=enforce version=v1:sha256:6ac41c05171d rules=6 limits=1`.

### 2026-11-12 18:45 IST

- Added Ed25519 signed checkpoints, DPAPI Secrets Broker v1, and scoped parameterized SQLite executor:
  - Checkpoints (`core/actentra_core/checkpoints.py`, `cli/actentra_cli/main.py`): `generate_ed25519_keypair`, `sign_checkpoint`, `verify_checkpoint` (verifies Ed25519 signature + log integrity + head/seq anchoring), `write_checkpoint`, `load_checkpoint`, and `actentra checkpoint keygen/sign/verify`. Added `cryptography>=43.0` to `pyproject.toml`.
  - Secrets Broker (`sdk/python/actentra/secrets.py`, `sdk/python/actentra/boundary.py`): `SecretsBroker` with native Windows DPAPI `CryptProtectData`/`CryptUnprotectData` persistence (`dpapi_protect`, `dpapi_unprotect`), runtime secret retrieval, and `redact()` integrated into `Boundary` error handling (`I7`).
  - SQLite Executor (`executors/actentra_executors/sqlite.py`): `ScopedSQLiteExecutor` and `ScopedSQLiteTools` with single-statement validation (rejects `;` multi-statement injection, SQL comments, `ATTACH`/`DETACH`/`VACUUM`/`PRAGMA`), parameterized `args`, `read_only` (`mode=ro`) enforcement, and `max_rows` capping.
  - Tests: added `tests/unit/test_checkpoints.py`, `tests/unit/test_secrets_broker.py`, `tests/unit/test_sqlite_executor.py`, and fixed Hypothesis `_SAFE_SEGMENT` in `tests/property/test_properties.py` to exclude all Windows reserved names (`COM1`-`COM9`, `LPT1`-`LPT9`, etc.).
- Validation (after final edit):
  - `.venv\Scripts\ruff check core executors gateway sdk cli tests`: All checks passed.
  - `.venv\Scripts\mypy`: Success, 0 issues in 18 source files (`strict = true`).
  - `.venv\Scripts\pytest -v`: 62 passed, 2 skipped (OS-privileged symlink/junction creation) in 2.15s.

### 2026-11-13 11:15 IST

- Added Scoped HTTP Executor (SSRF-defended), HTML Audit Reporting, Agent Framework Adapters, and HTTP Gateway Service with Local Web Approval UI:
  - Scoped HTTP Executor (`executors/actentra_executors/http.py`): `ScopedHTTPExecutor` and `ScopedHTTPTools` featuring strict URL canonicalization, DNS resolution + SSRF defense (rejects `169.254.169.254` cloud metadata, `127.0.0.0/8`, private `10/8`, `172.16/12`, `192.168/16`), allowed hosts wildcard matching (`api.github.com`, `*.domain.com`), HTTP method filtering, bounded response size (1 MiB by default to stop memory bombs), and broker header secret injection.
  - Audit Reporting (`core/actentra_core/reporting.py`, `cli/actentra_cli/main.py`): `build_audit_summary` and `render_html_report` generating offline, zero-external-CDN HTML audit reports with SVG security badges, integrity verification status, verdict breakdown metrics, and a chronological receipt timeline. Added CLI command `actentra report <db_path> [--html out.html]`.
  - Agent Adapters (`sdk/python/actentra/adapters/`):
    - `function_calling.py`: `FunctionCallAdapter` supporting OpenAI-compatible and Anthropic-style function call dictionaries, automatic resource/verb inference, and execution through `Boundary`.
    - `langchain.py`: `LangChainToolWrapper` and `wrap_langchain_tool` duck-typed wrapper supporting LangChain `.invoke()`, `.run()`, and direct `__call__()`.
  - HTTP Gateway Service (`gateway/actentra_gateway/http_service.py`, `cli/actentra_cli/main.py`): zero-dependency `ThreadingHTTPServer` exposing REST API (`/health`, `/v1/crossings`, `/v1/crossings/pending`, `/v1/crossings/{id}/approve`, `/v1/receipts`, `/v1/verify`, `/v1/freeze`, `/v1/unfreeze`) and an embedded Operator Console web UI at `/ui` for human-in-the-loop approvals. Added CLI command `actentra serve --policy <path> [--port 8080]`.
  - Tests: added `tests/unit/test_http_executor.py`, `tests/unit/test_reporting.py`, `tests/unit/test_adapters.py`, `tests/unit/test_http_service.py`. Handled Windows Sandbox socket isolation (`WinError 10013`) gracefully with test skip assertions for loopback connections.
- Validation:
  - `.venv\Scripts\ruff check core executors gateway sdk cli tests`: All checks passed!
  - `.venv\Scripts\mypy`: Success, 0 issues found in 24 source files (`strict = true`).
  - `.venv\Scripts\pytest -v`: 69 passed, 4 skipped in 9.70s (and 100% passed when run unsandboxed).
  - Kernel size (`core/actentra_core/*.py`): 2,041 lines (under 3,000-line budget).

### 2026-11-13 11:35 IST

- Added Phase 3 Context-Aware Safety: Cumulative Session Budgets, Policy Canary Diff Engine, Dry-Run Simulation, and Session Taint Propagation:
  - Cumulative Session Budgets (`core/actentra_core/budgets.py`, `policy.py`): `SessionBudgetConfig` and memory-bounded `SessionBudgetTracker` enforcing `max_actions`, `max_external_calls`, and `max_write_bytes` per session with customizable escalation (`ask` or `deny`), directly mitigating slow-drip exfiltration (T4) and runaway agent recursion loops (T5).
  - Policy Canary Diff Engine (`core/actentra_core/canary.py`, `cli/actentra_cli/main.py`): `run_policy_canary` and `CanarySummary` replaying historical SQLite receipt logs against candidate policy packs to detect verdict shifts, identical outcomes, and permission regressions before production activation (`actentra policy canary <candidate_policy.yaml> <receipts.db>`).
  - Dry-Run Simulation (`sdk/python/actentra/boundary.py`, `cli/actentra_cli/main.py`): `Boundary.dry_run()` and CLI command `actentra dry-run` to predict policy verdicts, risk tags, and constraints without side effects, supporting optional shadow receipts for auditing.
  - Session Taint Propagation (`sdk/python/actentra/boundary.py`): dynamic session taint tracking that marks a session untrusted when reading untrusted inputs (indirect prompt injection defense) and automatically binds subsequent unannotated actions in that session to untrusted egress controls.
  - Receipt Store Action Envelopes (`core/actentra_core/receipts.py`): added `action_envelopes` table to persist and retrieve full canonical envelopes for historical auditing and canary replay.
  - Tests: added `tests/unit/test_budgets.py`, `tests/unit/test_canary.py`, `tests/unit/test_dry_run_and_taint.py`.
- Validation:
  - `.venv\Scripts\ruff check core executors gateway sdk cli tests`: All checks passed!
  - `.venv\Scripts\mypy`: Success, 0 issues found in 26 source files (`strict = true`).
  - `.venv\Scripts\pytest -v`: 76 passed, 4 skipped in 5.95s.

### 2026-11-13 11:45 IST

- Added Phase 4 Cryptographic Capability Tokens (Warrants), Documentation Suite, and Windows Service Daemon:
  - Warrants Engine (`core/actentra_core/warrants.py`, `cli/actentra_cli/main.py`): `Warrant`, `issue_warrant`, `verify_warrant`, `is_action_permitted_by_warrant`, and `WarrantRegistry` implementing Ed25519-signed capability delegation tokens with scoped tools, resource patterns, expiration, and use limits (`actentra warrant issue` / `actentra warrant verify`).
  - Documentation Suite:
    - `docs/quickstart.md`: Comprehensive 5-minute tutorial covering Python SDK `@guard`, adapters, CLI commands, dry-run, approval UI, and receipts verification.
    - `docs/architecture.md`: Full multi-layer system architecture diagram and 7 core invariants.
    - `README.md`: Modernized with complete feature matrices, quick checks, SDK examples, and architecture maps.
  - Windows Service Daemon Runner (`scripts/windows/run_gateway.ps1`): Resilient background launcher with automated health probes and crash auto-recovery.
  - Tests: added `tests/unit/test_warrants.py`.
- Validation:
  - `.venv\Scripts\ruff check core executors gateway sdk cli tests`: All checks passed!
  - `.venv\Scripts\mypy`: Success, 0 issues found in 27 source files (`strict = true`).
  - `.venv\Scripts\pytest -v`: 80 passed, 4 skipped in 6.03s.

### 2026-11-13 12:45 IST

- Built Actentra V2 — Unified Operator Application, Persistent Approvals, Action Lifecycle & Dispatched Execution per `PLAN_V2.md`:
  - Architecture & Specification (`docs/lifecycle-contract.md`, `docs/product-status.md`):
    - Authored the normative Action Lifecycle & Operational Contract defining states (`PROPOSED`, `EVALUATED`, `PENDING_APPROVAL`, `APPROVED`, `EXECUTING`, `COMPLETED`), TOCTOU binding (Invariant I3), decision/outcome receipt durability (Invariant I5), and local-only security posture.
    - Authored Product Status & Feature Support Matrix labeling capabilities across Supported, Experimental, and Planned tiers.
  - Persistent Approvals in SQLite WAL (`core/actentra_core/receipts.py`):
    - Added `pending_approvals` table storing `crossing_id`, `session_id`, `canonical_hash`, `tool`, `verb`, `resource`, `risk_tags_json`, `reason`, `params_json`, `ts`, `expires_at`, `status`, and `resolution_ts`.
    - Implemented `add_pending_approval`, `list_pending_approvals`, `get_pending_approval`, `resolve_pending_approval`, `mark_approval_consumed`, and `cleanup_expired_approvals`.
    - Pending human approvals now survive gateway process restarts, crash recoveries, and power cycles.
    - Modified `record_decision` to commit `action_envelopes` within the exact same atomic transaction as the decision receipt.
  - Paginated Bounded Receipts & Search (`core/actentra_core/receipts.py`):
    - Implemented `query_records(limit, offset, verdict, tool, status, session_id, record_type, search)` returning bounded records and exact `total_count`.
  - Replay Fidelity Verification (`core/actentra_core/canary.py`):
    - Enhanced `run_policy_canary` and `CanarySummary` with `missing_context_count` to explicitly report missing or corrupted replay context rather than guessing.
  - Thread Safety (`sdk/python/actentra/boundary.py`):
    - Protected mutable in-memory structures (`_approvals`, `_session_taints`) with `threading.Lock()` and wired `_has_valid_approval` to check and consume persistent SQLite approvals.
  - Typed Application Services Layer (`gateway/actentra_gateway/services.py`):
    - Implemented `AppServices` and `ExecutorRegistry` unifying CLI and Web UI.
    - Provided built-in executor registration (`register_fs`, `register_sqlite`, `register_http`) and dispatch logic (`_dispatch_and_record`).
    - Implemented `submit_crossing` with optional execution dispatch, `resolve_approval`, `execute_approved_crossing`, `record_external_outcome`, `query_receipts`, `verify_audit_log`, `export_audit_bundle`, `run_canary_on_candidate`, and `simulate_dry_run`.
  - Hardened HTTP Service & Unified Web Console (`gateway/actentra_gateway/http_service.py`, `console.html`):
    - Enforced strict loopback binding (`127.0.0.1`); non-loopback addresses fail closed unless `--unsafe-allow-remote` and Bearer token auth (`--token` / `ACTENTRA_GATEWAY_TOKEN`) are provided.
    - Replaced wildcard `*` CORS with verified loopback origin reflection.
    - Added REST endpoints for `/v1/crossings/{id}/execute`, `/v1/crossings/{id}/outcome`, `/v1/policy`, `/v1/policy/lint`, `/v1/policy/canary`, `/v1/simulate`, and `/v1/bundle/export`.
    - Built the embedded offline Web Console (`console.html`) with 7 views: Overview, Approvals Inbox, Policies & Linter, Dry-Run Simulator, Receipts Explorer, Integrations, and Settings.
  - CLI Enhancements (`cli/actentra_cli/main.py`):
    - Added `actentra approvals list` and `actentra approvals resolve`.
    - Added `actentra bundle export`.
    - Extended `actentra serve` with `--token`, `--unsafe-allow-remote`, `--ttl`, and `--workspace`.
  - Testing & Performance (`tests/unit/test_app_services.py`, `tests/perf/test_resource_budget.py`):
    - Added 8 comprehensive integration tests covering persistent approval restart survival, TTL expiration, executor continuation, external outcome recording, paged queries, canary diffs, token auth, and audit bundle exports.
    - Added `test_gateway_startup_and_memory_footprint` measuring gateway initialization latency and idle memory footprint.
  - Validation:
    - `.venv\Scripts\ruff check core executors gateway sdk cli tests`: All checks passed!
    - `.venv\Scripts\mypy`: Success, 0 issues found in 28 source files (`strict = true`).
    - `.venv\Scripts\pytest -v`: 89 passed, 4 skipped in 6.79s (and 100% passed unsandboxed).

### 2026-11-13 15:35 IST

- Remediated all 10 security findings and operational recommendations from the Read-Only Code Review:
  - Finding 1 (Critical):
    - Re-evaluated approved crossings in `execute_approved_crossing` now strictly enforce `decision.verdict.permits_execution`, blocking execution if policy freezes or returns `DENY`/`HOLD`.
    - Added atomic `claim_approval_for_execution` in `ReceiptStore` (`UPDATE ... WHERE status = 'approved' AND expires_at > ?`) executed before dispatch to eliminate race conditions and concurrent duplicate dispatch.
    - Updated `cleanup_expired_approvals` to expire both `pending` and `approved` records whose TTL has elapsed.
  - Finding 2 (High):
    - Added `SSRFSafeRedirectHandler` in `ScopedHTTPExecutor` validating every redirect target URL against allowed schemes (`http`/`https`), host allowlists, and IP ranges (`_verify_destination_ip`), blocking SSRF redirection to loopback, private, or cloud metadata endpoints.
  - Finding 3 (High):
    - Enforced mandatory token authentication on non-loopback bindings in `ActentraHTTPServer`: attempts to bind to remote addresses without both `unsafe_allow_remote` and a non-empty `auth_token` fail closed immediately.
  - Finding 4 (High):
    - Added `escapeHtml()` sanitization across all dynamic card, table, parameter, and error interpolations in `console.html`.
    - Added Content-Security-Policy (`default-src 'self'`), `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY` headers in `_send_html`.
    - Displayed safely rendered, scrollable action parameters in approval cards for informed operator decisions.
  - Finding 5 (High):
    - Implemented session taint tracking and propagation across gateway crossings in `submit_crossing` via `boundary.get_session_taint` and `boundary.set_session_taint`.
  - Finding 6 (High):
    - Added cumulative session budget recording in `_dispatch_and_record` via `self.boundary.engine.budget_tracker.record_usage(envelope)`, ensuring gateway execution paths accumulate actions, external calls, and write bytes against configured budgets.
  - Finding 7 (Medium):
    - Replaced naïve `WITH` classification in `_infer_verb` with a SQL scanner (`_scan_cte_main_verb`) that extracts the primary statement verb (`DELETE`, `UPDATE`, `INSERT`, etc.) following CTE blocks.
    - Enforced database connection-level `PRAGMA query_only = ON;` in `ScopedSQLiteExecutor` when `read_only=True`.
  - Finding 8 (Medium):
    - Hardened `record_external_outcome` in `AppServices` to reject duplicate reports via `has_outcome_receipt`, verify that the corresponding decision receipt exists, and ensure the decision verdict permitted execution (`allow` or `allow_with_constraints`).
  - Finding 9 (Medium):
    - Clamped receipt query `limit` (`max(1, min(limit, 500))`) and `offset` (`max(0, offset)`) in both `http_service.py` and `ReceiptStore.query_records`.
  - Finding 10 (Medium):
    - Validated `0 <= length <= _MAX_BODY_BYTES` in `_read_json_body`, rejecting negative `Content-Length` headers.
  - Side-effect-free simulations:
    - Added `record_rate_limit: bool = True` to `PolicyEngine.evaluate()`, disabling rate-limit token consumption during `Boundary.dry_run()` and `AppServices.simulate_dry_run()`.
  - Policy export completeness:
    - Updated `get_policy_yaml()` to serialize `limits`, `budgets`, and full `match` fields (`agent_id`, `taint`, `risk_any`, `risk_all`, `default_reason`).
  - Health check performance:
    - Separated fast health checks ($O(1)$ record count and latest record hash) from full hash-chain verification (`full_verify=False` by default).
  - Test suite fixes & regression tests:
    - Fixed vacuous assertion in `test_app_services.py`.
    - Created `tests/unit/test_security_review_remediations.py` containing 14 comprehensive tests verifying all 10 remediations. Total test count increased to 103 passed.
  - Validation:
    - `.venv\Scripts\ruff check core executors gateway sdk cli tests`: All checks passed!
    - `.venv\Scripts\mypy`: Success, 0 issues found in 28 source files (`strict = true`).
    - `.venv\Scripts\pytest -v`: 103 passed, 4 skipped (100% pass rate).

### 2026-11-13 15:48 IST

- Fixed CI timing race in `test_cleanup_expired_approvals_expires_approved_records`:
  - On busy GitHub Actions shared Windows runners, the initial wall-clock 0.05s TTL lapsed during `resolve_pending_approval`, causing an intermittent test failure (`assert 'expired' == 'approved'`).
  - Replaced wall-clock `time.sleep` with a deterministic `monkeypatch` over `time.time()`, advancing simulated time explicitly.
  - Validation: all 14 remediation tests and 103 total tests passed cleanly in under 5 seconds.

### 2026-11-14 19:10 IST

- Implemented V3 Foundation and Core Product enhancements following `PLAN_V3.md`:
  - **P0 — Strict Approval API & Endpoint Hardening (`http_service.py`):**
    - Enforced mandatory, strictly typed JSON boolean validation for `approved` in `/v1/crossings/<id>/approve`. Rejects empty `{}` payloads, missing fields, malformed JSON, strings (`"true"`), and integers (`1`) with HTTP 400 Bad Request.
    - Enforced boolean type validation on `execute` parameter.
    - Hardened `/v1/crossings/<id>/outcome` to validate `status` in `('success', 'failure', 'unknown')`, return HTTP 409 Conflict for duplicate reports, and HTTP 404 for missing crossings.
  - **P1 — Atomic Outcome Recording & Caller-Reported Evidence (`receipts.py`, `services.py`):**
    - Added partial unique index `idx_receipts_unique_outcome ON receipts(crossing_id) WHERE record_type = 'outcome'` in SQLite schema.
    - Inside `ReceiptStore._append_record`, atomic check within `BEGIN IMMEDIATE;` transaction and unique constraint eliminates race conditions on duplicate outcome reporting.
    - External outcomes are labeled with `reason="caller-reported"` (stored in SQLite and cryptographically hashed into `entry_hash`), and responses return `"reported_by": "caller"`.
    - Successful external outcome reports now increment the cumulative session budget counters in `SessionBudgetTracker`.
  - **P1 — Action Envelope Context Integrity (`receipts.py`, `services.py`):**
    - Added integrity verification in `ReceiptStore.get_envelope(crossing_id, verify_integrity=True)`, recomputing the action hash from stored envelope JSON and checking against `canonical_hash`.
    - Added `verify_envelopes: bool = False` option to `verify_log()`, verifying that all decision receipts have matching, un-tampered action envelopes in `action_envelopes`. Integrated into `AppServices.get_health(full_verify=True)` and `verify_audit_log(verify_envelopes=True)`.
  - **P1 — Dry-Run Session & Taint Propagation (`boundary.py`, `services.py`):**
    - Updated `Boundary.dry_run()` and `AppServices.simulate_dry_run()` to accept `session_id` and `agent_id`.
    - Evaluates dry-run actions against the requested session's taint, ensuring untrusted sessions trigger taint-matching rules during simulation while remaining completely side-effect-free.
  - **P1 — Faithful Policy Canary Replay (`canary.py`, `policy.py`):**
    - Reconstructed complete `ActionEnvelope` context in `run_policy_canary`: restored `provenance`, `intent`, `framework`, `model`, `idempotency_key`, and `ts`.
    - Verified envelope action hash matches the decision receipt's `canonical_hash`.
    - Added historical timestamp rate-limit evaluation (`PolicyEngine.evaluate(..., timestamp=hist_time)`), preventing false rate-limit spikes from rapid sequential replay.
    - Tracked cumulative session budget during canary replay.
    - Added `fidelity_warnings` to `CanarySummary` when context is missing or unverifiable.
  - **P2 — Operator Web Console Updates (`console.html`):**
    - Corrected RFC 8785 claim: replaced label with `SHA-256 (Deterministic UTF-8 Canonical JSON)`.
    - Surfaced specific server error responses in `resolveCrossing`.
  - **P1 — Documentation Alignment (`docs/product-status.md`, `PLAN.md`, `README.md`):**
    - Updated `docs/product-status.md` feature matrix: labeled DPAPI Secrets Broker and Warrants as **Experimental** to accurately reflect current integration depth; updated notes for canary and local gateway.
    - Updated status line in `PLAN.md` referencing `PLAN_V3.md`.
    - Updated `README.md` feature highlights.
  - **Validation & Test Suite:**
    - Added 8 new unit/integration tests across `test_http_service.py`, `test_security_review_remediations.py`, `test_dry_run_and_taint.py`, and `test_canary.py`.
    - Total tests: 111 passed, 3 skipped, 0 failures.
    - Ruff: All checks passed.
    - Mypy: Success (0 errors in 28 source files).

### 2026-11-14 19:40 IST

- Implemented Phase 2 & 3 capabilities from `PLAN_V3.md`:
  - **End-to-End Capability Warrant Enforcement in SDK (`boundary.py`, `test_warrants.py`):**
    - Integrated `warrant: Warrant | dict | None` into `Boundary.execute()` and `Boundary.dry_run()`.
    - Configured `warrant_public_key` (Ed25519) and `warrant_registry` (usage and quota tracker) in `Boundary`.
    - Enforced fail-closed validation: cryptographic signature verification against public key, holder matching (`expected_holder=agent_id`), expiration check, and tool/resource scope check (`is_action_permitted_by_warrant`).
    - Enforced consumption quota tracking (`WarrantRegistry.record_use()`), failing closed with `ActionBlockedError(rule_id="warrant:exhausted")` if `max_uses` is exceeded.
    - Attached `warrant:<id>` to action envelope provenance and durable decision receipts for complete auditability.
  - **End-to-End Credential Reference Resolution & Redaction (`http.py`, `test_http_executor.py`):**
    - Updated `ScopedHTTPExecutor` and `ScopedHTTPTools` to support `SecretsBroker`.
    - Added dynamic resolution of credential references (`secret:<NAME>`) in `secret_headers` constraints and request headers at execution time, keeping raw credentials out of policies, envelopes, and receipts.
    - Enforced full redaction on error bodies, HTTP status messages, response bodies, and response headers (`self._secrets_broker.redact(...)`), preventing credentials from leaking in logs or exceptions.
  - **Bounded Streaming Audit Log Iteration, Export & Archival (`receipts.py`, `test_receipt_archival.py`):**
    - Added `ReceiptStore.iter_records_stream()` using bounded SQLite cursor chunking (`fetchmany`), preventing memory spikes when querying large audit logs.
    - Updated `export_jsonl()` and `verify_log()` to stream records row-by-row / chunk-by-chunk in $O(1)$ memory.
    - Implemented `ReceiptStore.archive_records()` to archive historical records before a given sequence number into a separate self-contained SQLite archive database while preserving envelope context and hash chain integrity, with optional source pruning (`delete_from_source=True`).
  - **Guided Local Setup & Live Policy Preview in Web Console (`console.html`):**
    - Added an interactive "Interactive Policy Generator & Guided Setup" wizard in the Integrations view.
    - Allows operators and developers to select integration targets (Python SDK, MCP Stdio Proxy, Gateway HTTP API), choose template profiles (Workspace Filesystem Guard, Data Assistant, Scoped Webhook, Zero Trust), customize rules, copy/download generated YAML, and test simulated actions in real time.
  - **Validation & Test Suite:**
    - Added `tests/unit/test_receipt_archival.py` and expanded `tests/unit/test_warrants.py` and `tests/unit/test_http_executor.py`.
    - Total test suite: 116 passed, 4 skipped (Windows sandbox loopback/symlink privileges), 0 failures.
    - Ruff: All checks passed.
    - Mypy: Success (0 errors in 28 source files, strict mode).
