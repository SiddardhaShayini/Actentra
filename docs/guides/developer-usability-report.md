# Actentra Developer Usability Report

**Date:** 2026-11-26  
**Repository:** `SiddardhaShayini/Actentra`  
**Base Commit Reviewed:** `d41840f` (HEAD `85b663a` code/security baseline)

---

## 1. Phase 1 Exploration: Current Developer Experience

### Direct Answers to Core Adoption Questions

1. **Can it be installed using `pip install actentra`?**
   - **No.** `actentra` (`0.1.0a0`) is not currently published on PyPI.
   - Supported installation paths today are:
     - Editable or standard install from a clone (`pip install -e .` or `uv sync`)
     - Direct Git install (`pip install "git+https://github.com/SiddardhaShayini/Actentra.git"`)
     - Installing a built wheel (`pip install dist/actentra-0.1.0a0-py3-none-any.whl`)
2. **Can it be imported using a simple Python import?**
   - **Previously partial; now unified.** Previously, `from actentra import Boundary` was insufficient: developers also had to import `load_policy_file` / `load_policy_yaml` from `actentra_core.policy`, `ReceiptStore` from `actentra_core.receipts`, `LocalFSExecutor` / `WorkspaceFileVerifier` from `actentra_executors.*`, and `Verdict` / `ProvenanceItem` from `actentra_core.*`.
3. **What is the minimum configuration required?**
   - A fail-closed YAML policy (`version: 1`, `policy_id`, `defaults.verdict` set to `deny` or `hold`, and `rules`), plus a SQLite receipt database path.
4. **Can a developer initialize it without running a separate server?**
   - **Yes.** `Boundary` runs in-process over SQLite WAL with zero external services or daemons required.
5. **How does a developer register an executor?**
   - **Previously fragmented.** `AppServices` had `ExecutorRegistry` (`register_fs`, `register_sqlite`, `register_http`, `register`), whereas `Boundary` lacked executor registration and required passing `fn=executor.execute` manually on every `Boundary.execute()` call.
6. **How does a developer authorize an action?**
   - In-process via `Boundary.run(...)`, `Boundary.execute(...)`, `@boundary.guard(...)`, `ScopedFSTools`, `FunctionCallAdapter`, or `LangChainToolWrapper`; out-of-process via `MCPStdioProxy` or the HTTP gateway (`POST /v1/crossings`).
7. **How does a developer inspect whether an action was allowed, denied, or verified?**
   - **Previously awkward in the SDK.** `Boundary.execute()` returned only the raw callable return value, hiding `crossing_id`, `Decision`, `ObservationRecord`, and receipt metadata; developers had to query `ReceiptStore` directly without knowing the generated `crossing_id`.
8. **What requires a gateway, database, certificates, or external infrastructure?**
   - **Embedded Python:** Python `>=3.12` + SQLite file path (no server, no certificates, no external DB).
   - **HTTP Gateway (local loopback):** `actentra serve` / `create_gateway_server` on `127.0.0.1` (no TLS required on loopback).
   - **Remote / Controlled-Pilot Deployments:** Require TLS 1.2+ (`--cert`, `--key`), mTLS (`--ca-certs`, `--require-client-cert`), mapped principal credentials, and an off-directory `CheckpointAnchor` + `KeyRing`.
9. **What was unnecessarily complicated?**
   - Multi-package import sprawl across `actentra`, `actentra_core`, and `actentra_executors`.
   - No `Boundary.from_yaml(...)` factory or `workspace_root` shortcut on `Boundary.from_files(...)`.
   - No `Boundary.run(...)` returning a structured `ExecutionResult` (`crossing_id`, `allowed`, `verdict`, `status`, `evidence_status`, `verified`, `observation`).
   - No one-call `Boundary.inspect_crossing(...)` or `Boundary.verify_receipts()` helpers.
   - `actentra init` hardcoded `path:C:/work/**`, causing quickstart runs in any other folder to deny workspace reads.
10. **Inconsistencies found between docs, examples, and implementation:**
    - `docs/guides/quickstart.md` ran `actentra init` (which targeted `C:/work/**`) and then read `notes.txt` from the current directory, which failed closed unless run inside `C:/work`.
    - `docs/guides/quickstart.md` referenced `--certfile` / `--keyfile` instead of the CLI's actual `--cert` / `--key` flags on `actentra serve`.
    - `README.md` SDK example previously required internal `actentra_core` imports and assumed `C:/work/notes.txt`.

---

## 2. Phase 2 & 3 Improvements Implemented

All usability improvements preserve Actentra's fail-closed defaults, TOCTOU hash checks, postcondition substitution defenses, warrant enforcement, and durable SQLite receipt invariants:

| Area | Improvement | Security Preservation |
| --- | --- | --- |
| **Package Exports** (`actentra/__init__.py`) | Re-exported `Boundary`, `ExecutionResult`, `CrossingReceipt`, `path_resource`, `load_policy_file`, `load_policy_yaml`, `ReceiptStore`, `Decision`, `Verdict`, `ProvenanceItem`, `CanonicalizationError`, `LocalFSExecutor`, `ScopedHTTPExecutor`, `ScopedSQLiteExecutor`, `WorkspaceFileVerifier`, and adapters. | No internal bypass paths exposed; underlying classes remain strictly typed and fail-closed. |
| **Initialization** (`Boundary.from_yaml`, `Boundary.from_files`) | Added `Boundary.from_yaml(...)` for inline policies and optional `workspace_root=` on both `from_files()` and `from_yaml()` to auto-register `LocalFSExecutor` and `WorkspaceFileVerifier`. Improved missing-policy `FileNotFoundError` hint. | Policies still pass strict `load_policy_file` / `load_policy_yaml` validation requiring `defaults.verdict` in `{'deny', 'hold'}`. |
| **Executor Registration** (`Boundary`) | Added `register_fs`, `register_sqlite`, `register_http`, `register_executor`, and `registered_tools`. | Uses the same defended executors (`LocalFSExecutor`, `ScopedHTTPExecutor`, `ScopedSQLiteExecutor`). |
| **Structured Execution** (`Boundary.run`, `ExecutionResult`) | Added `Boundary.run(...)` delegating through `_execute_internal` (same enforcement path as `execute()`), returning `ExecutionResult` with `crossing_id`, `allowed`, `verdict`, `status`, `evidence_status`, `verified`, receipts, and observation. | Fails closed by default (`raise_on_blocked=True`); auto-defaults `fs.write` postcondition to `digest_match` when `verify_postcondition=True` without overriding policy-mandated postconditions. |
| **Receipt Inspection** (`Boundary.inspect_crossing`, `recent_receipts`, `verify_receipts`) | Added `CrossingReceipt` inspection by `crossing_id`, recent receipt listing, and one-line `verify_log` hash-chain verification. | Read-only SQLite queries; full SHA-256 chain and envelope verification preserved. |
| **Path Helper** (`path_resource`) | Added `path_resource(path, workspace_root=...)` producing canonical `path:...` strings. | Routes through `canonicalize_windows_path(..., resolve_fs=False)` so `..` escapes, ADS, and reserved names still fail closed with `CanonicalizationError`. |
| **CLI Init** (`actentra init --workspace`) | Added optional `--workspace / -w` flag to generate a policy scoped to the developer's actual workspace directory. | Default behavior without `--workspace` is preserved; generated workspace policy still sets `defaults.verdict: deny`, `ask` for writes/deletes, and denies `privilege-escalation` and untrusted `http.*` egress. |

---

## 3. Supported Developer Workflows

1. **Embedded Local Python:** `Boundary.from_yaml(..., workspace_root=...)` -> `boundary.run(...)` -> `boundary.inspect_crossing(...)` -> `boundary.verify_receipts()`.
2. **HTTP Gateway (Multi-Process / Operator Console):** `actentra serve --policy ... --workspace .` or `create_gateway_server(...)` -> HTTP `POST /v1/crossings` / `/ui`.
3. **AI-Agent Integration:** `FunctionCallAdapter(boundary)` or `wrap_langchain_tool(tool, boundary)` mediating tool calls with `ProvenanceItem` taint tracking.
4. **Controlled-Pilot / Remote Deployment:** `SecurityProfile.CONTROLLED_PILOT` or `EXTERNAL_PRODUCTION`, TLS/mTLS (`--cert`, `--key`, `--ca-certs`, `--require-client-cert`), mapped principal credentials, and an off-directory `CheckpointAnchor` + `KeyRing`.

---

## 4. Phase 4 & 5 Deliverables and Verification

- **Examples added in `examples/`:**
  - `examples/minimal_file_write.py` — approved, postcondition-verified (`digest_match`) file write + receipt inspection.
  - `examples/minimal_blocked_action.py` — `.env` `DENY`, unapproved `ASK`, and traversal `CanonicalizationError` block.
  - `examples/gateway_http_example.py` — loopback HTTP gateway server & client flow.
  - `examples/agent_function_calling.py` — `FunctionCallAdapter` allowing safe reads and blocking tainted outbound HTTP.
- **Packaging & Clean-Venv Verification:**
  - Built source distribution (`.tar.gz`) and wheel (`.whl`) via `uv build`.
  - Installed the built wheel into a brand-new isolated virtual environment outside the repository and executed the examples from outside the repository tree to confirm zero reliance on repo-relative paths.
