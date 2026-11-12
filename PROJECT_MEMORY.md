# Actentra — Project Memory

## Project summary

Actentra is a planned lightweight, local-first execution boundary for AI agents. It mediates consequential tool actions through deterministic policy checks, optional human approval, constrained execution, and tamper-evident audit records. Enforcement must not depend on an LLM. The current plan prioritizes an in-process Python SDK and a narrowly scoped MVP before adding a daemon, HTTP API, or more connectors.

The project is at **Phase 0**. Its chosen project name is **Actentra**; this is not a claim of trademark, domain, or package-name clearance. See [PLAN.md](./PLAN.md) for the architecture, threat model, roadmap, resource targets, and remaining decisions.

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
  - Kernel size (`core/actentra_core/*.py`): 2,041 lines (under 3,000-line budget).
