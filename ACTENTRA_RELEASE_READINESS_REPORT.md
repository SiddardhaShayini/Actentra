# Actentra Release Readiness Report

**Assessment Date:** 2026-11-28  
**Repository:** `https://github.com/SiddardhaShayini/Actentra`  
**Published PyPI Package:** `actentra==0.1.0a0` (`https://pypi.org/project/actentra/`)  
**Published Release Tag / Commit:** `v0.1.0a0` (`2c0357f`)  
**Current Audit Baseline:** [ACTENTRA_POST_REMEDIATION_AUDIT.md](docs/security/audits/ACTENTRA_POST_REMEDIATION_AUDIT.md) (`85b663a`) and current `main` (`8fd7871`+)

---

## 1. Published Package Verification

Inspected live PyPI JSON metadata (`https://pypi.org/pypi/actentra/json`) and installed `actentra==0.1.0a0` into a clean virtual environment (`pypi_clean_venv`) without editable installs or repository-relative imports:

- **Version & Status:** `0.1.0a0`, `yanked: False`.
- **Python & Dependencies:** `requires_python: ">=3.12"`. Runtime dependencies: `PyYAML<7.0,>=6.0`, `cryptography>=43.0`, `typer<1.0,>=0.12`. Optional `[dev]` extras: `pytest>=8.0`, `hypothesis>=6.100`, `jsonschema>=4.20`, `mypy>=1.10`, `ruff>=0.6`, `psutil>=6.0`, `types-PyYAML>=6.0`.
- **Artifacts:**
  - Wheel: `actentra-0.1.0a0-py3-none-any.whl` (242,713 bytes, SHA-256 `1b5b58d9f5adaee9be893ea242b1033268e87fe739cf4c5d8b9710777a9a4da0`)
  - Source dist: `actentra-0.1.0a0.tar.gz` (221,155 bytes, SHA-256 `db887ea0ad94af0da1fb5cedb9ef630d741f83fcf778622478d59ae6969a6ce4`)
- **Clean-Venv Verification:**
  - `import actentra, actentra_core, actentra_executors, actentra_gateway, actentra_cli` succeeded from `site-packages\actentra\__init__.py` (`37` public exports in `actentra.__all__`).
  - `actentra.exe --help` succeeded.
  - End-to-end `Boundary.from_yaml(...)` -> `b.run(..., verify_postcondition=True, raise_on_postcondition_failure=True)` -> blocked `ActionBlockedError` -> `b.verify_receipts().ok` returned `PyPI_RUN_OK: True True True`.

---

## 2. Artifact and Provenance Verification

- **Trusted Publishing Provenance:** Verified PEP 740 Sigstore attestation bundle at `https://pypi.org/integrity/actentra/0.1.0a0/actentra-0.1.0a0-py3-none-any.whl/provenance` (`predicateType: https://docs.pypi.org/attestations/publish/v1`, `sigstore-intermediate` certificate, matching wheel SHA-256).
- **Source Commit Mapping:** Git tag `v0.1.0a0` points to `2c0357f` (`ci: add PyPI Trusted Publishing workflow`), matching [.github/workflows/publish.yml](.github/workflows/publish.yml).
- **Post-Release Drift:** Commits after `v0.1.0a0` (`8aec173` POSIX root path fix in `core`, `executors`, and `sdk`; `00f12c1`..`ed230bc` `examples/real_agent_demo/`; `4487f37` `ACTENTRA_SECURITY_MODEL.md`; `8fd7871` technical docs) are on `main` **but are not yet in PyPI `0.1.0a0`**.

---

## 3. Platform Compatibility Matrix

| Platform | Status | Evidence & Scope |
|---|---|---|
| **Windows 11 (amd64, Python 3.12)** | **Tested and passed** (with documented skips) | Unsandboxed audit (`85b663a`): `403 passed, 1 skipped` (symlink privilege skip at `test_fs_executor.py:207`). Sandboxed run (`ed230bc` / `8fd7871`): `414 passed, 10 skipped` (7 sandbox `WinError 10013` socket skips + 3 symlink/junction privilege skips). Clean PyPI `0.1.0a0` install, Ruff, Mypy, and live Ollama `qwen3:1.7b` demo all passed. |
| **Ubuntu Linux (x86_64)** | **Not tested** (full suite); **Partial** (demo from source on Kaggle) | No local Docker or WSL Linux environment was available, and `.github/workflows/ci.yml` only runs `windows-latest`. Kaggle Ubuntu 2x T4 runs exercised `examples/real_agent_demo` from source (`8aec173`..`ed230bc`), **not** the full `pytest` suite or POSIX `dir_fd` symlink race tests. |
| **macOS (arm64 / x86_64)** | **Not tested** | No macOS environment available. |
| **Windows DPAPI Secrets (`dpapi_protect`)** | **Unsupported by design on POSIX** | Windows-only (`sys.platform == "win32"`); POSIX falls back to AES-256-GCM in `SecretsBroker`. |

---

## 4. Installation Results

- **`pip install actentra==0.1.0a0` (clean venv, Windows 11, Python 3.12.8):** Installed cleanly from PyPI wheel with all runtime dependencies (`PyYAML`, `cryptography`, `typer`).
- **`uv sync --extra dev` (repository clone, Python 3.12.12):** Installed cleanly; `ruff`, `mypy`, `pytest`, and `actentra` CLI all functional.

---

## 5. Real-Agent Reproduction Results

Reproduced `examples/real_agent_demo/run_demo.py` from the repository environment in both offline scripted mode and live local LLM mode:

1. **Deterministic Scripted Mode & Integration Tests:**
   - `uv run python examples/real_agent_demo/run_demo.py --backend scripted`: Passed (`Protected file unchanged: True`, `False-success ghost absent: True`, `Approved file created: True`, `Hash-chain integrity: ok=True, records=9`).
   - `uv run pytest tests/integration/test_real_agent_demo.py -v`: `5 passed in 1.18s`.
2. **Live Local Model Reproduction (Ollama):**
   - **Model & Backend:** `qwen3:1.7b` (`8f68893c685c`, 1.4 GB) via `OpenAICompatibleModelClient` (`http://127.0.0.1:11434/v1`).
   - **Hardware:** Windows 11, 12 logical CPUs, 15.73 GB total RAM (5.21 GB available at start), CPU-only.
   - **Enforcement vs. Self-Refusal:** `qwen3:1.7b` **proposed all 6 tool calls** (`write_workspace_file` for A, B1, D1, D2; `run_shell_command` for B2; `unreliable_write_file` for C). **Actentra** (not model self-refusal) denied B1 and B2, refuted C (`obs=refuted`, `verified=False`), held D1 (`verdict=ask`, `allowed=False`), and verified A and D2 (`evidence=externally_verified`, `verified=True`). Audit chain: `ok=True, records=9`.
3. **Previously Recorded Kaggle 2x T4 GPU Results (`ed230bc`):**
   - `Qwen/Qwen2.5-3B-Instruct` (`records=11`), `Qwen/Qwen3.5-9B` (`records=13`), and `ibm-granite/granite-4.2-8b` (`records=17`) proposed and had all scenarios enforced by Actentra.
   - `Qwen/Qwen3-8B` (`records=8`) **self-refused** `run_shell_command` in Scenario B2 without emitting a tool call; Scenarios A, B1, C, D1, D2 were enforced by Actentra.
   - Models > 12B (`openai/gpt-oss-20b`, `Qwen/Qwen3-Coder-30B-A3B-Instruct`) hit GPU OOM on 2x T4 (`29.12 GB` VRAM).

---

## 6. Documentation Inconsistencies Found & Resolved

| Item | Inconsistency Found | Resolution |
|---|---|---|
| **PyPI `0.1.0a0` Description** | Contained relative `<img src="assets/actentra-logo-dark.svg">` (broken on `pypi.org`) and pre-dates `ACTENTRA_SECURITY_MODEL.md`, `docs/README.md`, and `examples/real_agent_demo/`. Did *not* claim "unpublished". | Updated [README.md](README.md) to use absolute GitHub raw logo URL and current docs/results; prepared metadata recommendation for `0.1.0a1`. |
| **`docs/guides/developer-usability-report.md`** | Line 14 claimed `actentra (0.1.0a0) is not currently published on PyPI`. | Updated to reflect `actentra==0.1.0a0` on PyPI. |
| **`CHANGELOG.md`** | All items sat under `[Unreleased]` with no `[0.1.0a0]` release boundary. | Added `[0.1.0a0] - 2026-11-26` section and separated post-release `[Unreleased]` changes. |
| **`docs/product-status.md`** | Stated Linux/macOS support in core logic without distinguishing untested status. | Documented exact platform test status in [ACTENTRA_SECURITY_MODEL.md](ACTENTRA_SECURITY_MODEL.md) and this report. |

---

## 7. Security Limitations

Summary of key boundaries documented in [ACTENTRA_SECURITY_MODEL.md](ACTENTRA_SECURITY_MODEL.md) and [ACTENTRA_POST_REMEDIATION_AUDIT.md](docs/security/audits/ACTENTRA_POST_REMEDIATION_AUDIT.md):
- Actentra is an in-process Python execution boundary, **not** an OS-level sandbox; unmediated Python/OS calls bypass it.
- Local SQLite hash chains do not stop a DB editor unless paired with custody-separated Ed25519 `CheckpointAnchor` + `KeyRing`.
- `WorkspaceFileVerifier` verifies local host filesystem state; remote effects require an external witness.
- Linux/macOS POSIX `dir_fd` symlink races, live public-network SSRF, external penetration testing, and third-party dependency audits have not been performed.

---

## 8. Developer Usability Findings

### Reproducible New-Developer Evaluation Procedure
1. **Install (`~30s`):** `python -m venv .venv && .venv\Scripts\activate && pip install actentra`
2. **Verify CLI & Import (`~5s`):** `actentra --help` and `python -c "from actentra import Boundary, path_resource"`
3. **Run First Protected Action (`~2 min`):** Copy the quickstart snippet from [docs/guides/quickstart.md](docs/guides/quickstart.md) (`Boundary.from_yaml`, `boundary.run(..., verify_postcondition=True)`, `ActionBlockedError`, `boundary.inspect_crossing`, `boundary.verify_receipts`).
4. **Integrate an Agent (`~5 min`):** Wrap tool callables with `FunctionCallAdapter(boundary)` per [docs/guides/ai-agent-integration.md](docs/guides/ai-agent-integration.md).
5. **Review Security Boundaries:** Read [ACTENTRA_SECURITY_MODEL.md](ACTENTRA_SECURITY_MODEL.md).

### Assessment & External Participation
- **Steps & Complexity:** Single-package `pip install actentra` and `Boundary.from_yaml` + `boundary.run` reduce initial setup to 1 install command and ~25 lines of Python; error messages (`ActionBlockedError`, `PolicyValidationError`, `CanonicalizationError`) clearly identify the failing rule or field.
- **External Developer Participation:** **Not yet tested** with external developers outside the project team; no external-user feedback is claimed.

---

## 9. Release Blockers

- **For broader alpha evaluation (`0.1.0a1`):** No hard blocker on Windows 11, **except** PyPI `0.1.0a0` is missing the `8aec173` POSIX root path fix and updated README/docs metadata.
- **For Linux/macOS support claims:** Blocked until `.github/workflows/ci.yml` includes `ubuntu-latest` (and `macos-latest` if supported) and passes the full suite including real POSIX `dir_fd` symlink race tests.
- **For unconditional external production:** Blocked by same-host TCB limitations, absence of OS sandboxing, and unverified external audit/pentest items in [ACTENTRA_POST_REMEDIATION_AUDIT.md](docs/security/audits/ACTENTRA_POST_REMEDIATION_AUDIT.md) Section 10.

---

## 10. Recommendation for Next Alpha Release (`0.1.0a1`)

1. Bump `version` in `pyproject.toml` from `0.1.0a0` to `0.1.0a1` (do not overwrite `0.1.0a0`).
2. Add an `ubuntu-latest` job to `.github/workflows/ci.yml` and verify the full `pytest` suite (including `test_phase3_fs_race_confinement.py` and `test_fs_executor.py` POSIX symlink tests) on Ubuntu.
3. Tag `v0.1.0a1` to trigger `.github/workflows/publish.yml` so PyPI receives the `8aec173` POSIX fix, `examples/real_agent_demo/`, the updated `README.md` (with absolute logo URL and doc links), and Sigstore Trusted Publishing provenance.
