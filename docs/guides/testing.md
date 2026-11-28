# Testing Guide

This guide covers running Actentra's automated test suites, static analysis checks, and runnable examples.

---

## 1. Test Setup

Actentra requires **Python 3.12+** and development dependencies (`pytest`, `hypothesis`, `jsonschema`, `mypy`, `ruff`, `psutil`, `types-PyYAML`).

```powershell
git clone https://github.com/SiddardhaShayini/Actentra.git
cd Actentra
uv sync --extra dev
```

Or with `pip`:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

---

## 2. Fast Test Suite vs. Full Test Suite

In `pyproject.toml`, the default `addopts` excludes `@pytest.mark.slow` tests (`-q -m 'not slow'`) for fast iteration.

```powershell
# Fast loop (matches CI)
uv run pytest -m "not slow"

# Full test suite (includes slow and Hypothesis property tests)
uv run pytest -o addopts= -q -rs
```

At `HEAD` `ed230bc` on Windows 11 (sandboxed), `uv run pytest -o addopts= -q -rs` ran 424 tests (`414 passed, 10 skipped`):
- 7 skips in sandboxed environments where loopback socket binding/connecting is restricted (`WinError 10013`).
- 3 skips where the Windows test environment lacks OS symlink/junction creation privilege (`tests/unit/test_fs_executor.py:187`, `tests/unit/test_fs_executor.py:207`, `tests/unit/test_phase3_fs_race_confinement.py:301`).

In an unsandboxed Windows run at audited `85b663a` (see [ACTENTRA_POST_REMEDIATION_AUDIT.md](../security/audits/ACTENTRA_POST_REMEDIATION_AUDIT.md)), `403 passed, 1 skipped` (only `test_fs_executor.py:207` skipped for OS symlink privilege).

---

## 3. Security & Reliability Test Suite

Run focused security, race, mTLS, chaos, and property tests:

```powershell
uv run pytest -o addopts= -q -rs `
  tests/unit/test_security_finding_01_identity.py `
  tests/unit/test_security_finding_02_dns_rebinding.py `
  tests/unit/test_security_finding_03_warrant_quotas.py `
  tests/unit/test_security_finding_04_postconditions.py `
  tests/unit/test_security_finding_05_external_outcomes.py `
  tests/unit/test_phase1_identity_hardening.py `
  tests/unit/test_phase2_observation_binding.py `
  tests/unit/test_phase2_session_and_authorization.py `
  tests/unit/test_phase3_fs_race_confinement.py `
  tests/unit/test_phase3_remote_gateway_security.py `
  tests/unit/test_phase4_executor_hardening.py `
  tests/unit/test_phase4_mtls_principal_binding.py `
  tests/unit/test_phase5_execution_integrity.py `
  tests/unit/test_phase5_production_trust_anchoring.py `
  tests/unit/test_phase6_audit_architecture.py `
  tests/unit/test_phase7_production_reliability.py `
  tests/unit/test_phase8_complete_hardening.py `
  tests/chaos/test_chaos.py `
  tests/property/test_properties.py
```

---

## 4. Static Analysis (Lint & Type Check)

```powershell
# Ruff linting (rules: E, F, I, UP, B, SIM, S)
uv run ruff check core executors gateway sdk cli tests

# Strict Mypy type checking across all 5 packages (41 source files)
uv run mypy
```

---

## 5. Running Examples

```powershell
uv run python examples/minimal_file_write.py
uv run python examples/minimal_blocked_action.py
uv run python examples/agent_function_calling.py
uv run python examples/gateway_demo.py
```

For the multi-model real-agent demonstration (Ollama / Hugging Face Transformers), see [examples/real_agent_demo/README.md](../../examples/real_agent_demo/README.md).
