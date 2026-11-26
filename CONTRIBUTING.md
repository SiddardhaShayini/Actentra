# Contributing to Actentra

Thank you for your interest in contributing to Actentra. Actentra is a lightweight, local-first deterministic execution boundary for AI agents.

## Development Setup

### Prerequisites
- **Python:** `>=3.12` (primary CI target: Windows Python 3.12)
- **Package Manager:** `uv` (recommended) or `pip`

### Clone and Install

```powershell
git clone https://github.com/SiddardhaShayini/Actentra.git
cd Actentra

# Using uv (matches CI)
uv sync --extra dev

# Or using pip in a virtual environment
pip install -e ".[dev]"
```

## Repository Structure

- `core/actentra_core/` — Deterministic policy engine, canonicalization, risk tagging, budgets, receipts, checkpoints, warrants, claims, and lifecycle state machine.
- `executors/actentra_executors/` — Scoped filesystem, SQLite, HTTP (SSRF-defended), and workspace verifier executors.
- `gateway/actentra_gateway/` — `AppServices`, HTTP gateway (`/v1/crossings`, `/ui`), and MCP stdio proxy.
- `sdk/python/actentra/` — In-process `Boundary`, `@guard`, `SecretsBroker`, and framework adapters.
- `cli/actentra_cli/` — Typer CLI (`actentra`).
- `spec/` — Draft 2020-12 JSON Schemas.
- `corpus/` — Incident, red-team, and benign evaluation corpora.
- `docs/` — Architecture, guides, security model, audits, and remediation reports.
- `tests/` — Unit, golden, chaos, replay, property, and performance test suites.

## Quality Checks

All pull requests and commits to `main` must pass the CI checks defined in `.github/workflows/ci.yml`:

```powershell
# 1. Lint with Ruff
uv run ruff check core executors gateway sdk cli tests

# 2. Strict type checking with Mypy
uv run mypy

# 3. Fast test suite (matches CI)
uv run pytest -m "not slow"

# Full test suite (including slow/property tests)
uv run pytest -o addopts= -q
```

## Coding & Security Guidelines

1. **Zero LLM in the Enforcement Path:** Policy evaluation, canonicalization, and risk tagging must remain 100% deterministic.
2. **Fail Closed:** Errors, malformed inputs, or missing authorization must default to `DENY` or `HOLD` rather than failing open.
3. **Preserve Security Invariants:** Changes to canonicalization, policy evaluation, identity binding, executors, or receipt persistence must preserve the invariants documented in [docs/security/guarantees-and-limits.md](docs/security/guarantees-and-limits.md) and include regression tests.
4. **Type Safety & Style:** Follow Ruff rules (`E`, `F`, `I`, `UP`, `B`, `SIM`, `S`, line length 100) and `mypy --strict`.

## Reporting Security Issues

Do **not** open public GitHub issues for security vulnerabilities. Follow the private reporting instructions in [SECURITY.md](SECURITY.md).

## License

By contributing to Actentra, you agree that your contributions will be licensed under the Apache-2.0 License. See [LICENSE](LICENSE).
