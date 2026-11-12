<p align="center">
  <img src="assets/actentra-logo.svg" alt="Actentra" width="260" />
</p>

# Actentra

> *Intelligence proposes. Actentra decides.*

**Actentra** is a lightweight, local-first deterministic execution boundary for AI agents. It sits between any model or agent framework and real-world tools—canonicalizing each tool call, evaluating deterministic YAML policies and risk tags, binding human approvals to an exact action hash, and writing tamper-evident hash-chained receipts.

## Current Status

- **Phase:** Phase 0 → early Phase 1 Kernel MVP
- **Target:** Windows-first, CPU-only, < 60 MB RSS, no LLM in the enforcement path
- **License:** Apache-2.0

## Repository Layout

- [`core/actentra_core/`](core/actentra_core/) — Pure, deterministic enforcement kernel (zero network, zero heavy dependencies): envelope builder, Windows path & JSON canonicalizer, risk tagger, deny-overrides YAML policy engine, hash-chained SQLite WAL receipts, Ed25519 signed checkpoints
- [`executors/actentra_executors/`](executors/actentra_executors/) — Narrowly scoped action executors: `LocalFSExecutor` + `ScopedFSTools` (reparse-point containment + constraints) and `ScopedSQLiteExecutor` + `ScopedSQLiteTools` (single-statement parameterized SQL + `read_only` / `max_rows`)
- [`gateway/actentra_gateway/`](gateway/actentra_gateway/) — MCP stdio proxy (`MCPStdioProxy`, `serve_stdio`) intercepting `tools/call` and pinning `tools/list` definitions against rug-pull tampering
- [`sdk/python/actentra/`](sdk/python/actentra/) — Thin in-process Python SDK (`Boundary`, `@guard`, `SecretsBroker` with Windows DPAPI encryption & secret redaction)
- [`cli/actentra_cli/`](cli/actentra_cli/) — `actentra` CLI (`init`, `policy check`, `run`, `replay`, `mcp-proxy`, `checkpoint keygen/sign/verify`, `verify-log`, `export-log`, `demo`)
- [`spec/`](spec/) — Draft 2020-12 JSON Schemas for Envelope, Policy, and Receipt v1
- [`policies/examples/`](policies/examples/) — Starter policy packs
- [`corpus/`](corpus/) — Incident replay, red-team, and benign evaluation corpora
- [`docs/`](docs/) — [Threat Model](docs/threat-model.md), [Guarantees & Limits](docs/guarantees-and-limits.md), [Naming Clearance Checklist](docs/naming-clearance.md)
- [`tests/`](tests/) — Unit, golden, chaos, replay, property (Hypothesis), and performance tests

## Quick Check

```powershell
# Run lint, strict type-checking, and fast tests
.venv\Scripts\ruff check core executors sdk cli tests
.venv\Scripts\mypy
.venv\Scripts\pytest -v

# Run the end-to-end workspace demo, incident replay, and self-contained demo
.venv\Scripts\actentra run
.venv\Scripts\actentra replay corpus/incidents/agent_incidents.jsonl --policy policies/examples/starter.yaml
.venv\Scripts\actentra demo
```

## Guarantees and Limits

Actentra is designed to **fail closed**, bind approvals to exact `sha256` action hashes, and persist durable decision records before execution. See [docs/guarantees-and-limits.md](docs/guarantees-and-limits.md) for explicit scope and non-goals.
