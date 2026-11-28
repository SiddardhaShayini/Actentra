# Actentra Documentation Index

Welcome to the Actentra documentation. Actentra is a lightweight, local-first deterministic execution boundary for AI agents.

---

## Start Here

- **[Project Overview & Quick Start (README)](../README.md)** — What Actentra is, what it solves (and does not solve), and a 5-minute quick start.
- **[Installation & Quick Start Guide](guides/quickstart.md)** — Verified installation steps, first local `Boundary`, policy setup, authorized/blocked actions, postcondition verification, and receipt inspection.

## Architecture & Security

- **[System Architecture](architecture/architecture.md)** — Component responsibilities across Core, Gateway, SDKs, Executors, Identity, Delegation, Policies, Warrants, Sessions, Approvals, Claims, Postconditions, Observations/Evidence, Receipts, Lifecycle, and Checkpoints.
- **[Action Lifecycle Contract](architecture/lifecycle-contract.md)** — Normative crossing lifecycle, persistence scope, and evidence quality tiers.
- **[Formal Security Model & Trust Boundaries](../ACTENTRA_SECURITY_MODEL.md)** — Comprehensive security contract, threat model, 6 architectural diagrams, guarantees vs. assumptions, and audit reproduction status.
- **[Threat Model](security/threat-model.md)** — Detailed threat matrix (T1–T20) and audit threat profiles.
- **[Guarantees and Explicit Limits](security/guarantees-and-limits.md)** — Invariants I1–I16, supported executors, and explicit non-goals.
- **[Post-Remediation Security Audit](security/audits/ACTENTRA_POST_REMEDIATION_AUDIT.md)** — Independent audit findings, reproductions, and controlled-pilot verdict.

## Guides & Reference

- **[AI-Agent Integration Guide](guides/ai-agent-integration.md)** — 9-step agent-to-Actentra workflow, `FunctionCallAdapter`, `LangChainToolWrapper`, `MCPStdioProxy`, and enforcement boundaries.
- **[Developer Guide](guides/developer-guide.md)** — Custom executors, YAML policies, approval workflows, evidence verification, error handling, and deployment configuration.
- **[Public API Reference](../docs/reference/api-reference.md)** — Public Python SDK (`actentra`) and CLI (`actentra`) reference with signatures, errors, and security notes.
- **[Deployment Guide](guides/deployment.md)** — Local dev, embedded usage, remote gateway with TLS/mTLS, principal mappings, SQLite WAL, filesystem confinement, external checkpoints, monitoring, backup/recovery, and controlled-pilot restrictions.
- **[Production Reliability Guide](architecture/deployment-reliability.md)** — Lifecycle state machine, durable idempotency, crash recovery, and disaster recovery runbook.

## Testing, Troubleshooting & Governance

- **[Testing Guide](guides/testing.md)** — Fast suite, full suite, security test suite, static analysis, and runnable examples.
- **[Troubleshooting Guide](guides/troubleshooting.md)** — Installation, authentication, authorization, postcondition, unknown-outcome, and recovery diagnostics.
- **[Contributing & Governance](../CONTRIBUTING.md)** — Development setup, quality checks, coding guidelines, versioning/release process, and security reporting ([SECURITY.md](../SECURITY.md)).
