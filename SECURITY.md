# Security Policy

Actentra is a deterministic execution boundary for AI agents. Security bugs in the canonicalizer, policy engine, approval binding, or receipt log are treated as high-priority defects.

## Supported Versions

Actentra is currently in **pre-1.0 development** (suitable for restricted controlled pilots under the deployment conditions in [ACTENTRA_POST_REMEDIATION_AUDIT.md](docs/security/audits/ACTENTRA_POST_REMEDIATION_AUDIT.md)) and is not yet recommended for unconditional external production enforcement.

| Version | Supported |
| --- | --- |
| `main` (pre-1.0) | Best-effort security fixes |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities, policy bypasses, path canonicalization differentials, or receipt-integrity bugs.

Instead, report privately to the project maintainers with:

1. A minimal reproduction (envelope, policy YAML, or path/URL/SQL payload).
2. Expected verdict vs. observed verdict.
3. Environment details (OS, Python version, connector).

We will acknowledge receipt, reproduce the issue, add a regression case to `corpus/redteam/`, and coordinate a fix before public disclosure.

## Out-of-Scope / Explicit Limits

See [docs/security/guarantees-and-limits.md](docs/security/guarantees-and-limits.md) for what Actentra does and does not defend against (for example: unmediated credentials held directly by an agent, or a fully compromised host OS).
