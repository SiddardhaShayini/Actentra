# Actentra — Security Readiness Assessment

**Assessment date:** 2026-11-20  
**Repository state assessed:** `main` at `63e1be8cffce0243a3e87a0aa0b3728f64a963f5`

## Executive verdict

Actentra demonstrates useful local enforcement mechanisms, but this checkout is **not suitable for remote or production security enforcement**. A structured bearer token bypasses the configured shared token and can create an authenticated operator with wildcard scopes. A caller-controlled header also creates delegated authority without proving a delegation. The standalone warrant-registry fallback can forget an exhausted quota.

The HTTP executor pinning and postcondition/outcome changes materially improve their specific paths. Passing tests do not address every lifecycle, crash, host-isolation, or deployment risk.

## Suitability by deployment stage

| Stage | Assessment | Conditions / evidence required |
|---|---|---|
| **Local personal use** | **Suitable with limits** | Use loopback-only gateway, same-user trusted code, noncritical targets, least-privilege policies, and backups. Do not treat the SDK as a sandbox against malicious code running as the same user. |
| **Controlled developer testing** | **Suitable** | Use isolated workspaces, disposable databases, test credentials, simulated/local endpoints, and explicit private-IP policy only where intended. Review receipts and do not infer remote state from caller-reported outcomes. |
| **Controlled alpha pilots** | **Conditional** | Restrict to trusted operators, loopback or tightly isolated networks, noncritical systems, and reversible actions with manual approval. First remove structured-token/delegation bypasses and the standalone quota fallback hazard. Document rollback and evidence limitations. |
| **Limited production deployments** | **Not suitable in this checkout** | Require fixed authentication/delegation, durable quotas on all supported paths, tested Windows filesystem race defenses, hardened service/API boundary, crash/recovery testing, protected audit anchoring, and deployment-specific penetration testing before reconsideration. |
| **Enterprise production deployments** | **Not suitable** | Additionally require an enterprise identity/credential lifecycle, TLS/mTLS, centralized policy and key management, HA/distributed state where needed, process/network isolation, SBOM and signed release supply-chain controls, incident response/audit operations, and independent assurance. |

## Evidence established in this audit

- The current branch contains all five remediation commits and the original audit commit.
- The five dedicated remediation regression files passed: **59 passed**.
- The complete fast suite passed: **228 passed, 1 skipped**.
- Ruff passed; mypy reported no issues in 38 source files.
- The HTTP path pins validated addresses, checks the socket peer, disables ambient proxy discovery, and revalidates redirects.
- Postcondition-requested outcomes are written after verification; only verified observations create externally verified outcome evidence.
- HTTP external reports use single-use claims bound to a crossing and executor principal and are labeled caller-reported.
- Structured operator-token and delegation-header bypasses were reproduced locally.
- Finite-use quota replay in the standalone memory fallback was reproduced locally.

## Evidence required to advance

### Before alpha beyond a trusted local developer

1. Reject `agent:`, `approver:`, and `operator:` bearer strings unless they map to configured credentials; ensure a configured token cannot be bypassed by a token prefix.
2. Remove caller-controlled delegation authority. Validate delegation provenance, scope attenuation, expiry, revocation, and chain integrity at the service boundary.
3. Eliminate or fail closed on non-durable warrant registries for finite-use warrants.
4. Add integration regressions for remote-bind authentication and delegation, not only direct resolver/unit tests.

### Before any limited production

1. Run Windows-specific symlink/junction race tests and close any workspace escape paths.
2. Add process-kill and storage-failure tests around execution, postcondition verification, claim consumption, and outcome persistence.
3. Test concurrent claim/outcome writes and multiprocess SQLite behavior on supported deployment configurations.
4. Establish TLS and a real credential lifecycle for remote deployments; configure network egress controls independent of the Python HTTP executor.
5. Anchor audit checkpoints off-host and protect signing keys; validate backup/restore, retention, and incident-response procedures.
6. Conduct a scoped independent penetration test after the confirmed auth issues are fixed.

### Before enterprise production

1. Define and test the threat model for multi-tenant identity, trusted operators, delegated workers, and executor isolation.
2. Integrate an enterprise identity provider or equivalent strong credential system, role separation, rotation, revocation, and auditable authorization.
3. Adopt supported transactional HA storage if multiple nodes share authority or quotas.
4. Add dependency scanning, SBOM generation, provenance, signed builds/releases, and a vulnerability response process.
5. Demonstrate operational controls for key custody, audit integrity, monitoring, privacy, and recovery under failure.

## Five most important remaining risks

1. **HIGH — Gateway authentication bypass:** Any prefixed `operator:` bearer token can resolve to wildcard operator authority even with a configured token.
2. **HIGH — Caller-asserted delegation:** `X-Actentra-Delegated-By` contributes an arbitrary parent identity to the caller’s allowed identities.
3. **MEDIUM — Standalone quota reset:** In-memory fallback evicts exhausted warrants at its emergency capacity cap.
4. **MEDIUM — No in-process isolation:** Untrusted code in the same process can bypass SDK controls or invoke service APIs without an authenticated context.
5. **MEDIUM — Filesystem TOCTOU risk:** Path validation and later pathname-based operations may be raced by symlink/junction changes; Windows-specific adversarial testing is still needed.

## Final recommendation

The strongest next action is to repair the gateway authentication and delegation boundary and add regression tests for the exact reproduced bypasses. Keep the gateway loopback-only and avoid production or critical-system use until that work, the finite-quota fallback issue, and deployment-specific filesystem/isolation tests are addressed.

An independent external penetration test is justified after the authentication fixes land. Testing the current remote gateway is also useful to confirm exposure in a controlled environment, but a passing test should not be interpreted as readiness while the reproduced bypass remains.
