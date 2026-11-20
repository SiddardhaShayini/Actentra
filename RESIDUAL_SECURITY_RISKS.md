# Actentra — Residual Security Risks

**Assessment date:** 2026-11-20  
**Scope:** Risks remaining after independent review of remediation commits `70b09e8` through `63e1be8`

## Confirmed vulnerabilities

| ID | Severity | Exploitability | Confidence | Impact | Evidence and recommended next action |
|---|---|---|---|---|---|
| R-1 | **HIGH** | High if the gateway is remotely reachable with remote binding explicitly enabled | 10/10 | A caller can use `Bearer operator:<value>` instead of the configured secret. The resolver grants authenticated operator authority with wildcard scope. A caller can also add a victim identity with `X-Actentra-Delegated-By`. | `gateway/actentra_gateway/http_service.py:122-147`; `core/actentra_core/identity.py:220-280,300-309`. Reproduced locally. Accept only configured credentials/principal mappings; derive delegation from a verified, bounded grant, never a request header. |
| R-2 | **MEDIUM** | High when an application uses standalone `WarrantRegistry` without a `ReceiptStore` and reaches its emergency capacity | 9/10 | Exhausted warrant usage can be forgotten and a finite-use warrant consumed again. | `core/actentra_core/warrants.py:260-290`. Reproduced with `max_warrants=2`. Remove the fallback from security-sensitive paths or make quota exhaustion non-evictable; add a regression exceeding the `2 * max_warrants` cap. |

## Potential vulnerabilities requiring further proof

| ID | Severity | Exploitability | Confidence | Impact | Evidence and recommended next action |
|---|---|---|---|---|---|
| R-3 | **MEDIUM** | Requires an attacker able to race filesystem paths within the same host/workspace | 7/10 | A symlink/junction or parent path may be replaced between containment validation and a pathname-based filesystem operation. Reads or writes could cross the intended workspace boundary. | `executors/actentra_executors/fs.py:48-75,120-174`. Existing path checks are useful but not handle-relative atomic operations. Add Windows junction/reparse-point swap tests and evaluate handle-based/no-follow APIs. |
| R-4 | **MEDIUM** | Requires control of untrusted Python/plugin code in the Actentra process | 8/10 | A plugin can bypass the SDK by calling raw OS/network libraries or service methods without `caller_context`; there is no process sandbox. | `gateway/actentra_gateway/services.py:158-200,592-817` and in-process executor model. Define a trusted-code boundary or isolate untrusted workers in separate OS/container identities with egress controls. |

## Architectural limitations

| ID | Severity | Exploitability | Confidence | Impact | Recommended next action |
|---|---|---|---|---|---|
| R-5 | **MEDIUM** | Host administrator or attacker with database/key access | 9/10 | SQLite hash chaining is local tamper evidence, not protection against a privileged host adversary; signed checkpoints are only useful if private keys/checkpoints are independently protected and anchored. | Use external checkpoint anchoring and managed key custody; test backup/restore and tamper detection. |
| R-6 | **LOW** | Requires failure between execution-claim consumption and outcome persistence | 7/10 | Claim consumption and receipt writing are separate transactions; a write failure can leave a consumed claim without an outcome, limiting retry/recovery and leaving execution state indeterminate. | Make claim consumption and outcome commit one transaction or add explicit recoverable pending/indeterminate states and fault-injection tests. |
| R-7 | **LOW** | Requires caller to treat an executor return as proof of verified postcondition | 8/10 | With default `raise_on_postcondition_failure=False`, `Boundary.execute()` returns the original executor result even when the receipt is failure/unknown. | Keep behavior explicit in API docs; prefer strict mode where callers must not continue after failed/unknown verification. |
| R-8 | **LOW** | External reporter must possess a valid claim/principal; no compromise needed beyond that authorized role | 10/10 | Claim binding prevents arbitrary/replayed reports, but a valid executor can still report success without proof that the external side effect occurred. The evidence is correctly `caller_reported`. | Preserve the evidence tier and require an independent verifier for workflows needing verified external state. |

## Operational deployment risks

1. **Remote transport and credentials:** Remote binding is explicitly gated, but the current structured-token bypass makes the configured bearer-token check ineffective for prefixed token values. No TLS/mTLS, token rotation, or enterprise identity provider integration was validated. Do not expose this build remotely.
2. **Local unauthenticated mode:** Loopback mode grants a broad developer capability set. Treat other local processes and same-user code as trusted; loopback is not a process-isolation boundary.
3. **Single-host persistence:** SQLite transactions are suitable for local/single-host state but do not establish multi-node, multi-region, or consensus guarantees. This audit did not independently test multiprocess contention or recovery faults.
4. **Secrets and keys:** DPAPI storage is scoped to the current Windows user. Environment credentials remain in process memory. Checkpoint private keys are unencrypted PEM when generated; no KMS/HSM custody was found or validated.
5. **Supply chain:** `uv.lock` is present, but this audit did not run a dependency vulnerability scanner, produce an SBOM, validate provenance, or verify signed release artifacts.
6. **Resource exhaustion:** `ThreadingHTTPServer` and broad request-level resource behavior were not load-tested. Body size limits exist, but sustained connection/thread exhaustion has not been ruled out.
7. **Stale product documentation:** `docs/product-status.md` still says warrant counters are process-local. Its description does not match the normal SQLite-backed `Boundary` path and also does not disclose the standalone fallback eviction issue. Reconcile this after implementation changes.

## Improvements, not automatically defects

- Replacing single-host SQLite with a distributed transactional store is a deployment expansion, not a defect for the documented local-first use case.
- OIDC, SAML, KMS/HSM, multi-region coordination, and enclave attestation are enterprise enhancements. The immediate confirmed defect is weaker: caller-controlled structured tokens/delegation bypass the current gateway’s stated authentication boundary.
- A caller-reported external outcome is not independently verified evidence by design. It becomes a security defect only if downstream consumers incorrectly promote that evidence tier.
