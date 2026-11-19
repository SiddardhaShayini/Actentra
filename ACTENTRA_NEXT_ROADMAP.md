# Actentra Next Roadmap

This roadmap prioritizes a solo developer with limited hardware and budget. It avoids parallel distributed-platform work before the enforcement semantics are corrected.

## Security-critical fixes

### 0-30 days

1. **Bind HTTP identities to authenticated principals**
   - remove caller-controlled agent identity authority
   - add tenant, agent, approver, operator, and executor principal types
   - support mTLS or short-lived OIDC/JWT validation
   - reject owner=None lease release

2. **Fix DNS rebinding**
   - pin validated IP and connect to pinned peer
   - validate every redirect and proxy peer
   - add controlled DNS-rebinding tests

3. **Make warrant quotas durable and atomic**
   - store counters in transactional SQLite/PostgreSQL
   - increment and check atomically
   - retain counters through restart and eviction

4. **Fix postcondition outcome semantics**
   - never record success before verification
   - map refuted/error/unknown appropriately
   - add outcome observation transaction

5. **Authenticate external outcome reporting**
   - issue one-time crossing execution claims
   - bind claim to crossing, principal, hash, and session
   - preserve caller-reported vs independently verified evidence

6. **Repair filesystem TOCTOU**
   - open resolved directories/files with OS-native handles
   - validate no reparse/junction changes at dispatch
   - test path replacement races

## Enterprise-readiness improvements

### 30-90 days

1. **Choose state target**
   - embedded SQLite for single-host/offline mode
   - PostgreSQL for enterprise mode
   - document exact consistency and recovery guarantees

2. **Add signed execution/approval artifacts**
   - typed, tenant-bound, expiring crossing claim
   - independently verifiable approval record
   - approver identity and signing key

3. **Secrets and key management**
   - external vault/KMS integration
   - key rotation
   - unencrypted Ed25519 key generation only as development mode

4. **Operational telemetry**
   - OpenTelemetry tracing/metrics
   - structured audit and access logs
   - SIEM JSON and checkpoint export
   - health, readiness, database, key, and executor checks

5. **Native TLS/mTLS**
   - HTTPS gateway
   - mutual executor/agent auth
   - proxy-header trust controls

6. **Backups and recovery**
   - documented restore and chain-anchoring runbook
   - checksum/sequence verification after restore
   - automated retention/archive tests

## Integration improvements

### 30-120 days

1. Publish a Claude Code/Cursor MCP configuration package.
2. Create stable MCP server lifecycle/identity contract.
3. Add CrewAI and AutoGen adapters with end-to-end tests.
4. Add an official HTTP MCP transport only after auth/TLS.
5. Define an enterprise tool adapter contract for LangChain and custom agents.
6. Add OIDC support first; SAML later as a connector.

## Testing and assurance

### Parallel, starting immediately

- Implement the P0 regression suite in this document.
- Add Hypothesis canonicalization/policy/lease properties.
- Add fuzz harnesses for URLs, paths, SQL, JSON-RPC, and YAML.
- Add process-crash and disk-full chaos tests.
- Add SQLite and HTTP concurrency tests.
- Add benchmark baselines.
- Add a third-party penetration test before external/remote deployment.
- Add a cryptographic protocol/key-custody review.
- Add Windows reparse/junction race review.
- Add independent supply-chain review.

## Optional enhancements

- operator console approval UX improvements
- additional local file/SQL verifier claims
- policy canary UI
- standalone desktop installer
- shell executor, if implemented with a separate process sandbox
- SaaS connector framework
- policy editor
- export adapters for datadog/splunk/elasticsearch

Do not add these until P0/P1 security fixes and basic enterprise identity/state exist.

## Long-term research opportunities

- formally verified canonicalization and policy semantics
- remote attestation for executor/verifier hosts
- confidential execution and key custody
- distributed lease consensus with platform-level enforcement
- cryptographic causal provenance across services
- multi-cluster policy replication
- post-quantum signatures
- automated intent/semantic verification
- robust causal/transactional postconditions for SaaS systems

## Exit criteria for a critical-system pilot

An enterprise pilot should not proceed until:

- P0 security findings are fixed and third-party retested
- every agent and human principal is authenticated
- approval and warrant state is durable and atomic
- DNS/peer pinning is verified
- external outcome claims are cryptographically bound
- signed checkpoints are anchored outside the host
- backup/restore and crash recovery are tested
- policy, lease, and approval behavior has load/concurrency benchmarks
- release artifacts have SBOM and signatures
- direct execution bypasses are documented and mitigated by OS/IAM controls
