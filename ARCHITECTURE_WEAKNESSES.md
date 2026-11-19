# Architecture Weaknesses

## Executive summary

The architecture is coherent as a local Python SDK and alpha gateway, but it is not yet a distributed enforcement plane. It is primarily a process-local kernel with SQLite persistence. Its strongest properties are canonicalization, policy determinism, receipt sequencing, and scoped executor APIs. Its weakest properties are authenticated identity, distributed coordination, cryptographic execution evidence, availability, and control-plane security.

## 1. Enforcement boundary

### Strengths

- `Boundary.execute()` centralizes envelope creation, policy evaluation, receipt persistence, hash revalidation, and outcome recording.
- The function and LangChain adapters route calls through `Boundary.execute()`.
- MCP stdio proxy intercepts `tools/call` and blocks unknown tools before forwarding.
- FS/SQL executors are bound to a workspace/database and the HTTP executor validates URL policy constraints.

### Weaknesses

- I1 is not enforceable by Actentra: in-process agents can hold raw credentials or call targets outside wrapped APIs.
- HTTP external executors only report outcomes; the gateway cannot prove execution.
- MCP downstream server processes receive JSON-RPC only after proposal checks, but the proxy has no end-to-end auth or mTLS.
- Arbitrary callable adapters can perform side effects that bypass registered executor policy constraints.
- The code can be bypassed operationally by running tools outside Actentra.

**Architectural requirement:** Enterprise deployment needs mandatory sidecar/network/IAM enforcement, not SDK-only mediation.

## 2. Trust model

The implementation defines `CallerContext`, but HTTP tokens are shared bearer secrets with no subject, role, tenant, agent, or key lifecycle. It allows loopback unauthenticated callers and trusts `X-Actentra-Identity` only as a display/claim. This means handoffs and leases are not identity-bound despite some string-equality checks.

**Needed trust hierarchy:**

1. short-lived tenant principal
2. agent/workload identity
3. delegated warrant identity
4. human approver identity
5. executor identity
6. independent verifier identity

No one of these is currently cryptographically established end-to-end by the gateway.

## 3. Single points of failure

In local mode, the single Python process owns policy state, freeze state, rate-limit buckets, warrant counters, and gateway executors. SQLite is the only durable control/audit store.

Failure exposure:

- process loss loses freeze and in-memory token buckets
- SQLite lock or corruption blocks or degrades enforcement
- host loss destroys local state unless backup/anchor exists
- receipt DB and private signing key may share the compromised host
- gateway restart may replay pending approvals without a human notification/re-authentication flow
- policy reload is process-local

## 4. SQLite limitations

SQLite is appropriate for alpha local persistence but not a distributed control plane:

- one writer, cross-process lock contention under high concurrency
- no HA replication, leader election, or split-brain model
- no multi-region consistency
- lease conflicts and approval claims are local to one database
- backup, restore, and archival require coordinated operators
- no native RBAC, tenant isolation, or encryption-at-rest
- database growth, compaction, and retention are not automated
- file permissions and host encryption are deployment responsibilities

The existing synchronous setting is configurable, but the default `NORMAL` does not equal `FULL`; it should not be described as full power-loss durability.

## 5. Resource leases

SQLite leases are real local coordination records with atomic acquisition, wildcard matching, expiry, and release ownership.

Limitations:

- not distributed and not enforced in the OS or external systems
- executor mutation must independently hold the lease
- lease acquisition is not tied to the exact identity used in gateway operations
- HTTP may release by omitted or impersonated owner
- a same-owner agent can mutate overlapping resources under separate sessions
- TTL expiry is cooperative and can leave target systems mutable after lease loss
- wildcard matching has syntax ambiguity for different resource types

They support a local stress-test, not strong distributed mutual exclusion.

## 6. Evidence and postconditions

`locally_observed`, `caller_reported`, `externally_verified`, `stale`, and `unknown` are meaningful labels but are not all equally defensible:

- locally observed means a registered scoped executor completed a function call
- caller-reported means an external caller submitted an outcome
- externally verified means a configured verifier returned an observation
- the verifier is trusted because it runs on the same host/host identity

The Boundary records success before postcondition verification. A refuted observation therefore does not change execution outcome.

Postcondition verifier coverage is currently filesystem-oriented. It does not validate HTTP mutations, SQL effects, KMS changes, SaaS APIs, or external transaction commit semantics.

## 7. Cryptographic scope

- action hashes are SHA-256 canonical payload hashes, not signatures
- approval grants are process/SQLite state, not signed authorization artifacts
- receipt chains are tamper-evident, not tamper-resistant
- lease/handoff hashes detect local payload substitution but are not signed
- warrant/checkpoint signatures use Ed25519
- checkpoints prove signing key possession at a sequence/head only if the public key and checkpoint are externally anchored
- private Ed25519 keys have no KMS/HSM or rotation model

## 8. Production workload concerns

- `ThreadingHTTPServer` has no TLS, HTTP/2, proxy controls, or formal request backpressure
- body size is bounded, but thread count, DB writes, and HTTP executor concurrency are unbounded
- SQLite fetch pagination is bounded but `ThreadingHTTPServer` can create many concurrent connections
- HTTP response reads are bounded, but DNS and upstream stalls depend on timeout controls
- no metrics, tracing, audit exporter, or service health dependencies
- no leader-aware rate limits
- no tenant quotas or capacity management
- no blue/green, rolling migration, or schema migration framework

## 9. Complexity vs. value

Useful complexity:

- canonicalization
- receipt chain
- approvals
- policy canary
- evidence taxonomy
- warrants
- leases/handoffs
- scoped executors

Excessive or premature complexity for current stage:

- too many overlapping coordination abstractions before authenticated principals exist
- claims of enterprise features without an enterprise control plane
- multiple local-only state models instead of one explicit policy/identity state service
- broad console feature surface before TLS/RBAC

## Recommended architecture

For an incremental solo-developer route:

1. Keep the Python kernel and receipt library as a library, not as a public HTTP authority.
2. Add a small authenticated sidecar/control-plane API using mTLS and signed execution claims.
3. Move identity and durable quotas to one transactional store first (PostgreSQL) rather than immediately building Kubernetes HA.
4. Keep SQLite as an embedded/offline mode, with explicit unsupported/limited enterprise semantics.
5. Bind approval, warrant, crossing, execution claim, and outcome under a single tenant/session/agent identity model.
6. Establish external sinks and independently anchored checkpoints before adding advanced features.
