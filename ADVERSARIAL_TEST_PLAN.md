# Adversarial Test Plan

## Objective

Add evidence-based tests that demonstrate whether documented security claims hold under malformed input, DNS/network manipulation, concurrency, crashes, identity mismatch, and local persistence corruption.

## P0 security regressions

### T-01 DNS rebinding and dual-resolution

- Monkeypatch DNS to return public IP during validation and private IP during socket connection.
- Use a local HTTP server at loopback.
- Assert no socket connect and no response.
- Repeat for all redirect hops.

### T-02 Lease release and handoff identity

- Authenticate as agent-B and supply agent-A identities in JSON.
- Attempt handoff create/advance/verify and lease acquire/release.
- Assert no state mutation unless the authenticated principal is explicitly authorized.
- Test shared, different-session, and missing-owner cases.

### T-03 Warrant quota restart and eviction

- Issue a `max_uses=1` warrant.
- Use once, restart Boundary/WarrantRegistry.
- Assert second use denied.
- Force eviction of 1001 counters.
- Run concurrent consumption threads and assert exactly `max_uses`.

### T-04 Postcondition semantics

- For `exists`, `absent`, and `digest_match`, test success, refuted, error, stale, and verifier exception.
- Assert success only for verified success and appropriate failure/unknown outcome for others.
- Assert no externally-verified evidence on refuted/error.

### T-05 External outcome binding

- Record allowed crossing.
- Submit status before execution claim.
- Replay claim and outcome.
- Authenticate two executor principals.
- Assert only exact claim + executor may report once.

### T-06 Approval replay/race

- Approve once and start 100 concurrent execute calls.
- Assert exactly one executes and every replay is denied.
- Test process restart after approve but before claim.
- Test expiry between claim and executor dispatch.

## Property-based tests

Using Hypothesis:

- Canonicalization must be stable and NUL/control-free.
- Action hash recomputation must equal stored hash for unchanged payload.
- Mutating any session, agent, tool, verb, resource, or parameter field must change hash or trigger mismatch.
- Policy evaluation must be deterministic for identical input and policy hash.
- Resource lease overlap must be symmetric and never allow conflicting exclusive leases.
- Handoff scope expansion must be rejected.
- Receipt chain remains valid for every generated action/outcome sequence.
- Secret redaction must remove every known value from nested response structures and error text.

## Fuzz targets

1. JSON envelope fields and raw params.
2. Windows paths, UNC paths, 8.3 names, ADS, trailing dots/spaces, reserved names.
3. URLs including mixed-case schemes, credentials, redirects, IPv4/IPv6, IDN, percent encoding.
4. SQL single-statement parser and parameter shapes.
5. MCP tool names, JSON-RPC IDs, schema descriptions, inputSchema variants.
6. Policy YAML and unknown keys, booleans, numbers, Unicode, duplicate IDs.
7. Handoff/lease metadata and JSON nesting depth.

Fuzzing should assert no crash, no raw secret, no execution on invalid decision, and no receipt corruption.

## Filesystem and SQL attacks

- symlink/junction replacement between canonicalization and read/write/delete
- hard link to outside data
- workspace directory replaced
- parent directory created outside root
- reserved device names and ADS
- SQLite attached databases and PRAGMA abuse
- SQL comments, semicolon splitting, DDL bypassing read-only inference
- write to SQLite transaction with trigger effects

## MCP attacks

- rug-pull first list/call/list/call sequence
- schema ballooning above size limits
- duplicate tool names
- malformed JSON-RPC
- downstream server exits mid-call
- notification masquerading with call-like payload
- mapper ambiguity and argument alias confusion

## Concurrency and crash testing

- parallel approval claims
- parallel lease acquisition
- parallel warrant consumption
- parallel outcome writes
- process crash after decision and before execution
- crash after function returns and before success outcome
- SQLite lock, disk full, read-only DB, WAL corruption
- abrupt process termination while policy reload and DB commit occur

## Integration tests

- Python SDK, LangChain adapter, function calling adapter
- MCP stdio roundtrip
- HTTP gateway loopback/remote
- restart survival for policies, approvals, leases, budgets, taint, and warrants
- external executor claim/outcome
- independent verifier
- signed checkpoint creation/anchoring

## Performance benchmarks

Establish baseline and thresholds for:

- envelope canonicalization and policy evaluation p50/p95/p99
- SQLite decision/outcome throughput
- concurrent approval/lease/warrant operations
- 1k/100k/1M receipt verification and export
- max response body and MCP message limits
- memory and thread growth under sustained requests
- WAL archive/backup duration

Initial enterprise thresholds should be defined only after an intended deployment profile exists.

## Chaos/fault injection

- DNS outage and alternate answers
- outbound TLS/DNS latency
- SQLite I/O error and lock
- full disk
- process kill
- clock rollback/forward jump
- policy file corruption
- corrupt archive/checkpoint
- missing/private/public key
- secret store unavailable

Every action must remain deny/hold/unknown unless a valid durable state proves allow.

## Independent assurance

Before critical use:

- external penetration test of gateway and executor boundary
- formal threat model workshop
- canonicalization/parser differential review
- Windows reparse/junction specialist review
- cryptographic protocol/key-management review
- SQLite crash-recovery and backup/restore review
- supply-chain/SBOM and signed release assessment
