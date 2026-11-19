# Integration Readiness

Status labels: **Implemented**, **Partial**, **Missing**, **N/A**.

## Agent frameworks and runtimes

| Integration | Status | Evidence | Readiness limitations |
|---|---|---|---|
| Claude Code | Partial | MCP stdio proxy exists | No Claude Code distribution/configuration guide, auth, telemetry, or end-to-end identity |
| OpenAI Codex | Partial | FunctionCallAdapter uses OpenAI-style calls | No Codex-specific launcher or identity/session lifecycle |
| Cursor | Partial | MCP stdio proxy and generic JSON-RPC | No Cursor configuration, executable packaging, or documented enterprise policy workflow |
| MCP clients | Partial | `MCPStdioProxy`, stdio server | No MCP HTTP auth, OAuth, mTLS, downstream identity, or capability pinning approval workflow |
| MCP servers | Partial | Generic forwarding/proxy | Downstream server itself retains power; no sandbox, capability isolation, or execution receipt binding |
| LangChain | Implemented | `LangChainToolWrapper` | Wrapper is best-effort; direct underlying tool calls bypass wrapper unless every route is wrapped |
| CrewAI | Missing | No adapter | Generic Python callable adapter may be reusable, but no tests/package support |
| AutoGen | Missing | No adapter | Generic FunctionCallAdapter may be reused, but no integration contract |
| Custom Python agents | Implemented | `Boundary`, `guard`, function adapter | In-process only; cannot enforce direct target access outside wrapper |

## Protocols and APIs

| Capability | Status | Notes |
|---|---|---|
| MCP stdio | Partial | Message size, schema pinning, and call interception exist; no auth or network transport |
| MCP HTTP/SSE | Missing | Only stdio proxy and local HTTP REST gateway |
| REST gateway | Partial | Loopback REST, bearer remote auth, console; no TLS/mTLS/OIDC/RBAC |
| OpenAI function calls | Partial | Adapter exists and tests it; no SDK transport integration |
| Anthropic function calls | Partial | Adapter is format-compatible but not officially integrated/tested |
| LangChain modern/legacy invocation | Implemented | Duck-typed invoke/run/call |
| gRPC | Missing | No gRPC API |
| Webhooks | Missing | No signed webhook subscriptions |

## Identity and access

| Requirement | Status | Notes |
|---|---|---|
| SSO OIDC | Missing | No OIDC implementation |
| SAML | Missing | No SAML implementation |
| Enterprise directory | Missing | No LDAP/AD identity provider or role mapping |
| Agent/workload identity | Missing | HTTP agent_id is caller-asserted |
| Human approver identity | Missing | Approve endpoint has no approver principal |
| mTLS | Missing | Plain HTTP only |
| OAuth/DPoP | Missing | Shared bearer token only |
| RBAC | Missing | No role/tenant policy separation |
| Least privilege service identities | Partial | In-process local context and scoped executor APIs |

## Policy management

| Requirement | Status | Notes |
|---|---|---|
| YAML policy validation | Implemented | Strict parser and last-known-good reload |
| Centralized policy | Missing | Local file/process only |
| Policy versioning/rollout | Partial | policy hash in receipts; no central rollout/rollback |
| Policy as code/PR workflow | Partial | CI tests policy only indirectly |
| Tenant policy inheritance | Missing | no tenant model |
| Canary replay | Implemented | local historical replay |

## Secrets and key management

| Requirement | Status | Notes |
|---|---|---|
| Windows DPAPI broker | Implemented | local Windows current-user data protection |
| Environment secret injection | Partial | env prefix support |
| Vault integration | Missing | no HashiCorp/Kubernetes/cloud vault |
| KMS/HSM | Missing | no private key custody |
| Per-tool secret scope | Partial | HTTP constraint `secret_headers` |
| Secret rotation | Missing | no broker rotation workflow |

## Observability and operations

| Requirement | Status | Notes |
|---|---|---|
| SQLite audit log | Implemented | local durable chain |
| Human console | Implemented | 7-tab standalone HTML |
| OpenTelemetry | Missing | no spans/metrics |
| SIEM export | Partial | JSON/JSONL export and local audit reports |
| Prometheus | Missing | no metrics endpoint |
| Structured access logs | Missing | gateway log_message intentionally suppresses logs |
| Alerting | Missing | no built-in incident alerting |
| Health/readiness/dependency checks | Partial | simple health endpoint only |

## Deployment

| Requirement | Status | Notes |
|---|---|---|
| Windows 11 local package | Partial | scripts and Python package exist |
| Linux/macOS core | Partial | code exists, DPAPI is Windows-only |
| Docker | Missing | no Dockerfile |
| Kubernetes | Missing | no chart/manifests/operator |
| Private network | Partial | loopback or explicit remote bearer |
| TLS reverse proxy | Missing | no native TLS configuration |
| High availability | Missing | SQLite and process state |
| Disaster recovery | Partial | backup/archival CLI, no orchestrated restore/runbook |
| Signed package/release | Missing | no signing or provenance workflow |
| SBOM | Missing | no generated/published SBOM |

## Compliance and retention

| Requirement | Status | Notes |
|---|---|---|
| Tamper-evident local log | Implemented | SHA-256 chain |
| Signed checkpoints | Partial | Ed25519 API exists, key management external |
| Audit export | Implemented | JSON/JSONL and HTML report |
| Immutable off-host retention | Missing | no streaming archive sink or anchor |
| Configurable retention | Partial | archive CLI exists |
| Tenant audit separation | Missing | no tenancy |
| Change approval | Partial | approval lifecycle but no approver identity |
| Legal hold | Missing | no retention/hold management |

## Practical integration recommendations

### Claude Code/Codex/Cursor

Package one tested MCP stdio distribution for alpha. It must be read-only until gateway auth and DNS fixes exist. Document that no direct tool call may bypass the MCP process.

### LangChain/CrewAI/AutoGen

Keep LangChain wrapper. Before broader support, define a standard `ActentraToolAdapter` contract:

- resource extractor
- parameter schema
- agent/principal/session
- execution claim
- result/postcondition verifier

### Enterprise agents

Require SDK-only mediation plus OS/container/network controls. Do not rely on policy packages alone.
