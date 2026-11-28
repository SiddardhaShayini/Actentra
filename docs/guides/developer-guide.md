# Developer Guide

Practical patterns for Python developers building with Actentra: custom executors, custom YAML policies, approval workflows, evidence verification, error handling, and deployment configuration.

---

## 1. Python SDK Basics (`Boundary` & `@guard`)

Create a `Boundary` from a YAML file (`Boundary.from_files`) or inline YAML (`Boundary.from_yaml`), register executors, and run actions via `boundary.run()`, `boundary.execute()`, or `@boundary.guard(...)`:

```python
from pathlib import Path
from actentra import Boundary, path_resource

workspace = Path("./workspace").resolve()
workspace.mkdir(exist_ok=True)
ws = path_resource(workspace).removeprefix("path:")

POLICY_YAML = f"""
version: 1
policy_id: dev-guide
mode: enforce
defaults:
  verdict: deny
  reason: "Denied by default"
rules:
  - id: allow-read
    match:
      tool: fs.read
      verb: read
      resource: "path:{ws}/**"
    verdict: allow
    reason: "Allow workspace reads"
"""

boundary = Boundary.from_yaml(
    policy_yaml=POLICY_YAML,
    receipts_db="receipts.db",
    workspace_root=workspace,
)

@boundary.guard(
    tool="fs.read",
    verb="read",
    resource_fn=lambda filename: path_resource(filename, workspace_root=workspace),
)
def read_note(filename: str) -> str:
    return (workspace / filename).read_text(encoding="utf-8")
```

Use `boundary.dry_run(tool=..., verb=..., resource=...)` to simulate policy evaluation without executing or consuming rate-limit buckets.

---

## 2. Custom Executors

Register custom tool callables with `boundary.register_executor(tool_name, fn)` where `fn(envelope: ActionEnvelope, decision: Decision) -> Any`:

```python
from actentra_core.envelope import ActionEnvelope
from actentra_core.verdict import Decision

def custom_echo(envelope: ActionEnvelope, decision: Decision) -> dict[str, str]:
    msg = str(envelope.action.params.get("message", ""))
    return {"echo": msg, "rule": decision.rule_id}

boundary.register_executor("custom.echo", custom_echo)
```

For production tools, always enforce resource confinement inside the executor and inject secrets via `SecretsBroker` rather than accepting raw credentials in `params`.

---

## 3. Custom Policies (YAML)

Actentra policies (`spec/policy.v1.schema.json`) use **deny-overrides** evaluation:
- `DENY` > `HOLD` > `ASK` > `ALLOW_WITH_CONSTRAINTS` > `ALLOW`.
- Missing or unmatched rules fall through to `defaults.verdict` (recommended: `deny`).

```yaml
version: 1
policy_id: custom-policy
mode: enforce

defaults:
  verdict: deny
  reason: "Denied by default"

limits:
  - id: session-rate
    scope: session
    max_actions_per_minute: 60
    max_actions_per_session: 200
    max_external_calls_per_session: 20
    max_write_bytes_per_session: 10485760

rules:
  - id: deny-env-files
    match:
      resource: "**/.env*"
    verdict: deny
    reason: "Sensitive .env access denied"

  - id: ask-writes
    match:
      tool: fs.write
      verb: write
      resource: "path:C:/work/**"
    verdict: ask
    constraints:
      require_postcondition: true
      postcondition: digest_match
    reason: "Writes require approval and digest verification"
```

Validate policies before deployment with:
```powershell
actentra policy check my_policy.yaml
actentra policy canary receipts.db my_policy.yaml
```

---

## 4. Approval Workflows

When a rule returns `Verdict.ASK`:
- **In-Process SDK:** Provide `approval_callback(envelope, decision) -> bool` (e.g., `cli_approval_prompt` for interactive terminal approval) or pre-grant an approval via `boundary.grant_approval(canonical_hash=..., session_id=...)`. Approvals are single-use and expire after `approval_ttl_seconds`.
- **HTTP Gateway:** `POST /v1/crossings` persists `ASK` crossings in SQLite `pending_approvals`. An operator reviews and resolves them via `/ui`, `POST /v1/crossings/{id}/approve`, or `actentra approvals resolve <crossing_id> --approve`.

---

## 5. Evidence Verification & Postconditions

Enable postcondition verification on mutating operations:
- Pass `verify_postcondition=True` and `raise_on_postcondition_failure=True` to `boundary.run(...)` or `boundary.execute(...)`.
- For `fs.write`, Actentra automatically derives `claim="digest_match"` and computes `expected_digest` from `params["content"]` when `strict=True` (rejecting weak `exists` claims).
- Perform standalone read-only checks with `boundary.verify_state(resource, claim="digest_match", expected_digest=...)`.

---

## 6. Error Handling

| Exception | Cause | Recommended Handling |
|---|---|---|
| `ActionBlockedError` | `DENY`, `HOLD`, or unapproved `ASK` | Inspect `exc.decision.verdict`, `exc.decision.rule_id`, `exc.crossing_id`; do not retry without policy/approval change |
| `PostconditionFailedError` | Verifier returned `refuted`, `error`, or `unknown` | Inspect `exc.observation` and `exc.outcome_status`; reconcile if `unknown` |
| `CanonicalizationError` | Path traversal, ADS, 8.3 name, or malformed URL | Reject input and surface validation error |
| `ExecutorError` | Filesystem escape, SSRF IP block, or SQL authorizer denial | Log security denial and abort |
| `PolicyValidationError` | Invalid YAML policy schema or rule | Fix policy; `PolicyStore` preserves last-known-good policy |
| `DatabaseUnavailableError` | SQLite missing or failed integrity check | Fail closed; run `actentra verify-log` and restore/reconcile |
| `IdempotencyConflictError` / `IdempotencyInFlightError` / `ReconciliationRequiredError` | Reused key with different params, concurrent duplicate, or crashed action | Fix params, wait for completion, or run `reconcile_outcome()` |

---

## 7. Deployment Configuration

Choose a `SecurityProfile` (`core/actentra_core/checkpoints.py`) and `DeploymentMode` (`gateway/actentra_gateway/http_service.py`) matching your environment:
- `local_dev` / `local_trusted` + `DeploymentMode.LOCAL`: Loopback development.
- `controlled_pilot` + `DeploymentMode.PRIVATE_NETWORK` / `REMOTE`: Requires TLS, auth, `CheckpointAnchor`, and `KeyRing`.
- `external_production`: Additionally requires custody-separated durable `CheckpointAnchor`, `require_client_cert=True`, and `cert_principals`/`token_principals`. See [Deployment Guide](deployment.md).
