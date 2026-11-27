"""Deterministic YAML policy builder for the real-agent demonstration."""

from __future__ import annotations

from pathlib import Path

from actentra import path_resource


def build_demo_policy_yaml(workspace_root: Path) -> str:
    """Build a fail-closed YAML policy scoped strictly to ``workspace_root``.

    Rules:
    - Defaults to ``deny``.
    - Denies privilege escalation and shell execution.
    - Allows workspace reads and listings.
    - Allows writes under ``<workspace>/drafts/**`` and ``<workspace>/unreliable/**``
      with mandatory ``digest_match`` postcondition verification.
    - Requires explicit human approval (``ask``) for writes under ``<workspace>/approved/**``
      and deletes anywhere in ``<workspace>/**``.
    """
    ws = path_resource(workspace_root).removeprefix("path:")
    return f"""\
version: 1
policy_id: real-agent-demo-policy
mode: enforce

defaults:
  verdict: deny
  reason: "Denied by default fail-closed policy"

rules:
  - id: block-privilege-escalation
    match:
      risk_any: [privilege-escalation]
    verdict: deny
    reason: "Sensitive paths and privilege-escalating actions are blocked"

  - id: block-shell-execution
    match:
      tool: "shell.*"
    verdict: deny
    reason: "Arbitrary shell execution is prohibited"

  - id: allow-workspace-list
    match:
      tool: fs.list
      verb: read
      resource: "path:{ws}"
    verdict: allow
    reason: "Allow listing workspace root"

  - id: allow-workspace-list-sub
    match:
      tool: fs.list
      verb: read
      resource: "path:{ws}/**"
    verdict: allow
    reason: "Allow listing workspace subdirectories"

  - id: allow-workspace-read
    match:
      tool: fs.read
      verb: read
      resource: "path:{ws}/**"
    verdict: allow
    reason: "Allow reading non-sensitive workspace files"

  - id: allow-draft-write-verified
    match:
      tool: fs.write
      verb: write
      resource: "path:{ws}/drafts/**"
    verdict: allow
    reason: "Allow draft writes with mandatory digest_match postcondition"
    constraints:
      require_postcondition: true
      postcondition: digest_match

  - id: allow-unreliable-test-write
    match:
      tool: unreliable.fs_write
      verb: write
      resource: "path:{ws}/unreliable/**"
    verdict: allow
    reason: "Allow test executor call with mandatory digest_match postcondition"
    constraints:
      require_postcondition: true
      postcondition: digest_match

  - id: ask-approved-write
    match:
      tool: fs.write
      verb: write
      resource: "path:{ws}/approved/**"
    verdict: ask
    reason: "Writes to approved/ require explicit human approval"
    constraints:
      require_postcondition: true
      postcondition: digest_match

  - id: ask-workspace-delete
    match:
      tool: fs.delete
      verb: delete
      resource: "path:{ws}/**"
    verdict: ask
    reason: "Deleting workspace files requires explicit human approval"
    constraints:
      require_postcondition: true
      postcondition: absent
"""
