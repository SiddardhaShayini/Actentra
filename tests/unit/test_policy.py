"""Unit tests for PolicyEngine, PolicyStore, and JSON schema conformance."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from actentra_core.envelope import ProvenanceItem, build_envelope
from actentra_core.policy import (
    PolicyStore,
    PolicyValidationError,
    lint_policy,
    load_policy_file,
    load_policy_yaml,
)
from actentra_core.verdict import Verdict

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_starter_policy_and_envelope_validate_against_json_schemas() -> None:
    policy_schema = json.loads(
        (REPO_ROOT / "spec" / "policy.v1.schema.json").read_text(encoding="utf-8")
    )
    envelope_schema = json.loads(
        (REPO_ROOT / "spec" / "envelope.v1.schema.json").read_text(encoding="utf-8")
    )

    starter_raw = yaml.safe_load(
        (REPO_ROOT / "policies" / "examples" / "starter.yaml").read_text(encoding="utf-8")
    )
    jsonschema.validate(instance=starter_raw, schema=policy_schema)

    env = build_envelope(
        tool="fs.read",
        verb="read",
        resource=r"path:C:\work\notes.txt",
        user_goal="Read notes",
        provenance=[ProvenanceItem(source="cli", trust="trusted")],
    )
    jsonschema.validate(instance=env.to_dict(), schema=envelope_schema)


def test_deny_overrides_allow_regardless_of_rule_order() -> None:
    policy = load_policy_yaml(
        """
version: 1
defaults:
  verdict: deny
rules:
  - id: allow-all-http
    match: { tool: "http.*" }
    verdict: allow
  - id: deny-untrusted-egress
    match: { tool: "http.*", taint: untrusted, risk_any: [external-egress] }
    verdict: deny
    reason: "Blocked untrusted egress"
"""
    )
    store = PolicyStore(policy)
    env = build_envelope(
        tool="http.post",
        verb="network",
        resource="https://example.com/hook",
        provenance=[ProvenanceItem(source="email:inbound", trust="untrusted")],
    )
    dec = store.engine.evaluate(env)
    assert dec.verdict == Verdict.DENY
    assert dec.rule_id == "deny-untrusted-egress"


def test_default_deny_for_unknown_tool() -> None:
    policy = load_policy_file(REPO_ROOT / "policies" / "examples" / "starter.yaml")
    store = PolicyStore(policy)
    env = build_envelope(tool="unknown.tool", verb="other", resource="res:1")
    dec = store.engine.evaluate(env)
    assert dec.verdict == Verdict.DENY
    assert dec.rule_id == "default"


def test_rate_limit_enforced_per_session() -> None:
    now = [100.0]
    policy = load_policy_yaml(
        """
version: 1
defaults: { verdict: deny }
limits:
  - id: cap-2
    scope: session
    max_actions_per_minute: 2
rules:
  - id: allow-read
    match: { tool: fs.read, verb: read }
    verdict: allow
"""
    )
    from actentra_core.policy import PolicyEngine

    engine = PolicyEngine(policy, clock=lambda: now[0])
    env = build_envelope(
        tool="fs.read", verb="read", resource="path:C:/work/a.txt", session_id="s1"
    )
    assert engine.evaluate(env).verdict == Verdict.ALLOW
    assert engine.evaluate(env).verdict == Verdict.ALLOW
    blocked = engine.evaluate(env)
    assert blocked.verdict == Verdict.DENY
    assert blocked.rule_id == "limit:cap-2"

    # Another session still has its own budget
    env_s2 = build_envelope(
        tool="fs.read", verb="read", resource="path:C:/work/a.txt", session_id="s2"
    )
    assert engine.evaluate(env_s2).verdict == Verdict.ALLOW

    # Advancing clock past 60s restores s1 budget
    now[0] += 61.0
    assert engine.evaluate(env).verdict == Verdict.ALLOW


def test_shadow_mode_logs_would_verdict_without_blocking() -> None:
    policy = load_policy_yaml(
        """
version: 1
mode: shadow
defaults: { verdict: deny, reason: "Default deny" }
rules: []
"""
    )
    store = PolicyStore(policy)
    env = build_envelope(tool="fs.write", verb="write", resource="path:C:/work/x.txt")
    dec = store.engine.evaluate(env)
    assert dec.shadow is True
    assert dec.verdict == Verdict.ALLOW
    assert dec.would_verdict == Verdict.DENY


def test_kill_switch_blocks_non_read_actions() -> None:
    policy = load_policy_yaml(
        """
version: 1
defaults: { verdict: deny }
rules:
  - id: allow-all
    match: { tool: "fs.*" }
    verdict: allow
"""
    )
    store = PolicyStore(policy)
    store.engine.freeze()

    read_env = build_envelope(tool="fs.read", verb="read", resource="path:C:/work/a.txt")
    write_env = build_envelope(tool="fs.write", verb="write", resource="path:C:/work/a.txt")
    assert store.engine.evaluate(read_env).verdict == Verdict.ALLOW
    assert store.engine.evaluate(write_env).verdict == Verdict.DENY
    assert store.engine.evaluate(write_env).rule_id == "kill-switch:frozen"


def test_invalid_reload_preserves_last_known_good_policy() -> None:
    initial = load_policy_file(REPO_ROOT / "policies" / "examples" / "starter.yaml")
    store = PolicyStore(initial)

    with pytest.raises(PolicyValidationError):
        store.reload_yaml("version: 1\ndefaults: { verdict: allow }\nrules: []\n")

    assert store.current.policy_hash == initial.policy_hash


def test_lint_policy_flags_shadowed_and_unscoped_rules() -> None:
    pack = load_policy_yaml(
        """
version: 1
mode: shadow
defaults: { verdict: deny }
rules:
  - id: r1
    match: { tool: fs.read }
    verdict: allow
  - id: r2
    match: { tool: fs.read }
    verdict: allow
"""
    )
    warnings = lint_policy(pack)
    assert any("shadow" in w.lower() for w in warnings)
    assert any("rate limits" in w.lower() for w in warnings)
    assert any("shadowed by earlier rule 'r1'" in w for w in warnings)
