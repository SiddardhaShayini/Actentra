"""Hypothesis property-based tests for canonicalization and deterministic policy."""

from __future__ import annotations

from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from actentra_core.canonicalize import (
    CanonicalizationError,
    canonicalize_json,
    canonicalize_windows_path,
    windows_path_join_safe,
)
from actentra_core.envelope import build_envelope
from actentra_core.policy import PolicyEngine, load_policy_file

REPO_ROOT = Path(__file__).resolve().parents[2]
_RESERVED_WIN = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_SAFE_SEGMENT = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"),
    min_size=1,
    max_size=12,
).filter(lambda s: s.upper() not in _RESERVED_WIN)


@settings(max_examples=50, deadline=None)
@given(
    drive=st.sampled_from(["C", "c", "D", "d"]),
    segs=st.lists(_SAFE_SEGMENT, min_size=1, max_size=5),
    sep=st.sampled_from(["/", "\\"]),
)
def test_windows_path_canonicalization_is_idempotent(drive: str, segs: list[str], sep: str) -> None:
    raw = f"{drive}:{sep}{sep.join(segs)}"
    once = canonicalize_windows_path(raw)
    twice = canonicalize_windows_path(once)
    assert once == twice
    assert once.startswith(f"{drive.lower()}:/")


@settings(max_examples=50, deadline=None)
@given(subpath=st.text(min_size=0, max_size=40))
def test_windows_path_join_safe_never_escapes_base_dir(subpath: str) -> None:
    base = "c:/work/sandbox"
    try:
        resolved = windows_path_join_safe(base, subpath)
    except CanonicalizationError:
        return
    assert resolved == base or resolved.startswith(f"{base}/")


@settings(max_examples=50, deadline=None)
@given(
    pairs=st.lists(
        st.tuples(
            st.text(min_size=1, max_size=10),
            st.one_of(st.integers(), st.booleans(), st.text(max_size=20), st.none()),
        ),
        min_size=0,
        max_size=10,
        unique_by=lambda kv: kv[0],
    )
)
def test_canonical_json_key_order_independent(pairs: list[tuple[str, object]]) -> None:
    d1 = dict(pairs)
    d2 = dict(reversed(pairs))
    assert canonicalize_json(d1) == canonicalize_json(d2)


@settings(max_examples=30, deadline=None)
@given(
    segs=st.lists(_SAFE_SEGMENT, min_size=1, max_size=4),
    verb=st.sampled_from(["read", "write", "delete"]),
    tool=st.sampled_from(["fs.read", "fs.write", "fs.delete", "http.post"]),
)
def test_policy_evaluation_is_deterministic(segs: list[str], verb: str, tool: str) -> None:
    policy = load_policy_file(REPO_ROOT / "policies" / "examples" / "starter.yaml")
    resource = f"path:C:/work/{'/'.join(segs)}.txt"
    env1 = build_envelope(tool=tool, verb=verb, resource=resource, session_id="prop-s1")
    env2 = build_envelope(tool=tool, verb=verb, resource=resource, session_id="prop-s1")

    d1 = PolicyEngine(policy).evaluate(env1)
    d2 = PolicyEngine(policy).evaluate(env2)
    assert d1.verdict == d2.verdict
    assert d1.rule_id == d2.rule_id
    assert d1.canonical_hash == d2.canonical_hash
    assert d1.risk_tags == d2.risk_tags
