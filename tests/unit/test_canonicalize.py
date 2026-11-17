"""Unit and red-team corpus tests for Windows path & JSON canonicalization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from actentra_core.canonicalize import (
    CanonicalizationError,
    canonicalize_json,
    canonicalize_windows_path,
    hash_canonical,
    match_resource_pattern,
    windows_path_join_safe,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_windows_path_normalization_and_idempotence() -> None:
    raw = r"C:\Work\Sub\.\Nested\..\Report.TXT"
    canon = canonicalize_windows_path(raw)
    assert canon == "c:/work/sub/report.txt"
    assert canonicalize_windows_path(canon) == canon


def test_windows_path_case_and_slash_equivalence() -> None:
    p1 = canonicalize_windows_path(r"C:\Work\Data\File.json")
    p2 = canonicalize_windows_path("c:/work/data/file.json")
    assert p1 == p2


def test_windows_path_base_dir_containment() -> None:
    assert windows_path_join_safe(r"C:\work", r"sub\..\notes.txt") == "c:/work/notes.txt"
    # /work2 must never be treated as inside /work
    with pytest.raises(CanonicalizationError):
        canonicalize_windows_path(r"C:\work2\secret.txt", base_dir=r"C:\work")

    # Traversal escaping base_dir must fail closed
    with pytest.raises(CanonicalizationError):
        windows_path_join_safe(r"C:\work", r"..\Windows\win.ini")


@pytest.mark.parametrize(
    "bad_path",
    [
        "",
        "   ",
        "C:relative.txt",
        r"\root_relative\file.txt",
        r"C:\work\file.txt:ads_stream",
        r"C:\work\CON",
        r"C:\work\nul.log",
        r"C:\work\COM1.txt",
        r"\\.\PhysicalDrive0",
        r"\\?\C:\work\file.txt",
        r"\\server\share\file.txt",
        "C:\\work\\trailing_dot.",
        "C:\\work\\trailing_space ",
        "C:\\work\\bad\x00.txt",
        r"C:\work\..\..",
        r"C:\work\*.txt",
    ],
)
def test_dangerous_windows_paths_rejected(bad_path: str) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_windows_path(bad_path)


def test_redteam_windows_paths_corpus() -> None:
    corpus_file = REPO_ROOT / "corpus" / "redteam" / "windows_paths.jsonl"
    raw_lines = corpus_file.read_text(encoding="utf-8").splitlines()
    lines = [json.loads(line) for line in raw_lines if line.strip()]
    assert len(lines) >= 10
    for entry in lines:
        raw = entry["raw_path"]
        if entry["expect"] == "reject":
            with pytest.raises(CanonicalizationError):
                canonicalize_windows_path(raw)
        elif entry["expect"] == "reject_or_escape":
            with pytest.raises(CanonicalizationError):
                canonicalize_windows_path(raw, base_dir=r"C:\work")


def test_segment_aware_glob_matching() -> None:
    assert match_resource_pattern("path:C:/work/**", r"path:C:\work\a.txt")
    assert match_resource_pattern("path:C:/work/**", r"path:C:\work\sub\a.txt")
    assert not match_resource_pattern("path:C:/work/**", r"path:C:\work2\a.txt")
    assert match_resource_pattern("path:C:/work/*", r"path:C:\work\a.txt")
    assert not match_resource_pattern("path:C:/work/*", r"path:C:\work\sub\a.txt")


def test_json_canonicalization_deterministic() -> None:
    a = {"b": 1, "a": [2, {"y": "z", "x": True}]}
    b = {"a": [2, {"x": True, "y": "z"}], "b": 1}
    assert canonicalize_json(a) == canonicalize_json(b)
    assert hash_canonical(a) == hash_canonical(b)

    with pytest.raises(CanonicalizationError):
        canonicalize_json({"bad": float("nan")})


def test_canonical_json_spec_test_vectors() -> None:
    vectors_path = REPO_ROOT / "spec" / "canonical_test_vectors.json"
    assert vectors_path.exists(), f"Missing spec vectors file: {vectors_path}"
    raw = json.loads(vectors_path.read_text(encoding="utf-8"))
    vectors = raw.get("vectors", [])
    assert len(vectors) >= 8

    for v in vectors:
        input_data = v["input"]
        expected_json = v["canonical_json"]
        expected_hash = f"sha256:{v['sha256']}"

        # 1. Exact deterministic JSON string serialization
        actual_json = canonicalize_json(input_data)
        assert actual_json == expected_json, f"Mismatch in vector {v['name']}"

        # 2. Exact SHA-256 canonical hash
        actual_hash = hash_canonical(input_data)
        assert actual_hash == expected_hash, f"Hash mismatch in vector {v['name']}"

        # 3. Idempotence under parse-reserialize
        reserialized = canonicalize_json(json.loads(actual_json))
        assert reserialized == expected_json, f"Idempotence failure in vector {v['name']}"
