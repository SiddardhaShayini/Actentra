"""Unit tests for POSIX path canonicalization and resource pattern matching."""

from __future__ import annotations

import os

import pytest

from actentra_core.canonicalize import (
    CanonicalizationError,
    canonicalize_windows_path,
    match_resource_pattern,
)


def test_posix_absolute_and_relative_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")

    assert (
        canonicalize_windows_path("/kaggle/working/Actentra/./drafts/../notes.txt")
        == "/kaggle/working/Actentra/notes.txt"
    )
    assert (
        canonicalize_windows_path("drafts/summary.txt", base_dir="/tmp/actentra-ws")
        == "/tmp/actentra-ws/drafts/summary.txt"
    )


def test_posix_rejects_escapes_unc_and_windows_drive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "posix")

    with pytest.raises(CanonicalizationError):
        canonicalize_windows_path("../outside.txt", base_dir="/tmp/actentra-ws")

    with pytest.raises(CanonicalizationError):
        canonicalize_windows_path("//server/share/file.txt")

    with pytest.raises(CanonicalizationError):
        canonicalize_windows_path("C:/work/file.txt")

    with pytest.raises(CanonicalizationError):
        canonicalize_windows_path("C:\\work\\file.txt")


def test_posix_resource_glob_preserves_case(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")

    assert match_resource_pattern(
        "path:/kaggle/working/Actentra/drafts/**",
        "path:/kaggle/working/Actentra/drafts/summary.txt",
    )
    assert not match_resource_pattern(
        "path:/kaggle/working/actentra/drafts/**",
        "path:/kaggle/working/Actentra/drafts/summary.txt",
    )
