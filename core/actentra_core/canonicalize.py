"""Deterministic canonicalization and hashing for Actentra.

Handles Unicode normalization, strict Windows path canonicalization,
deterministic JSON serialization, and segment-aware resource glob matching.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import unicodedata
from typing import Any

_WINDOWS_RESERVED_NAMES: frozenset[str] = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)

_INVALID_WIN_CHARS: frozenset[str] = frozenset('<>"|?*')
_GLOB_SEGMENT_RE_CACHE: dict[str, re.Pattern[str]] = {}


class CanonicalizationError(ValueError):
    """Raised when an input cannot be safely and unambiguously canonicalized."""


def canonicalize_unicode(text: str, *, allow_newlines: bool = False) -> str:
    """Normalize text to Unicode NFC and reject NUL or dangerous control characters."""
    if "\x00" in text:
        raise CanonicalizationError("NUL byte is not permitted")
    normalized = unicodedata.normalize("NFC", text)
    for ch in normalized:
        code = ord(ch)
        if code < 0x20:
            if allow_newlines and ch in ("\n", "\r", "\t"):
                continue
            raise CanonicalizationError(f"Control character U+{code:04X} is not permitted")
        if code == 0x7F:
            raise CanonicalizationError("DEL control character U+007F is not permitted")
    return normalized


def _validate_windows_segment(segment: str) -> None:
    if not segment:
        return
    if segment in (".", ".."):
        return
    if ":" in segment:
        raise CanonicalizationError(f"Alternate data stream or colon in segment: {segment!r}")
    if any(ch in _INVALID_WIN_CHARS for ch in segment):
        raise CanonicalizationError(f"Invalid filename character in segment: {segment!r}")
    if segment.endswith((".", " ")):
        raise CanonicalizationError(
            f"Trailing dot or space in Windows path segment is not permitted: {segment!r}"
        )
    stem = segment.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED_NAMES:
        raise CanonicalizationError(f"Reserved Windows device name is not permitted: {segment!r}")


def _resolve_segments(segments: list[str]) -> list[str]:
    stack: list[str] = []
    for seg in segments:
        if not seg or seg == ".":
            continue
        if seg == "..":
            if not stack:
                raise CanonicalizationError("Path traversal escapes root")
            stack.pop()
            continue
        stack.append(seg)
    return stack


def canonicalize_windows_path(
    raw_path: str,
    *,
    base_dir: str | None = None,
    allow_unc: bool = False,
    allow_relative: bool = False,
    resolve_fs: bool = False,
) -> str:
    """Canonicalize a Windows filesystem path into lowercase forward-slash form.

    Examples:
        ``C:\\Work\\Sub\\..\\file.txt`` -> ``c:/work/file.txt``

    Raises:
        CanonicalizationError: on NUL bytes, control chars, ADS, reserved device
            names, drive-relative paths, extended/device namespaces, trailing
            dots/spaces, root/base_dir traversal escapes, or disallowed UNC/relative paths.
    """
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise CanonicalizationError("Path must be a non-empty string")

    text = canonicalize_unicode(raw_path)
    if text != text.strip():
        raise CanonicalizationError("Leading or trailing whitespace in path is not permitted")
    win_slash = text.replace("/", "\\")

    # Reject extended-length and Win32 device namespaces (\\?\, \\.\, \??\).
    if win_slash.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        raise CanonicalizationError("Win32 device or extended-length namespaces are not permitted")

    canon_base: str | None = None
    if base_dir is not None:
        canon_base = canonicalize_windows_path(
            base_dir,
            base_dir=None,
            allow_unc=allow_unc,
            allow_relative=False,
            resolve_fs=resolve_fs,
        )

    # Reject UNC unless explicitly enabled.
    is_unc = win_slash.startswith("\\\\")
    if is_unc:
        if not allow_unc:
            raise CanonicalizationError("UNC paths are not permitted")
        parts = [p for p in win_slash[2:].split("\\") if p != ""]
        if len(parts) < 2:
            raise CanonicalizationError("Incomplete UNC path (requires server and share)")
        server, share, *rest = parts
        _validate_windows_segment(server)
        _validate_windows_segment(share)
        for seg in rest:
            _validate_windows_segment(seg)
        resolved = _resolve_segments(rest)
        result = f"//{server.lower()}/{share.lower()}"
        if resolved:
            result = f"{result}/{'/'.join(seg.lower() for seg in resolved)}"
        if canon_base is not None:
            _assert_within_base(result, canon_base)
        return result

    # Detect drive prefix (e.g. C:\...) vs drive-relative (C:foo.txt) vs root-relative (\foo).
    has_drive = (
        len(win_slash) >= 2
        and win_slash[0].isascii()
        and win_slash[0].isalpha()
        and win_slash[1] == ":"
    )
    if has_drive:
        if len(win_slash) == 2 or win_slash[2] != "\\":
            raise CanonicalizationError("Drive-relative paths (e.g. C:foo) are not permitted")
        drive = win_slash[0].lower()
        tail = win_slash[3:]
        raw_segments = [s for s in tail.split("\\") if s != ""]
        for seg in raw_segments:
            _validate_windows_segment(seg)
        resolved = _resolve_segments(raw_segments)
        result = f"{drive}:/{'/'.join(seg.lower() for seg in resolved)}"
    elif win_slash.startswith("\\"):
        raise CanonicalizationError("Root-relative paths without a drive letter are not permitted")
    else:
        raw_segments = [s for s in win_slash.split("\\") if s != ""]
        for seg in raw_segments:
            _validate_windows_segment(seg)
        if canon_base is not None:
            # Anchor relative path against canon_base.
            base_drive, base_tail = canon_base.split(":/", 1)
            base_segs = [s for s in base_tail.split("/") if s]
            combined = base_segs + raw_segments
            resolved = _resolve_segments(combined)
            result = f"{base_drive}:/{'/'.join(seg.lower() for seg in resolved)}"
        elif allow_relative:
            resolved = _resolve_segments(raw_segments)
            result = "/".join(seg.lower() for seg in resolved) if resolved else "."
        else:
            raise CanonicalizationError(
                "Relative paths are not permitted without base_dir or allow_relative=True"
            )

    if resolve_fs and result and len(result) >= 3 and result[1:3] == ":/":
        # Resolve symlinks/junctions/8.3 short names on disk when requested.
        real = os.path.realpath(result.replace("/", "\\"))
        if real.startswith(("\\\\?\\", "\\\\.\\")):
            real = real[4:]
        result = canonicalize_windows_path(
            real,
            base_dir=None,
            allow_unc=allow_unc,
            allow_relative=False,
            resolve_fs=False,
        )

    if canon_base is not None:
        _assert_within_base(result, canon_base)

    return result


def _assert_within_base(path: str, base: str) -> None:
    if path == base:
        return
    prefix = base if base.endswith("/") else f"{base}/"
    if not path.startswith(prefix):
        raise CanonicalizationError(
            f"Path {path!r} escapes allowed base directory {base!r}"
        )


def canonicalize_resource(resource: str) -> str:
    """Canonicalize a resource identifier such as ``path:C:\\work\\a.txt``."""
    if not isinstance(resource, str) or not resource.strip():
        raise CanonicalizationError("Resource must be a non-empty string")
    clean = canonicalize_unicode(resource)
    if clean.lower().startswith("path:"):
        raw_path = clean[5:]
        canon_path = canonicalize_windows_path(raw_path)
        return f"path:{canon_path}"
    return clean.strip()


def _validate_json_numbers(obj: Any) -> None:
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            raise CanonicalizationError("Non-finite floats (NaN/Infinity) are not permitted")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalizationError("JSON object keys must be strings")
            _validate_json_numbers(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _validate_json_numbers(item)


def canonicalize_json(obj: Any) -> str:
    """Serialize any JSON-compatible object into deterministic canonical JSON."""
    _validate_json_numbers(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def hash_canonical(obj: Any) -> str:
    """Return ``sha256:<hex>`` digest of the canonical JSON representation."""
    payload = canonicalize_json(obj).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return f"sha256:{digest}"


def _compile_segment_glob(segment: str) -> re.Pattern[str]:
    cached = _GLOB_SEGMENT_RE_CACHE.get(segment)
    if cached is not None:
        return cached
    parts: list[str] = ["^"]
    for ch in segment:
        if ch == "*":
            parts.append("[^/]*")
        elif ch == "?":
            parts.append("[^/]")
        else:
            parts.append(re.escape(ch))
    parts.append("$")
    compiled = re.compile("".join(parts))
    if len(_GLOB_SEGMENT_RE_CACHE) < 2048:
        _GLOB_SEGMENT_RE_CACHE[segment] = compiled
    return compiled


def _match_segments(pattern_segs: list[str], target_segs: list[str]) -> bool:
    p_len = len(pattern_segs)
    t_len = len(target_segs)
    # DP table over segments so ** matches 0 or more segments cleanly.
    dp: list[list[bool]] = [[False] * (t_len + 1) for _ in range(p_len + 1)]
    dp[0][0] = True
    for i in range(1, p_len + 1):
        if pattern_segs[i - 1] == "**":
            dp[i][0] = dp[i - 1][0]
    for i in range(1, p_len + 1):
        p_seg = pattern_segs[i - 1]
        for j in range(1, t_len + 1):
            if p_seg == "**":
                dp[i][j] = dp[i - 1][j] or dp[i][j - 1]
            else:
                if dp[i - 1][j - 1] and _compile_segment_glob(p_seg).match(target_segs[j - 1]):
                    dp[i][j] = True
    return dp[p_len][t_len]


def _normalize_path_pattern(raw_pattern: str) -> str:
    text = canonicalize_unicode(raw_pattern).strip().replace("\\", "/")
    if len(text) >= 2 and text[0].isascii() and text[0].isalpha() and text[1] == ":":
        if len(text) < 3 or text[2] != "/":
            raise CanonicalizationError(f"Invalid drive pattern: {raw_pattern!r}")
        drive = text[0].lower()
        rest = "/".join(seg.lower() for seg in text[3:].split("/") if seg)
        return f"{drive}:/{rest}"
    return text.lower()


def match_resource_pattern(pattern: str, resource: str) -> bool:
    """Match a canonicalized resource string against a policy resource pattern.

    Supports segment-aware ``**`` and single-segment ``*`` / ``?`` globs for
    ``path:`` resources and general resources.
    """
    pat = canonicalize_unicode(pattern).strip()
    res = canonicalize_unicode(resource).strip()

    if pat.lower().startswith("path:"):
        if not res.lower().startswith("path:"):
            return False
        pat_path = _normalize_path_pattern(pat[5:])
        res_path = canonicalize_windows_path(res[5:])
        pat_segs = [s for s in pat_path.split("/") if s]
        res_segs = [s for s in res_path.split("/") if s]
        return _match_segments(pat_segs, res_segs)

    # General resource glob (segment-aware on '/').
    if "**" in pat or "*" in pat or "?" in pat:
        pat_segs = [s for s in pat.split("/") if s]
        res_segs = [s for s in res.split("/") if s]
        return _match_segments(pat_segs, res_segs)

    return pat == res


def windows_path_join_safe(base_dir: str, untrusted_subpath: str) -> str:
    """Join ``base_dir`` and ``untrusted_subpath`` and guarantee containment."""
    return canonicalize_windows_path(untrusted_subpath, base_dir=base_dir)
