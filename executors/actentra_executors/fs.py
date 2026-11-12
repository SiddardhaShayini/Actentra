"""Narrowly scoped local filesystem executor for Actentra (Phase 1 MVP).

Enforces Invariant I3 (executes only the canonicalized path evaluated by policy),
checks execution-time reparse-point/symlink containment within ``workspace_root``,
and honors ``ALLOW_WITH_CONSTRAINTS`` limits.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from actentra.boundary import Boundary
from actentra_core.canonicalize import CanonicalizationError, canonicalize_windows_path
from actentra_core.envelope import ActionEnvelope, ProvenanceItem
from actentra_core.verdict import Decision

_DEFAULT_MAX_READ_BYTES = 1_048_576  # 1 MiB
_DEFAULT_MAX_WRITE_BYTES = 1_048_576  # 1 MiB
_DEFAULT_MAX_LIST_ENTRIES = 500


class ExecutorError(RuntimeError):
    """Safe, non-leaky execution error raised by a connector."""


class LocalFSExecutor:
    """Scoped filesystem executor confined strictly to ``workspace_root``."""

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        default_max_read_bytes: int = _DEFAULT_MAX_READ_BYTES,
        default_max_write_bytes: int = _DEFAULT_MAX_WRITE_BYTES,
    ) -> None:
        raw_root = str(Path(workspace_root).resolve())
        self._workspace_root = canonicalize_windows_path(raw_root, resolve_fs=True)
        self._root_path = Path(self._workspace_root.replace("/", "\\"))
        self._default_max_read_bytes = default_max_read_bytes
        self._default_max_write_bytes = default_max_write_bytes

    @property
    def workspace_root(self) -> str:
        return self._workspace_root

    def _resolve_target(self, envelope: ActionEnvelope) -> Path:
        resource = envelope.action.resource
        if not resource.startswith("path:"):
            raise ExecutorError(f"Unsupported resource scheme for fs executor: {resource!r}")
        raw_path = resource[5:]
        try:
            canon = canonicalize_windows_path(
                raw_path,
                base_dir=self._workspace_root,
                resolve_fs=True,
            )
        except CanonicalizationError as exc:
            raise ExecutorError(f"Filesystem path blocked at execution boundary: {exc}") from exc

        target = Path(canon.replace("/", "\\"))
        # Also verify the immediate parent does not escape workspace via symlink/junction.
        if target != self._root_path:
            parent = target.parent
            if parent.exists():
                try:
                    canonicalize_windows_path(
                        str(parent),
                        base_dir=self._workspace_root,
                        resolve_fs=True,
                    )
                except CanonicalizationError as exc:
                    raise ExecutorError(
                        f"Parent directory escapes workspace boundary: {exc}"
                    ) from exc
        return target

    def _check_constraints(
        self,
        op: str,
        target: Path,
        decision: Decision,
    ) -> dict[str, Any]:
        constraints = dict(decision.constraints)
        if constraints.get("read_only") and op in ("write", "delete"):
            raise ExecutorError("Constraint violation: read_only mode prohibits mutation")

        allowed_ext = constraints.get("allowed_extensions")
        if isinstance(allowed_ext, list) and allowed_ext:
            normalized_exts = {str(ext).lower() for ext in allowed_ext}
            if target.suffix.lower() not in normalized_exts:
                exts_str = sorted(normalized_exts)
                raise ExecutorError(
                    f"Constraint violation: extension {target.suffix!r} not in {exts_str}"
                )
        return constraints

    def execute(self, envelope: ActionEnvelope, decision: Decision) -> Any:
        """Dispatch an authorized filesystem ActionEnvelope."""
        tool = envelope.action.tool
        target = self._resolve_target(envelope)
        params = envelope.action.params

        if tool == "fs.list":
            constraints = self._check_constraints("list", target, decision)
            if not target.exists():
                raise ExecutorError("Directory does not exist")
            if not target.is_dir():
                raise ExecutorError("Target path is not a directory")
            max_entries = int(constraints.get("max_entries", _DEFAULT_MAX_LIST_ENTRIES))
            entries: list[dict[str, str]] = []
            for entry in sorted(target.iterdir(), key=lambda p: p.name.lower()):
                if len(entries) >= max_entries:
                    break
                kind = "symlink" if entry.is_symlink() else ("dir" if entry.is_dir() else "file")
                entries.append({"name": entry.name, "type": kind})
            return entries

        if tool == "fs.read":
            constraints = self._check_constraints("read", target, decision)
            if not target.exists():
                raise ExecutorError("File does not exist")
            if target.is_symlink():
                # Re-verify symlink target strictly inside workspace_root.
                try:
                    canonicalize_windows_path(
                        os.path.realpath(target),
                        base_dir=self._workspace_root,
                        resolve_fs=True,
                    )
                except CanonicalizationError as exc:
                    raise ExecutorError(f"Symlink target escapes workspace: {exc}") from exc
            if not target.is_file():
                raise ExecutorError("Target path is not a regular file")
            max_bytes = int(constraints.get("max_read_bytes", self._default_max_read_bytes))
            size = target.stat().st_size
            if size > max_bytes:
                raise ExecutorError(
                    f"File size ({size} bytes) exceeds max_read_bytes ({max_bytes})"
                )
            return target.read_text(encoding="utf-8")

        if tool == "fs.write":
            constraints = self._check_constraints("write", target, decision)
            if target == self._root_path:
                raise ExecutorError("Cannot overwrite workspace root")
            if target.exists() and target.is_dir():
                raise ExecutorError("Cannot overwrite a directory")
            content = params.get("content")
            if not isinstance(content, str):
                raise ExecutorError("fs.write requires string 'content' parameter")
            encoded = content.encode("utf-8")
            max_bytes = int(constraints.get("max_write_bytes", self._default_max_write_bytes))
            if len(encoded) > max_bytes:
                raise ExecutorError(
                    f"Write payload ({len(encoded)} bytes) exceeds max_write_bytes ({max_bytes})"
                )
            if bool(params.get("create_parents", False)):
                target.parent.mkdir(parents=True, exist_ok=True)
            elif not target.parent.exists():
                raise ExecutorError("Parent directory does not exist")
            target.write_bytes(encoded)
            return {"written_bytes": len(encoded), "path": str(target)}

        if tool == "fs.delete":
            self._check_constraints("delete", target, decision)
            if target == self._root_path:
                raise ExecutorError("Cannot delete workspace root")
            if not target.exists():
                raise ExecutorError("File does not exist")
            if target.is_dir():
                raise ExecutorError("Directory deletion is not permitted by fs.delete")
            target.unlink()
            return {"deleted": True, "path": str(target)}

        raise ExecutorError(f"Unsupported tool for LocalFSExecutor: {tool!r}")


class ScopedFSTools:
    """Agent-facing filesystem tool functions bound through an Actentra Boundary (I1)."""

    def __init__(self, boundary: Boundary, executor: LocalFSExecutor) -> None:
        self._boundary = boundary
        self._executor = executor

    def _anchor_resource(self, path: str) -> str:
        """Anchor relative path against workspace_root without stripping anomalies."""
        if path.lower().startswith("path:"):
            return path
        p = path.replace("/", "\\")
        is_abs = len(p) >= 3 and p[0].isalpha() and p[1] == ":" and p[2] == "\\"
        is_drive_rel = len(p) >= 2 and p[0].isalpha() and p[1] == ":"
        is_special = p.startswith(("\\\\", "\\")) or is_drive_rel
        if is_abs or is_special:
            return f"path:{path}"
        return f"path:{self._executor.workspace_root}/{path}"

    def list_dir(
        self,
        path: str = ".",
        *,
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        user_goal: str | None = None,
    ) -> list[dict[str, str]]:
        result: list[dict[str, str]] = self._boundary.execute(
            tool="fs.list",
            verb="read",
            resource=self._anchor_resource(path),
            params={},
            fn=self._executor.execute,
            provenance=provenance,
            user_goal=user_goal,
        )
        return result

    def read_file(
        self,
        path: str,
        *,
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        user_goal: str | None = None,
    ) -> str:
        result: str = self._boundary.execute(
            tool="fs.read",
            verb="read",
            resource=self._anchor_resource(path),
            params={},
            fn=self._executor.execute,
            provenance=provenance,
            user_goal=user_goal,
        )
        return result

    def write_file(
        self,
        path: str,
        content: str,
        *,
        create_parents: bool = False,
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        user_goal: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = self._boundary.execute(
            tool="fs.write",
            verb="write",
            resource=self._anchor_resource(path),
            params={"content": content, "create_parents": create_parents},
            fn=self._executor.execute,
            provenance=provenance,
            user_goal=user_goal,
        )
        return result

    def delete_file(
        self,
        path: str,
        *,
        provenance: list[ProvenanceItem] | tuple[ProvenanceItem, ...] = (),
        user_goal: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = self._boundary.execute(
            tool="fs.delete",
            verb="delete",
            resource=self._anchor_resource(path),
            params={},
            fn=self._executor.execute,
            provenance=provenance,
            user_goal=user_goal,
        )
        return result
