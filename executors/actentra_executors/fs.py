"""Narrowly scoped local filesystem executor for Actentra (Phase 1 MVP).

Enforces Invariant I3 (executes only the canonicalized path evaluated by policy),
checks execution-time reparse-point/symlink containment within ``workspace_root``,
and honors ``ALLOW_WITH_CONSTRAINTS`` limits.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import secrets
import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from actentra.boundary import Boundary
from actentra_core.canonicalize import CanonicalizationError, canonicalize_windows_path
from actentra_core.envelope import ActionEnvelope, ProvenanceItem
from actentra_core.verdict import Decision

_DEFAULT_MAX_READ_BYTES = 1_048_576  # 1 MiB
_DEFAULT_MAX_WRITE_BYTES = 1_048_576  # 1 MiB
_DEFAULT_MAX_LIST_ENTRIES = 500

# Win32 constants for handle-based confinement
_WIN_GENERIC_READ = 0x80000000
_WIN_DELETE = 0x00010000
_WIN_FILE_SHARE_READ = 0x00000001
_WIN_FILE_SHARE_WRITE = 0x00000002
_WIN_FILE_SHARE_DELETE = 0x00000004
_WIN_OPEN_EXISTING = 3
_WIN_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WIN_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WIN_FILE_ATTRIBUTE_DIRECTORY = 0x10
_WIN_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_WIN_FILE_DISPOSITION_INFO = 4
_WIN_ERROR_FILE_NOT_FOUND = 2
_WIN_ERROR_PATH_NOT_FOUND = 3
_WIN_ERROR_ALREADY_EXISTS = 183


if sys.platform == "win32":
    from ctypes import wintypes

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    _kernel32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, wintypes.LPVOID]
    _kernel32.CreateDirectoryW.restype = wintypes.BOOL
    _kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.INT,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
else:
    _kernel32 = None
    _INVALID_HANDLE_VALUE = -1


def _get_handle_real_path(handle: int) -> str | None:
    """Retrieve the canonical real path of an open Win32 handle."""
    if sys.platform != "win32" or _kernel32 is None:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        res = _kernel32.GetFinalPathNameByHandleW(
            ctypes.c_void_p(handle), buf, len(buf), 0
        )
        if res == 0:
            return None
        path_str = str(buf.value)
        if path_str.startswith("\\\\?\\UNC\\"):
            return "\\\\" + path_str[8:]
        if path_str.startswith("\\\\?\\"):
            return path_str[4:]
        return path_str
    except (OSError, AttributeError, RuntimeError):
        return None


def _get_fd_real_path(fd: int) -> str | None:
    """Retrieve the canonical real path of an open file descriptor across platforms."""
    try:
        if sys.platform == "win32":
            import msvcrt

            handle = msvcrt.get_osfhandle(fd)
            return _get_handle_real_path(handle)
        proc_fd = f"/proc/self/fd/{fd}"
        if os.path.exists(proc_fd):
            return os.path.realpath(proc_fd)
    except (OSError, AttributeError, RuntimeError):
        return None
    return None


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
        self._root_path = Path(
            self._workspace_root.replace("/", "\\") if os.name == "nt" else self._workspace_root
        )
        self._default_max_read_bytes = default_max_read_bytes
        self._default_max_write_bytes = default_max_write_bytes

    @property
    def workspace_root(self) -> str:
        return self._workspace_root

    def _verify_containment(self, path: Path | str) -> None:
        """Verify that a path or directory strictly resides within workspace_root."""
        try:
            canonicalize_windows_path(
                str(path),
                base_dir=self._workspace_root,
                resolve_fs=True,
            )
        except CanonicalizationError as exc:
            raise ExecutorError(f"Filesystem path escapes workspace boundary: {exc}") from exc

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

        target = Path(canon.replace("/", "\\") if os.name == "nt" else canon)
        # Verify containment of all existing ancestor directories down to target.
        curr = target if target.exists() else target.parent
        while curr != self._root_path and curr.parent != curr:
            if curr.exists():
                self._verify_containment(curr)
            curr = curr.parent
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

    def _relative_segments(self, path: Path) -> list[str]:
        """Return relative path segments from workspace_root to path."""
        try:
            rel = path.relative_to(self._root_path)
        except ValueError as exc:
            raise ExecutorError(
                f"Filesystem path escapes workspace boundary: {exc}"
            ) from exc
        return [p for p in rel.parts if p and p != "."]

    # --- Win32 Handle-Based Race-Resistant Confinement ---

    def _win_open_dir_handle(
        self,
        path: str,
        *,
        lock_delete: bool = True,
    ) -> tuple[int, str, tuple[int, int, int]]:
        assert _kernel32 is not None
        share = _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE
        if not lock_delete:
            share |= _WIN_FILE_SHARE_DELETE
        handle = _kernel32.CreateFileW(
            path,
            _WIN_GENERIC_READ,
            share,
            None,
            _WIN_OPEN_EXISTING,
            _WIN_FILE_FLAG_BACKUP_SEMANTICS | _WIN_FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            if err in (_WIN_ERROR_FILE_NOT_FOUND, _WIN_ERROR_PATH_NOT_FOUND):
                raise FileNotFoundError(f"Directory does not exist: {path}")
            raise ExecutorError(
                f"Cannot securely open directory handle (winerror={err})"
            )
        try:
            info = _BY_HANDLE_FILE_INFORMATION()
            if not _kernel32.GetFileInformationByHandle(
                ctypes.c_void_p(handle), ctypes.byref(info)
            ):
                raise ExecutorError("Failed to query directory handle information")
            if info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT:
                raise ExecutorError(
                    "Filesystem path escapes workspace boundary: "
                    "reparse point or junction is not permitted"
                )
            if not (info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_DIRECTORY):
                raise ExecutorError("Target path is not a directory")
            final_path = _get_handle_real_path(handle)
            if not final_path:
                raise ExecutorError("Failed to resolve directory handle path")
            self._verify_containment(final_path)
            file_id = (
                int(info.dwVolumeSerialNumber),
                int(info.nFileIndexHigh),
                int(info.nFileIndexLow),
            )
            return int(handle), final_path, file_id
        except Exception:
            _kernel32.CloseHandle(ctypes.c_void_p(handle))
            raise

    def _win_verify_dir_handle(
        self,
        handle: int,
        expected_id: tuple[int, int, int],
    ) -> str:
        assert _kernel32 is not None
        info = _BY_HANDLE_FILE_INFORMATION()
        if not _kernel32.GetFileInformationByHandle(
            ctypes.c_void_p(handle), ctypes.byref(info)
        ):
            raise ExecutorError("Directory handle became invalid during operation")
        if info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT:
            raise ExecutorError(
                "Filesystem path escapes workspace boundary: reparse point detected"
            )
        if not (info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_DIRECTORY):
            raise ExecutorError("Directory handle no longer refers to a directory")
        actual_id = (
            int(info.dwVolumeSerialNumber),
            int(info.nFileIndexHigh),
            int(info.nFileIndexLow),
        )
        if actual_id != expected_id:
            raise ExecutorError("Directory identity changed concurrently")
        final_path = _get_handle_real_path(handle)
        if not final_path:
            raise ExecutorError("Failed to resolve directory handle path")
        self._verify_containment(final_path)
        return final_path

    @contextlib.contextmanager
    def _win_lock_ancestors(
        self,
        dir_path: Path,
        *,
        create_parents: bool = False,
    ) -> Iterator[tuple[str, list[tuple[int, tuple[int, int, int]]]]]:
        """Walk and lock ancestors from workspace_root to dir_path without FILE_SHARE_DELETE."""
        assert _kernel32 is not None
        segments = self._relative_segments(dir_path)
        held: list[tuple[int, tuple[int, int, int]]] = []
        try:
            root_h, cur_final, root_id = self._win_open_dir_handle(
                str(self._root_path), lock_delete=True
            )
            held.append((root_h, root_id))
            for seg in segments:
                next_path = f"{cur_final}\\{seg}"
                if create_parents and not os.path.exists(next_path):
                    ok = _kernel32.CreateDirectoryW(next_path, None)
                    if not ok:
                        err = ctypes.get_last_error()
                        if err != _WIN_ERROR_ALREADY_EXISTS:
                            raise ExecutorError(
                                f"Failed to create parent directory (winerror={err})"
                            )
                try:
                    h, next_final, fid = self._win_open_dir_handle(
                        next_path, lock_delete=True
                    )
                except FileNotFoundError as exc:
                    raise ExecutorError("Parent directory does not exist") from exc
                # Verify child's resolved parent matches cur_final
                if str(Path(next_final).parent).lower() != cur_final.lower():
                    _kernel32.CloseHandle(ctypes.c_void_p(h))
                    raise ExecutorError(
                        "Filesystem path escapes workspace boundary: parent mismatch"
                    )
                held.append((h, fid))
                cur_final = next_final
            yield cur_final, held
        finally:
            for h, _fid in reversed(held):
                with contextlib.suppress(Exception):
                    _kernel32.CloseHandle(ctypes.c_void_p(h))

    def _win_open_leaf_fd(self, leaf_path: str) -> int:
        """Open a leaf regular file on Windows rejecting reparse points and directories."""
        assert _kernel32 is not None
        import msvcrt

        handle = _kernel32.CreateFileW(
            leaf_path,
            _WIN_GENERIC_READ,
            _WIN_FILE_SHARE_READ,
            None,
            _WIN_OPEN_EXISTING,
            _WIN_FILE_FLAG_BACKUP_SEMANTICS | _WIN_FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            if err in (_WIN_ERROR_FILE_NOT_FOUND, _WIN_ERROR_PATH_NOT_FOUND):
                raise ExecutorError("File does not exist")
            raise ExecutorError(f"Cannot open file (winerror={err})")
        try:
            info = _BY_HANDLE_FILE_INFORMATION()
            if not _kernel32.GetFileInformationByHandle(
                ctypes.c_void_p(handle), ctypes.byref(info)
            ):
                raise ExecutorError("Failed to inspect opened file handle")
            if info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT:
                raise ExecutorError(
                    "Filesystem path escapes workspace boundary: "
                    "Symlink or reparse point is not permitted"
                )
            if info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_DIRECTORY:
                raise ExecutorError("Target path is not a regular file")
            return msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
        except Exception:
            _kernel32.CloseHandle(ctypes.c_void_p(handle))
            raise

    def _win_check_leaf_writable(self, leaf_path: str) -> None:
        """If leaf exists on Windows, verify via handle that it is not a dir or reparse point."""
        assert _kernel32 is not None
        handle = _kernel32.CreateFileW(
            leaf_path,
            _WIN_GENERIC_READ,
            _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE,
            None,
            _WIN_OPEN_EXISTING,
            _WIN_FILE_FLAG_BACKUP_SEMANTICS | _WIN_FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            if err in (_WIN_ERROR_FILE_NOT_FOUND, _WIN_ERROR_PATH_NOT_FOUND):
                return
            raise ExecutorError(f"Cannot inspect target path (winerror={err})")
        try:
            info = _BY_HANDLE_FILE_INFORMATION()
            if not _kernel32.GetFileInformationByHandle(
                ctypes.c_void_p(handle), ctypes.byref(info)
            ):
                raise ExecutorError("Failed to inspect target file handle")
            if info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT:
                raise ExecutorError("Cannot overwrite symlink")
            if info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_DIRECTORY:
                raise ExecutorError("Cannot overwrite a directory")
        finally:
            _kernel32.CloseHandle(ctypes.c_void_p(handle))

    def _win_delete_leaf_handle(self, leaf_path: str) -> None:
        """Delete a file on Windows using SetFileInformationByHandle on a verified handle."""
        assert _kernel32 is not None
        handle = _kernel32.CreateFileW(
            leaf_path,
            _WIN_DELETE | _WIN_GENERIC_READ,
            _WIN_FILE_SHARE_READ | _WIN_FILE_SHARE_WRITE | _WIN_FILE_SHARE_DELETE,
            None,
            _WIN_OPEN_EXISTING,
            _WIN_FILE_FLAG_BACKUP_SEMANTICS | _WIN_FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            if err in (_WIN_ERROR_FILE_NOT_FOUND, _WIN_ERROR_PATH_NOT_FOUND):
                raise ExecutorError("File does not exist")
            raise ExecutorError(f"Cannot open target for deletion (winerror={err})")
        try:
            info = _BY_HANDLE_FILE_INFORMATION()
            if not _kernel32.GetFileInformationByHandle(
                ctypes.c_void_p(handle), ctypes.byref(info)
            ):
                raise ExecutorError("Failed to inspect target handle for deletion")
            if info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT:
                raise ExecutorError(
                    "Filesystem path escapes workspace boundary: "
                    "reparse point deletion is not permitted"
                )
            if info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_DIRECTORY:
                raise ExecutorError("Directory deletion is not permitted by fs.delete")
            final_path = _get_handle_real_path(handle)
            if final_path:
                self._verify_containment(final_path)
            dispose = ctypes.c_bool(True)
            ok = _kernel32.SetFileInformationByHandle(
                ctypes.c_void_p(handle),
                _WIN_FILE_DISPOSITION_INFO,
                ctypes.byref(dispose),
                ctypes.sizeof(dispose),
            )
            if not ok:
                err = ctypes.get_last_error()
                raise ExecutorError(f"Failed to delete file handle (winerror={err})")
        finally:
            _kernel32.CloseHandle(ctypes.c_void_p(handle))

    # --- POSIX Descriptor-Relative (dir_fd) Confinement ---

    @contextlib.contextmanager
    def _posix_open_ancestors(
        self,
        dir_path: Path,
        *,
        create_parents: bool = False,
    ) -> Iterator[int]:
        """Walk workspace_root -> dir_path using openat + O_NOFOLLOW + O_DIRECTORY."""
        dir_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        cur_fd = os.open(str(self._root_path), dir_flags)
        try:
            root_real = _get_fd_real_path(cur_fd)
            if root_real is not None:
                self._verify_containment(root_real)
            for seg in self._relative_segments(dir_path):
                try:
                    next_fd = os.open(seg, dir_flags, dir_fd=cur_fd)
                except FileNotFoundError as exc:
                    if not create_parents:
                        raise ExecutorError("Parent directory does not exist") from exc
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(seg, 0o755, dir_fd=cur_fd)
                    next_fd = os.open(seg, dir_flags, dir_fd=cur_fd)
                except OSError as exc:
                    raise ExecutorError(
                        f"Filesystem path escapes workspace boundary: {exc}"
                    ) from exc
                os.close(cur_fd)
                cur_fd = next_fd
                cur_real = _get_fd_real_path(cur_fd)
                if cur_real is not None:
                    self._verify_containment(cur_real)
            yield cur_fd
        finally:
            with contextlib.suppress(OSError):
                os.close(cur_fd)

    def execute(self, envelope: ActionEnvelope, decision: Decision) -> Any:
        """Dispatch an authorized filesystem ActionEnvelope."""
        tool = envelope.action.tool
        target = self._resolve_target(envelope)
        params = envelope.action.params

        if tool == "fs.list":
            constraints = self._check_constraints("list", target, decision)
            max_entries = int(constraints.get("max_entries", _DEFAULT_MAX_LIST_ENTRIES))
            entries: list[dict[str, str]] = []

            if sys.platform == "win32":
                try:
                    with self._win_lock_ancestors(target, create_parents=False) as (
                        dir_final,
                        _held,
                    ):
                        dir_path = Path(dir_final)
                        for entry in sorted(dir_path.iterdir(), key=lambda p: p.name.lower()):
                            if len(entries) >= max_entries:
                                break
                            kind = (
                                "symlink"
                                if entry.is_symlink()
                                else ("dir" if entry.is_dir() else "file")
                            )
                            entries.append({"name": entry.name, "type": kind})
                except ExecutorError as exc:
                    if "does not exist" in str(exc).lower():
                        raise ExecutorError("Directory does not exist") from exc
                    raise
                return entries

            with self._posix_open_ancestors(target, create_parents=False) as dir_fd:
                for name in sorted(os.listdir(dir_fd), key=str.lower):
                    if len(entries) >= max_entries:
                        break
                    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                    kind = (
                        "symlink"
                        if stat.S_ISLNK(st.st_mode)
                        else ("dir" if stat.S_ISDIR(st.st_mode) else "file")
                    )
                    entries.append({"name": name, "type": kind})
                return entries

        if tool == "fs.read":
            constraints = self._check_constraints("read", target, decision)
            max_bytes = int(constraints.get("max_read_bytes", self._default_max_read_bytes))
            if target == self._root_path:
                raise ExecutorError("Target path is not a regular file")

            if sys.platform == "win32":
                with self._win_lock_ancestors(target.parent, create_parents=False) as (
                    parent_final,
                    _held,
                ):
                    leaf_path = f"{parent_final}\\{target.name}"
                    fd = self._win_open_leaf_fd(leaf_path)
                    try:
                        return self._read_verified_fd(fd, max_bytes)
                    finally:
                        os.close(fd)
            else:
                with self._posix_open_ancestors(target.parent, create_parents=False) as p_fd:
                    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                    try:
                        fd = os.open(target.name, flags, dir_fd=p_fd)
                    except FileNotFoundError as exc:
                        raise ExecutorError("File does not exist") from exc
                    except OSError as exc:
                        raise ExecutorError(
                            f"Filesystem path escapes workspace boundary: {exc}"
                        ) from exc
                    try:
                        return self._read_verified_fd(fd, max_bytes)
                    finally:
                        os.close(fd)

        if tool == "fs.write":
            constraints = self._check_constraints("write", target, decision)
            if target == self._root_path:
                raise ExecutorError("Cannot overwrite workspace root")
            if target.is_symlink():
                raise ExecutorError("Cannot overwrite symlink")

            content = params.get("content")
            if not isinstance(content, str):
                raise ExecutorError("fs.write requires string 'content' parameter")
            encoded = content.encode("utf-8")
            max_bytes = int(constraints.get("max_write_bytes", self._default_max_write_bytes))
            if len(encoded) > max_bytes:
                raise ExecutorError(
                    f"Write payload ({len(encoded)} bytes) exceeds max_write_bytes ({max_bytes})"
                )

            create_parents = bool(params.get("create_parents", False))
            tmp_name = f".actentra_tmp_{secrets.token_hex(12)}"

            if sys.platform == "win32":
                with self._win_lock_ancestors(
                    target.parent, create_parents=create_parents
                ) as (parent_final, held):
                    leaf_path = f"{parent_final}\\{target.name}"
                    self._win_check_leaf_writable(leaf_path)
                    temp_path = f"{parent_final}\\{tmp_name}"
                    flags = (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_BINARY", 0)
                    )
                    temp_fd = os.open(temp_path, flags, 0o600)
                    try:
                        temp_real = _get_fd_real_path(temp_fd)
                        if temp_real is not None:
                            self._verify_containment(temp_real)
                        os.write(temp_fd, encoded)
                        os.fsync(temp_fd)
                        os.close(temp_fd)
                        temp_fd = -1

                        # Re-verify parent handle identity before atomic replace
                        parent_h, parent_id = held[-1]
                        verified_parent = self._win_verify_dir_handle(parent_h, parent_id)
                        try:
                            os.replace(
                                f"{verified_parent}\\{tmp_name}",
                                f"{verified_parent}\\{target.name}",
                            )
                        except OSError as exc:
                            raise ExecutorError(
                                f"Cannot atomically replace target (concurrent change): {exc}"
                            ) from exc
                        self._win_check_leaf_writable(f"{verified_parent}\\{target.name}")
                    finally:
                        if temp_fd != -1:
                            with contextlib.suppress(OSError):
                                os.close(temp_fd)
                        parent_h, parent_id = held[-1]
                        with contextlib.suppress(Exception):
                            verified_parent = self._win_verify_dir_handle(parent_h, parent_id)
                            stale_tmp = Path(f"{verified_parent}\\{tmp_name}")
                            if stale_tmp.exists() and not stale_tmp.is_symlink():
                                stale_tmp.unlink()
                    return {"written_bytes": len(encoded), "path": str(target)}
            else:
                with self._posix_open_ancestors(
                    target.parent, create_parents=create_parents
                ) as p_fd:
                    try:
                        st = os.stat(target.name, dir_fd=p_fd, follow_symlinks=False)
                        if stat.S_ISLNK(st.st_mode):
                            raise ExecutorError("Cannot overwrite symlink")
                        if stat.S_ISDIR(st.st_mode):
                            raise ExecutorError("Cannot overwrite a directory")
                    except FileNotFoundError:
                        pass

                    flags = (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_NOFOLLOW", 0)
                    )
                    temp_fd = os.open(tmp_name, flags, 0o600, dir_fd=p_fd)
                    try:
                        temp_real = _get_fd_real_path(temp_fd)
                        if temp_real is not None:
                            self._verify_containment(temp_real)
                        os.write(temp_fd, encoded)
                        os.fsync(temp_fd)
                        os.close(temp_fd)
                        temp_fd = -1
                        try:
                            os.replace(
                                tmp_name,
                                target.name,
                                src_dir_fd=p_fd,
                                dst_dir_fd=p_fd,
                            )
                        except OSError as exc:
                            raise ExecutorError(
                                f"Cannot atomically replace target (concurrent change): {exc}"
                            ) from exc
                    finally:
                        if temp_fd != -1:
                            with contextlib.suppress(OSError):
                                os.close(temp_fd)
                        with contextlib.suppress(OSError):
                            os.unlink(tmp_name, dir_fd=p_fd)
                    return {"written_bytes": len(encoded), "path": str(target)}

        if tool == "fs.delete":
            self._check_constraints("delete", target, decision)
            if target == self._root_path:
                raise ExecutorError("Cannot delete workspace root")

            if sys.platform == "win32":
                with self._win_lock_ancestors(target.parent, create_parents=False) as (
                    parent_final,
                    _held,
                ):
                    self._win_delete_leaf_handle(f"{parent_final}\\{target.name}")
                return {"deleted": True, "path": str(target)}
            else:
                with self._posix_open_ancestors(target.parent, create_parents=False) as p_fd:
                    try:
                        st = os.stat(target.name, dir_fd=p_fd, follow_symlinks=False)
                    except FileNotFoundError as exc:
                        raise ExecutorError("File does not exist") from exc
                    if stat.S_ISDIR(st.st_mode):
                        raise ExecutorError("Directory deletion is not permitted by fs.delete")
                    if stat.S_ISLNK(st.st_mode):
                        raise ExecutorError(
                            "Filesystem path escapes workspace boundary: "
                            "symlink deletion is not permitted"
                        )
                    os.unlink(target.name, dir_fd=p_fd)
                return {"deleted": True, "path": str(target)}

        raise ExecutorError(f"Unsupported tool for LocalFSExecutor: {tool!r}")

    def _read_verified_fd(self, fd: int, max_bytes: int) -> str:
        """Validate opened descriptor (regular file, size, containment) and read UTF-8."""
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ExecutorError("Target path is not a regular file")
        if st.st_size > max_bytes:
            raise ExecutorError(
                f"File size ({st.st_size} bytes) exceeds max_read_bytes ({max_bytes})"
            )

        fd_real = _get_fd_real_path(fd)
        if fd_real is not None:
            self._verify_containment(fd_real)

        raw = os.read(fd, max_bytes + 1)
        if len(raw) > max_bytes:
            raise ExecutorError(
                f"File size ({len(raw)} bytes) exceeds max_read_bytes ({max_bytes})"
            )
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ExecutorError(f"File content is not valid UTF-8: {exc}") from exc


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
