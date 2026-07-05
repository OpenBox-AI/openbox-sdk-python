"""File wrapper — governed open() with read/write/writelines counting.

Preflight runs BEFORE the file handle is created (a BLOCK means the file is
never opened). The returned handle is proxied to count bytes/lines; closing
emits ONE completed telemetry event with the totals.

Both ``builtins.open`` and ``io.open`` are patched: ``pathlib`` file helpers
(``Path.open``/``read_text``/``write_text``) call ``io.open`` DIRECTLY and
never touch ``builtins.open``, so patching only the builtin would leave every
pathlib file access ungoverned. In CPython the two names reference the SAME
object and a single logical open resolves through exactly ONE of them
(direct ``open()`` -> builtins, pathlib -> io), so wiring both to one wrapper
governs pathlib without any double wrapping or double evaluation.

Noise control: paths under the interpreter prefix / site-packages / caches
bypass governance entirely, and (like every hook) operations with no bound
ActivityContext are skipped by the hook runtime.
"""

from __future__ import annotations

import builtins
import io
import logging
import sys
import sysconfig
import threading
from typing import Any

from ..contracts.otel_spans import HookType
from ..otel.provider import get_tracer
from .shared import get_hook_runtime

logger = logging.getLogger(__name__)

__all__ = ["install_file_io", "uninstall_file_io", "GovernedFile"]

# The genuine opener (``builtins.open`` == ``io.open`` pre-patch) — used both
# to bypass governance and to create the handle after preflight. Non-None
# while instrumentation is installed (doubles as the idempotency guard).
_original_open: Any = None
# Whether we replaced ``io.open`` too, so uninstall restores exactly what we
# changed (skipped if a foreign wrapper already owned ``io.open`` at install).
_patched_io: bool = False

# Interpreter-owned trees (venv AND base install — they differ in venvs).
_IGNORED_PATH_PREFIXES = tuple(
    {
        sys.prefix,
        sys.exec_prefix,
        sys.base_prefix,
        sys.base_exec_prefix,
        sysconfig.get_paths().get("stdlib", sys.base_prefix),
        sysconfig.get_paths().get("platstdlib", sys.base_prefix),
        sysconfig.get_paths().get("purelib", sys.prefix),
        sysconfig.get_paths().get("platlib", sys.prefix),
    }
)


def _mode_operation(mode: str) -> str:
    if any(c in mode for c in ("w", "a", "x", "+")):
        return "write"
    return "read"


def _file_span_name(mode: str) -> str:
    return f"file.{_mode_operation(mode)}"


def _coerce_path(file: Any) -> str | None:
    """str path for str/bytes/os.PathLike; None for fds/unknowns (pass through)."""
    import os

    if isinstance(file, int):
        return None  # file descriptor
    try:
        path = os.fspath(file)
    except TypeError:
        return None
    return path.decode(errors="ignore") if isinstance(path, bytes) else path


# Re-entrancy guard: governance evaluation opens files itself (httpx/ssl,
# package-metadata scans). Governing those opens evaluates again and recurses
# until RecursionError — any open on a thread already inside file-governance
# work passes straight through.
_reentrancy = threading.local()


def _should_skip(path: str | None) -> bool:
    if path is None:
        return True
    if "__pycache__" in path:
        return True
    return path.startswith(_IGNORED_PATH_PREFIXES)


class GovernedFile:
    """Transparent file proxy counting reads/writes for completed telemetry."""

    def __init__(self, handle: Any, span: Any, path: str, mode: str, runtime: Any):
        object.__setattr__(self, "_handle", handle)
        object.__setattr__(self, "_span", span)
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_mode", mode)
        object.__setattr__(self, "_runtime", runtime)
        object.__setattr__(self, "_bytes_read", 0)
        object.__setattr__(self, "_bytes_written", 0)
        object.__setattr__(self, "_lines_count", 0)
        object.__setattr__(self, "_closed_reported", False)

    # ── counted operations ────────────────────────────────────────────────

    def read(self, *args, **kwargs):
        data = self._handle.read(*args, **kwargs)
        object.__setattr__(self, "_bytes_read", self._bytes_read + len(data))
        return data

    def write(self, data):
        written = self._handle.write(data)
        object.__setattr__(self, "_bytes_written", self._bytes_written + len(data))
        return written

    def writelines(self, lines):
        materialized = list(lines)
        result = self._handle.writelines(materialized)
        object.__setattr__(
            self, "_bytes_written", self._bytes_written + sum(len(line) for line in materialized)
        )
        object.__setattr__(self, "_lines_count", self._lines_count + len(materialized))
        return result

    def close(self):
        result = self._handle.close()
        self._report_completed()
        return result

    def _report_completed(self):
        if self._closed_reported:
            return
        object.__setattr__(self, "_closed_reported", True)
        _reentrancy.active = True
        try:
            self._span.end()
            self._runtime.completed(
                self._span,
                hook_type=HookType.FILE_OPERATION,
                fields={
                    "file_path": self._path,
                    "file_mode": self._mode,
                    "file_operation": _mode_operation(self._mode),
                    "bytes_read": self._bytes_read or None,
                    "bytes_written": self._bytes_written or None,
                    "lines_count": self._lines_count or None,
                },
            )
        except Exception:
            logger.debug("file completed telemetry failed", exc_info=True)
        finally:
            _reentrancy.active = False

    # ── passthrough ───────────────────────────────────────────────────────

    def __enter__(self):
        self._handle.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        result = self._handle.__exit__(exc_type, exc_value, traceback)
        self._report_completed()
        return result

    def __iter__(self):
        return iter(self._handle)

    def __getattr__(self, name):
        return getattr(self._handle, name)


def _governed_open(file, mode="r", *args, **kwargs):
    runtime = get_hook_runtime()
    path = _coerce_path(file)
    if runtime is None or getattr(_reentrancy, "active", False) or _should_skip(path):
        return _original_open(file, mode, *args, **kwargs)
    operation = _mode_operation(mode)
    span = get_tracer().start_span(_file_span_name(mode))
    span.set_attribute("file.path", path)
    span.set_attribute("file.mode", mode)
    span.set_attribute("file.operation", operation)
    _reentrancy.active = True
    try:
        # BLOCK/HALT raises here — the file handle is never created.
        runtime.preflight(
            span,
            hook_type=HookType.FILE_OPERATION,
            identifier=path,
            fields={
                "file_path": path,
                "file_mode": mode,
                "file_operation": operation,
            },
        )
    finally:
        _reentrancy.active = False
    handle = _original_open(file, mode, *args, **kwargs)
    return GovernedFile(handle, span, path, mode, runtime)


def install_file_io() -> bool:
    """Idempotent open() patch across builtins AND io (guard flag mirrors the
    Temporal SDK). Patching ``io.open`` is what brings ``pathlib`` file helpers
    under governance — they bypass ``builtins.open`` entirely."""
    global _original_open, _patched_io
    if _original_open is not None:
        return True
    _original_open = builtins.open
    builtins.open = _governed_open
    # pathlib routes through io.open. Only patch it if it is still the genuine
    # opener — never clobber a foreign wrapper another tool installed first
    # (that would also make it the wrapper we call as "_original_open").
    if io.open is _original_open:
        io.open = _governed_open
        _patched_io = True
    return True


def uninstall_file_io() -> None:
    """Restore both ``builtins.open`` and ``io.open`` to their originals."""
    global _original_open, _patched_io
    if _original_open is None:
        return
    builtins.open = _original_open
    if _patched_io:
        io.open = _original_open
        _patched_io = False
    _original_open = None
