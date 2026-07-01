"""Shared instrumentation state — the active HookRuntime.

Patched call sites (module-level hooks, builtins patches) can't hold instance
references, so the manager publishes the active runtime here on install and
clears it on uninstall. One active runtime per process (matching the
one-global-config model of the existing SDKs).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..hooks.preflight import HookRuntime

__all__ = ["set_hook_runtime", "get_hook_runtime"]

_hook_runtime: HookRuntime | None = None


def set_hook_runtime(runtime: HookRuntime | None) -> None:
    global _hook_runtime
    _hook_runtime = runtime


def get_hook_runtime() -> HookRuntime | None:
    return _hook_runtime
