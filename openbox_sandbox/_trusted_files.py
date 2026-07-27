"""Private secure-file and strict-JSON helpers for deployment configuration."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .errors import GovernedCommandDeploymentError

MAX_CONFIG_BYTES = 1024 * 1024


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GovernedCommandDeploymentError()
        result[key] = value
    return result


def reject_constant(_: str) -> None:
    raise GovernedCommandDeploymentError()


def _reject_symlink_components(path: Path) -> None:
    if not path.is_absolute():
        raise GovernedCommandDeploymentError()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            if stat.S_ISLNK(os.lstat(current).st_mode):
                raise GovernedCommandDeploymentError()
        except FileNotFoundError:
            if current == path:
                return
            raise GovernedCommandDeploymentError() from None
        except OSError:
            raise GovernedCommandDeploymentError() from None


def read_trusted_file(
    path: Path,
    *,
    maximum: int = MAX_CONFIG_BYTES,
    private: bool = False,
    read_data: bool = True,
) -> bytes:
    """Read one owner-controlled regular file through a verified descriptor."""
    if not isinstance(path, Path) or not path.is_absolute() or type(maximum) is not int:
        raise GovernedCommandDeploymentError()
    if not 1 <= maximum <= MAX_CONFIG_BYTES:
        raise GovernedCommandDeploymentError()
    _reject_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_size <= 0
            or metadata.st_size > maximum
            or (private and mode != 0o600)
            or (not private and mode & 0o022)
        ):
            raise GovernedCommandDeploymentError()
        if not read_data:
            return b""
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(chunks)
        if not body or len(body) != metadata.st_size or len(body) > maximum:
            raise GovernedCommandDeploymentError()
        return body
    except GovernedCommandDeploymentError:
        raise
    except (OSError, ValueError):
        raise GovernedCommandDeploymentError() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def parse_strict_json(body: bytes) -> dict[str, Any]:
    try:
        text = body.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=strict_object,
            parse_constant=reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        GovernedCommandDeploymentError,
        RecursionError,
    ):
        raise GovernedCommandDeploymentError() from None
    if not isinstance(value, dict):
        raise GovernedCommandDeploymentError()
    return value


def load_strict_json(path: Path) -> dict[str, Any]:
    return parse_strict_json(read_trusted_file(path))


def validate_trusted_file(path: Path, *, private: bool = False) -> None:
    read_trusted_file(path, private=private, read_data=False)


def validate_secure_directory(path: Path) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise GovernedCommandDeploymentError()
    _reject_symlink_components(path)
    try:
        metadata = os.lstat(path)
    except OSError:
        raise GovernedCommandDeploymentError() from None
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or mode != 0o700:
        raise GovernedCommandDeploymentError()
