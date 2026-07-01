"""Byte/transform-only JSON serialization.

This module knows NOTHING about events or spans — evaluate-body assembly
(``span_count``, compat-noise removal) is owned by ``wire/evaluate_payload.py``.
It owns exactly:

- ``to_json_safe`` — dataclass/enum/datetime-tolerant JSON coercion
- ``serialize_body`` — the EXACT bytes that are signed and transmitted
- ``truncate_string`` / ``apply_redaction`` — pre-signing transforms
- ``rfc3339_now`` — wall-clock helper (this module is NOT sandbox-pure)

Wall-clock lives here (not in contracts) so pure modules stay deterministic.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any

__all__ = [
    "to_json_safe",
    "serialize_body",
    "truncate_string",
    "apply_redaction",
    "rfc3339_now",
    "REDACTED_PLACEHOLDER",
]

REDACTED_PLACEHOLDER = "[REDACTED]"


def rfc3339_now() -> str:
    """Current UTC time, RFC3339 with millisecond precision and trailing ``Z``.

    Event-payload timestamp format — distinct from the request-*signing*
    timestamp which keeps ``+00:00`` (see ``identity.py``).
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_json_safe(obj: Any, exclude_none: bool = True) -> Any:
    """Recursively coerce ``obj`` into JSON-serializable primitives.

    Handles dataclasses (as dicts), Enums (``.value``), datetimes (RFC3339),
    sets/tuples (lists), and dict keys via ``str()``. Unknown objects fall back
    to ``str(obj)`` — governance telemetry must never crash the host app over
    an exotic payload type.
    """
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, Enum):
        return to_json_safe(obj.value, exclude_none)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return to_json_safe(dataclasses.asdict(obj), exclude_none)
    if isinstance(obj, datetime):
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=UTC)
        return obj.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if isinstance(obj, dict):
        return {
            str(k): to_json_safe(v, exclude_none)
            for k, v in obj.items()
            if not (exclude_none and v is None)
        }
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_json_safe(v, exclude_none) for v in obj]
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return str(obj)


def serialize_body(payload: dict | None) -> bytes:
    """Serialize a payload to the EXACT bytes that will be transmitted.

    - ``None`` -> ``b""`` (body hash becomes the empty-body SHA-256).
    - Compact separators (no spaces) and a single serialization pass so the
      bytes we hash are identical to the bytes we send. Re-serializing with
      ``json=`` elsewhere would break Core's body-hash verification.
    """
    if payload is None:
        return b""
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def truncate_string(value: str, max_size: int | None) -> tuple[str, bool]:
    """Truncate ``value`` to ``max_size`` chars. Returns (value, truncated?).

    ``None``/non-positive ``max_size`` disables truncation. Applied BEFORE
    signing — the signed bytes are the truncated bytes.
    """
    if not max_size or max_size <= 0 or len(value) <= max_size:
        return value, False
    return value[:max_size], True


def apply_redaction(
    obj: Any,
    redact_keys: frozenset[str] | set[str],
    replacement: str = REDACTED_PLACEHOLDER,
) -> tuple[Any, list[str]]:
    """Replace values of case-insensitive key matches anywhere in ``obj``.

    Returns ``(redacted_copy, changed_paths)`` — the paths identify what
    changed so callers can attach diagnostics. Applied BEFORE signing.
    """
    if not redact_keys:
        return obj, []
    lowered = {k.lower() for k in redact_keys}
    changed: list[str] = []

    def _walk(node: Any, path: str) -> Any:
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                child_path = f"{path}.{k}" if path else str(k)
                if isinstance(k, str) and k.lower() in lowered:
                    out[k] = replacement
                    changed.append(child_path)
                else:
                    out[k] = _walk(v, child_path)
            return out
        if isinstance(node, (list, tuple)):
            return [_walk(v, f"{path}[{i}]") for i, v in enumerate(node)]
        return node

    return _walk(obj, ""), changed
