"""SDK identifier formatting for OpenBox request headers.

The wire value is intentionally framework-branded rather than just a package
version so Core can distinguish SDK families:

    openbox-{engine}-{language}-v{version}
"""

from __future__ import annotations

import re

__all__ = [
    "DEFAULT_SDK_ENGINE",
    "DEFAULT_SDK_LANGUAGE",
    "SDK_IDENTIFIER_PATTERN",
    "build_sdk_identifier",
    "normalize_sdk_version",
]

DEFAULT_SDK_ENGINE = "base"
DEFAULT_SDK_LANGUAGE = "python"

_SLUG_PART_RE = re.compile(r"[^a-z0-9]+")
_VERSION_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$")

SDK_IDENTIFIER_PATTERN = re.compile(
    r"^openbox-[a-z0-9]+(?:-[a-z0-9]+)*-[a-z0-9]+-v"
    r"\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$"
)


def _slug(value: str, field_name: str) -> str:
    text = str(value).strip().lower()
    slug = _SLUG_PART_RE.sub("-", text).strip("-")
    if not slug:
        raise ValueError(f"{field_name} must not be empty")
    return slug


def normalize_sdk_version(version: str) -> str:
    """Return a canonical ``v``-prefixed SDK version component."""

    raw = str(version).strip()
    if raw.startswith(("v", "V")):
        raw = raw[1:]
    if not _VERSION_RE.fullmatch(raw):
        raise ValueError(
            "sdk version must look like '1.1' or '1.2.3' "
            f"(optionally with a suffix), got {version!r}"
        )
    return f"v{raw}"


def build_sdk_identifier(
    *,
    engine: str = DEFAULT_SDK_ENGINE,
    language: str = DEFAULT_SDK_LANGUAGE,
    version: str | None = None,
) -> str:
    """Build ``openbox-{engine}-{language}-v{version}``.

    ``version`` may be a raw package version (``1.2.3``), a ``v``-prefixed
    version (``v1.2.3``), or an already formatted OpenBox SDK identifier.
    """

    if version is None:
        from . import __version__ as version

    raw = str(version).strip()
    if raw.startswith("openbox-"):
        if not SDK_IDENTIFIER_PATTERN.fullmatch(raw):
            raise ValueError(f"invalid OpenBox SDK identifier: {version!r}")
        return raw

    return (
        f"openbox-{_slug(engine, 'sdk engine')}-"
        f"{_slug(language, 'sdk language')}-{normalize_sdk_version(raw)}"
    )
