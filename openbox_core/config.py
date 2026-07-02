"""OpenBoxConfig and nested config groups with layered env resolution.

Resolution order (highest wins):

1. explicit arguments
2. SDK-specific environment variables via ``env_prefix`` (e.g.
   ``OPENBOX_TEMPORAL_API_KEY`` for ``env_prefix="OPENBOX_TEMPORAL"``)
3. global ``OPENBOX_*`` environment variables
4. defaults
5. validation and normalization

This layered ``env_prefix``/``OPENBOX_*`` order is NEW versus the Temporal SDK
(which resolves everything at ``initialize()`` with no prefix). Temporal's
``GovernanceConfig`` fields map onto the nested groups here so the migration
can shim without losing options:

    skip_workflow_types / skip_activity_types / skip_signals /
    enforce_task_queues / send_start_event / send_activity_start_event  -> gate
    hitl_enabled / skip_hitl_activity_types / hitl_poll_interval_ms     -> hitl
    max_body_size                                                       -> privacy
    on_api_error / api_timeout                                          -> top level

No heavy imports; safe outside sandbox paths (env access happens only inside
``resolve()``, never at import time).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .errors import OpenBoxAuthError, OpenBoxConfigError, OpenBoxInsecureURLError

__all__ = [
    "GLOBAL_ENV_PREFIX",
    "HitlConfig",
    "TelemetryConfig",
    "InstrumentationConfig",
    "GateConfig",
    "PrivacyConfig",
    "OpenBoxConfig",
]

# API key format pattern (obx_live_... or obx_test_...)
API_KEY_PATTERN = re.compile(r"^obx_(live|test)_\w+$")

GLOBAL_ENV_PREFIX = "OPENBOX"

# Config fields resolvable from the environment (suffix -> coercion).
_ENV_FIELDS: dict[str, str] = {
    "api_url": "API_URL",
    "api_key": "API_KEY",
    "timeout_seconds": "TIMEOUT_SECONDS",
    "on_api_error": "ON_API_ERROR",
    "agent_name": "AGENT_NAME",
    "agent_did": "AGENT_DID",
    "agent_private_key": "AGENT_PRIVATE_KEY",
}


@dataclass
class HitlConfig:
    """Human-in-the-loop approval polling configuration."""

    enabled: bool = True
    poll_interval_ms: int = 5000
    max_wait_ms: int | None = None  # None = poll indefinitely (framework decides)
    # Activity types to skip approval checks for (avoids infinite loops).
    skip_activity_types: set[str] = field(default_factory=lambda: {"send_governance_event"})


@dataclass
class TelemetryConfig:
    """Telemetry emission toggles."""

    enabled: bool = True


@dataclass
class InstrumentationConfig:
    """Generic instrumentation install toggles."""

    enabled: bool = True
    http_enabled: bool = True
    db_enabled: bool = True
    # Safe to default-on: interpreter-owned paths bypass governance and a
    # re-entrancy guard passes through evaluation-time opens.
    file_enabled: bool = True
    function_enabled: bool = True
    llm_enabled: bool = False  # LLM instrumentation lands when scoped
    install_opentelemetry: bool = True
    preflight_enabled: bool = True
    completed_telemetry_enabled: bool = True


@dataclass
class GateConfig:
    """Event-level gate toggles (which lifecycle events are evaluated).

    NOTE: there is deliberately NO gate *mode* here — the gate is always
    strict for event/runtime contracts. These are emission toggles only.
    """

    skip_workflow_types: set[str] = field(default_factory=set)
    skip_signals: set[str] = field(default_factory=set)
    # By default skip the governance event activity itself to avoid loops.
    skip_activity_types: set[str] = field(default_factory=lambda: {"send_governance_event"})
    enforce_task_queues: set[str] | None = None  # None = all
    send_start_event: bool = True
    send_activity_start_event: bool = True


@dataclass
class PrivacyConfig:
    """Redaction/truncation applied BEFORE signing."""

    redact_keys: set[str] = field(default_factory=set)
    max_body_size: int = 65536  # chars; Temporal default


@dataclass
class OpenBoxConfig:
    """Resolved base-SDK configuration.

    Build via :meth:`resolve` for layered env resolution + validation, or
    construct directly in tests (no validation on direct construction).
    """

    api_url: str = ""
    api_key: str = ""
    timeout_seconds: float = 30.0
    on_api_error: str = "fail_open"  # "fail_open" | "fail_closed"
    on_fallback: Any = None  # reserved passthrough for fallback callbacks
    agent_name: str | None = None
    agent_did: str | None = None
    agent_private_key: str | None = field(default=None, repr=False)  # never in repr
    env_prefix: str | None = None
    hitl: HitlConfig = field(default_factory=HitlConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    instrumentation: InstrumentationConfig = field(default_factory=InstrumentationConfig)
    gate: GateConfig = field(default_factory=GateConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    metadata: dict[str, Any] = field(default_factory=dict)

    # ── Resolution ───────────────────────────────────────────────────────

    @classmethod
    def resolve(
        cls,
        *,
        env_prefix: str | None = None,
        environ: Mapping[str, str] | None = None,
        validate: bool = True,
        **explicit: Any,
    ) -> OpenBoxConfig:
        """Layered resolution: explicit > env_prefix > OPENBOX_* > defaults.

        Args:
            env_prefix: SDK-specific env namespace (e.g. ``OPENBOX_TEMPORAL``).
            environ: Environment mapping (defaults to ``os.environ``; injectable
                for tests).
            validate: Run validation/normalization (step 5). Disable only in
                tests that need partial configs.
            **explicit: Explicit values for any OpenBoxConfig field. ``None``
                means "not provided" and falls through to the next layer.
        """
        if environ is None:
            import os

            environ = os.environ

        unknown = set(explicit) - {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        if unknown:
            raise OpenBoxConfigError(f"Unknown config fields: {sorted(unknown)}")

        resolved: dict[str, Any] = {}
        for field_name, suffix in _ENV_FIELDS.items():
            value: Any = explicit.get(field_name)
            if value is None and env_prefix:
                value = environ.get(f"{env_prefix}_{suffix}")
            if value is None:
                value = environ.get(f"{GLOBAL_ENV_PREFIX}_{suffix}")
            if value is not None:
                resolved[field_name] = value

        # Non-env fields pass through explicitly only.
        for field_name, value in explicit.items():
            if field_name not in _ENV_FIELDS and value is not None:
                resolved[field_name] = value

        config = cls(env_prefix=env_prefix, **resolved)
        return config.normalized() if validate else config

    def normalized(self) -> OpenBoxConfig:
        """Validate + normalize in place (step 5). Returns self for chaining."""
        if not self.api_url:
            raise OpenBoxConfigError("api_url is required")
        if not self.api_key:
            raise OpenBoxConfigError("api_key is required")

        self.api_url = str(self.api_url).rstrip("/")
        _validate_url_security(self.api_url)

        if not API_KEY_PATTERN.match(self.api_key):
            raise OpenBoxAuthError(
                f"Invalid API key format. Expected 'obx_live_*' or 'obx_test_*', "
                f"got: '{self.api_key[:15]}...' (showing first 15 chars)"
            )

        try:
            self.timeout_seconds = float(self.timeout_seconds)
        except (TypeError, ValueError):
            raise OpenBoxConfigError(
                f"timeout_seconds must be numeric, got {self.timeout_seconds!r}"
            ) from None

        if self.on_api_error not in ("fail_open", "fail_closed"):
            raise OpenBoxConfigError(
                f"on_api_error must be 'fail_open' or 'fail_closed', got {self.on_api_error!r}"
            )

        # DID + private key: both-or-neither; format-validate the DID eagerly.
        if bool(self.agent_did) != bool(self.agent_private_key):
            raise OpenBoxConfigError(
                "agent_did and agent_private_key must be provided together "
                "(got only one). Provide both to enable signed requests, or neither."
            )
        if self.agent_did:
            from .identity import validate_agent_did

            validate_agent_did(self.agent_did)
        return self

    def load_identity(self) -> Any:
        """Load an :class:`~openbox_core.identity.AgentIdentity` (or None).

        Decodes + loads the Ed25519 seed exactly once; callers keep the
        returned identity and never re-touch the raw key string.
        """
        if not (self.agent_did and self.agent_private_key):
            return None
        from .identity import AgentIdentity

        return AgentIdentity.from_private_key(self.agent_did, self.agent_private_key)


def _validate_url_security(api_url: str) -> None:
    """HTTPS required for non-localhost URLs (protects API keys in transit)."""
    from urllib.parse import urlparse

    parsed = urlparse(api_url)
    is_localhost = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme == "http" and not is_localhost:
        raise OpenBoxInsecureURLError(
            f"Insecure HTTP URL detected: {api_url}. "
            "Use HTTPS for non-localhost URLs to protect API keys in transit."
        )
