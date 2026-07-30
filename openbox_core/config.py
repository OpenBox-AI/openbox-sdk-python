"""OpenBoxConfig and nested config groups with layered env resolution.

Resolution order (highest wins):

1. explicit arguments
2. SDK-specific environment variables via ``env_prefix`` (e.g.
   ``OPENBOX_FRAMEWORK_API_KEY`` for ``env_prefix="OPENBOX_FRAMEWORK"``)
3. global ``OPENBOX_*`` environment variables
4. defaults
5. validation and normalization

Common framework configuration fields map onto the nested groups here:

    skip_workflow_types / skip_activity_types / skip_signals /
    enforce_task_queues / send_start_event / send_activity_start_event  -> gate
    hitl_enabled / skip_hitl_activity_types / hitl_poll_interval_ms     -> hitl
    max_body_size                                                       -> privacy
    on_api_error / api_timeout                                          -> top level

Identity verification (proposal §13.1) is tagged, not a single shape:
`agent_did` + `agent_private_key` (v1 OpenBox DID) and the Okta AI Agent
fields (`okta_agent_id`, `okta_agent_key_id`, `okta_agent_private_key`,
`okta_agent_algorithm`, `openbox_agent_id`, `organization_id`,
`deployment_id`, `agent_proof_audience` — v2) are mutually exclusive; neither
present infers `legacy_unsigned` (API-key-only). `identity_method` is an
explicit override that still requires the matching fields. See
`_resolve_identity_method()`.

No heavy imports; safe outside sandbox paths (env access happens only inside
``resolve()``, never at import time).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .errors import OpenBoxAuthError, OpenBoxConfigError, OpenBoxInsecureURLError
from .sdk_version import DEFAULT_SDK_ENGINE, DEFAULT_SDK_LANGUAGE

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
    # v2 (Okta AI Agent) tagged identity — proposal §13.1.
    "identity_method": "AGENT_IDENTITY_METHOD",
    "okta_agent_id": "OKTA_AGENT_ID",
    "okta_agent_key_id": "OKTA_AGENT_KEY_ID",
    "okta_agent_private_key": "OKTA_AGENT_PRIVATE_KEY",
    "okta_agent_algorithm": "OKTA_AGENT_ALGORITHM",
    "openbox_agent_id": "AGENT_ID",
    "organization_id": "ORGANIZATION_ID",
    "deployment_id": "DEPLOYMENT_ID",
    "agent_proof_audience": "AGENT_PROOF_AUDIENCE",
}

# The Okta-mode required fields (proposal §13.1 rule 4). Presence of any of
# these EXCEPT ``okta_agent_algorithm`` (which always carries the "RS256"
# default) signals okta_ai_agent intent for inference purposes.
_OKTA_IDENTITY_FIELDS: tuple[str, ...] = (
    "openbox_agent_id",
    "organization_id",
    "deployment_id",
    "okta_agent_id",
    "okta_agent_key_id",
    "okta_agent_algorithm",
    "agent_proof_audience",
    "okta_agent_private_key",
)
_OKTA_TRIGGER_FIELDS: tuple[str, ...] = tuple(
    f for f in _OKTA_IDENTITY_FIELDS if f != "okta_agent_algorithm"
)
_VALID_EXPLICIT_IDENTITY_METHODS = ("openbox_did", "okta_ai_agent")


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
    llm_enabled: bool = False  # Reserved; disabled until provider hooks are implemented.
    install_opentelemetry: bool = True
    preflight_enabled: bool = True
    completed_telemetry_enabled: bool = True


@dataclass
class GateConfig:
    """Event-level gate toggles (which lifecycle events are evaluated).

    Gate mode is not configurable: event/runtime contracts are always strict.
    These fields control only which events are emitted.
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
    max_body_size: int = 65536  # chars


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
    # v2 (Okta AI Agent) tagged identity — proposal §13.1. Mutually exclusive
    # with agent_did/agent_private_key; see `normalized()`.
    identity_method: str | None = None  # explicit override; resolved in-place by normalized()
    okta_agent_id: str | None = None  # external Okta AI Agent ID (iss/sub)
    okta_agent_key_id: str | None = None  # kid
    okta_agent_private_key: str | None = field(default=None, repr=False)  # PKCS8 PEM
    okta_agent_algorithm: str = "RS256"
    openbox_agent_id: str | None = None
    organization_id: str | None = None
    deployment_id: str | None = None
    agent_proof_audience: str | None = None
    sdk_version: str | None = None
    sdk_engine: str = DEFAULT_SDK_ENGINE
    sdk_language: str = DEFAULT_SDK_LANGUAGE
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
            env_prefix: SDK-specific env namespace (e.g. ``OPENBOX_FRAMEWORK``).
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

        self._resolve_identity_method()
        return self

    def _resolve_identity_method(self) -> None:
        """Resolve + validate the tagged identity method (proposal §13.1).

        Explicit `identity_method` wins; `agent_did` + `agent_private_key`
        infer `openbox_did`; Okta fields infer `okta_ai_agent`; neither
        infers `legacy_unsigned` (never explicitly selectable). DID and Okta
        fields are mutually exclusive. Mutates `self.identity_method` to the
        final resolved value (mirrors how `api_url` is normalized in place).
        """
        did_present = bool(self.agent_did) or bool(self.agent_private_key)
        okta_present = any(bool(getattr(self, f)) for f in _OKTA_TRIGGER_FIELDS)

        if did_present and okta_present:
            raise OpenBoxConfigError(
                "OpenBox DID fields (agent_did, agent_private_key) and Okta "
                f"AI Agent fields ({', '.join(_OKTA_TRIGGER_FIELDS)}) are "
                "mutually exclusive. Configure exactly one identity "
                "verification method."
            )

        if (
            self.identity_method is not None
            and self.identity_method not in _VALID_EXPLICIT_IDENTITY_METHODS
        ):
            raise OpenBoxConfigError(
                "identity_method must be 'openbox_did' or 'okta_ai_agent' "
                f"(got {self.identity_method!r}); 'legacy_unsigned' is "
                "inferred from absent identity configuration, never "
                "selected explicitly."
            )

        resolved_method = self.identity_method
        if resolved_method is None:
            if okta_present:
                resolved_method = "okta_ai_agent"
            elif did_present:
                resolved_method = "openbox_did"
            else:
                resolved_method = "legacy_unsigned"

        if resolved_method == "okta_ai_agent":
            missing = [f for f in _OKTA_IDENTITY_FIELDS if not getattr(self, f)]
            if missing:
                raise OpenBoxConfigError(
                    f"okta_ai_agent identity requires {', '.join(_OKTA_IDENTITY_FIELDS)}; "
                    f"missing: {', '.join(missing)}."
                )
            if self.okta_agent_algorithm != "RS256":
                raise OpenBoxConfigError(
                    f"Unsupported okta_agent_algorithm {self.okta_agent_algorithm!r}; "
                    "only 'RS256' is supported at launch."
                )
        elif resolved_method == "openbox_did":
            # both-or-neither; format-validate the DID eagerly.
            if not (self.agent_did and self.agent_private_key):
                raise OpenBoxConfigError(
                    "agent_did and agent_private_key must be provided together "
                    "to use openbox_did identity verification (got only one, "
                    "or neither with an explicit identity_method='openbox_did')."
                )
            from .identity import validate_agent_did

            validate_agent_did(self.agent_did)

        self.identity_method = resolved_method

    def load_identity(self) -> Any:
        """Load an :class:`~openbox_core.identity.AgentIdentity` (or None).

        Decodes + loads the Ed25519 seed exactly once; callers keep the
        returned identity and never re-touch the raw key string.

        Presence-based (like :meth:`load_okta_identity`), not
        `identity_method`-based, so it also works on a directly-constructed
        (unvalidated) config.
        """
        if not (self.agent_did and self.agent_private_key):
            return None
        from .identity import AgentIdentity

        return AgentIdentity.from_private_key(self.agent_did, self.agent_private_key)

    def load_okta_identity(self) -> Any:
        """Load an :class:`~openbox_core.identity_okta.OktaAgentIdentity` (or None).

        Presence-based, like :meth:`load_identity` — checks the resolved
        Okta fields directly rather than `identity_method`, so it works on a
        directly-constructed (unvalidated) config too. Decodes + loads the
        PKCS8 PEM key exactly once.
        """
        # Local variables (not repeated `self.x` attribute access) so mypy
        # narrows `str | None` -> `str` from the truthiness check below.
        okta_agent_id = self.okta_agent_id
        okta_agent_key_id = self.okta_agent_key_id
        okta_agent_private_key = self.okta_agent_private_key
        openbox_agent_id = self.openbox_agent_id
        organization_id = self.organization_id
        deployment_id = self.deployment_id
        agent_proof_audience = self.agent_proof_audience
        if not (
            okta_agent_id
            and okta_agent_key_id
            and okta_agent_private_key
            and openbox_agent_id
            and organization_id
            and deployment_id
            and agent_proof_audience
        ):
            return None
        from .identity_okta import OktaAgentIdentity
        from .identity_types import OktaAiAgentIdentityConfig

        candidate = OktaAiAgentIdentityConfig(
            openbox_agent_id=openbox_agent_id,
            organization_id=organization_id,
            deployment_id=deployment_id,
            external_agent_id=okta_agent_id,
            key_id=okta_agent_key_id,
            audience=agent_proof_audience,
            private_key=okta_agent_private_key,
            # okta_agent_algorithm is a plain `str` field (env/explicit input
            # can be any value); OktaAgentIdentity.from_config is the actual
            # runtime enforcement of SUPPORTED_ALGORITHMS, so the Literal
            # mismatch here is a static-typing artifact, not a real gap.
            algorithm=self.okta_agent_algorithm,  # type: ignore[arg-type]
        )
        return OktaAgentIdentity.from_config(candidate)


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
