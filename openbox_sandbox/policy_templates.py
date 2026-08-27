"""Policy template registry: which policy the SDK deploys to the sandbox.

The sandbox service pins ONE policy per deployment (the asset-bundle policy
identity in the provisioned service config) and verifies the active sandbox
policy against it at runtime (fail closed). Policy documents are
operator-supplied material — the SDK never embeds policy bytes. This module
owns the *selection contract*:

- canonical template ids mapping to the release asset filenames shipped by
  ``OpenBox-AI/openbox-sandbox`` ``deploy/policies/`` (the release carries all
  of them; ``OPENBOX_SANDBOX_POLICY_FILE`` in agent.env names the deployed
  one);
- ``load_policy(template_id, ...)`` materializes the PolicyDocument from the
  operator's file (explicit path, or the provisioned agent.env path) and —
  when an expected sha256 is supplied — verifies the document against it
  before use.

Callers select the template id per deployment; the engine still verifies the
active sandbox policy against the expected asset-bundle identity at runtime.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .runtime import PolicyDocument, ProtocolValidationError

_MEDIA_TYPE = "application/yaml"
_ENV_POLICY_FILE = "OPENBOX_SANDBOX_POLICY_FILE"
_ENV_POLICY_SHA256 = "OPENBOX_SANDBOX_POLICY_SHA256"

# Canonical template ids -> release asset filename (deploy/policies/).
DENY_NETWORK = "openbox-deny-network"
DENY_NETWORK_DEV = "openbox-deny-network-dev"
TEMPORAL_ACTIVITY_WORKER = "openbox-temporal-activity-worker"
TEMPORAL_ACTIVITY_WORKER_DEV = "openbox-temporal-activity-worker-dev"

_TEMPLATES: dict[str, str] = {
    DENY_NETWORK: "policy-deny-network.yaml",
    DENY_NETWORK_DEV: "policy-deny-network-dev.yaml",
    TEMPORAL_ACTIVITY_WORKER: "policy-temporal-activity-worker.yaml",
    TEMPORAL_ACTIVITY_WORKER_DEV: "policy-temporal-activity-worker-dev.yaml",
}


def available_templates() -> tuple[str, ...]:
    """Return the canonical policy template ids, sorted."""
    return tuple(sorted(_TEMPLATES))


def template_asset(template_id: str) -> str:
    """Return the release asset filename for a canonical template id.

    Raises ``KeyError`` for unknown ids.
    """
    try:
        return _TEMPLATES[template_id]
    except KeyError:
        raise KeyError(
            f"unknown policy template {template_id!r}; "
            f"available: {available_templates()}"
        ) from None


def _sha256_hex(document: bytes) -> str:
    return hashlib.sha256(document).hexdigest()


def load_policy(
    template_id: str,
    policy_path: str | os.PathLike[str] | None = None,
    expected_sha256: str | None = None,
) -> PolicyDocument:
    """Materialize a PolicyDocument for a canonical template id.

    The policy bytes come from the operator's file: ``policy_path`` if given,
    otherwise ``OPENBOX_SANDBOX_POLICY_FILE`` (agent.env). When
    ``expected_sha256`` is given (or ``OPENBOX_SANDBOX_POLICY_SHA256`` is set),
    the document is verified against it before use — matching the service's
    pinned asset-bundle policy identity.

    Raises ``KeyError`` for unknown ids, ``FileNotFoundError`` when no policy
    file is configured, and ``ProtocolValidationError`` on sha mismatch.
    """
    template_asset(template_id)  # raises KeyError for unknown ids
    if policy_path is None:
        configured = os.environ.get(_ENV_POLICY_FILE)
        if not configured:
            raise FileNotFoundError(
                f"no policy file for template {template_id!r}: pass policy_path "
                f"or set {_ENV_POLICY_FILE}"
            )
        policy_path = Path(configured)
    document = Path(policy_path).read_bytes()
    if expected_sha256 is None:
        expected_sha256 = os.environ.get(_ENV_POLICY_SHA256) or None
    if expected_sha256 is not None:
        actual = _sha256_hex(document)
        if actual != expected_sha256:
            raise ProtocolValidationError(
                f"policy sha256 mismatch for template {template_id!r}: "
                f"expected {expected_sha256}, found {actual}"
            )
    return PolicyDocument(_MEDIA_TYPE, document)
