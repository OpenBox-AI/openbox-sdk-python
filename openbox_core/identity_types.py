"""Tagged agent-identity-verification configuration types.

Mirrors the TypeScript ``AgentIdentityVerification`` discriminated union
(``src/identity/types.ts``) in Python idiom — a ``method`` string-literal
discriminator on frozen dataclasses instead of a TS union — so the two base
SDKs stay learnable from one another (proposal §13.1, contract §1).

``legacy_unsigned`` has NO type here: it is an *inferred* internal
compatibility classification (proposal §13.1 rule 6), never a method a
caller selects. See ``config.py`` for how presence/absence of these fields
resolves to a verification method.

Pure module: dataclasses only, no crypto/network/wall-clock. Safe to import
from constrained framework paths (not currently re-exported from the package
root, matching the existing ``identity.py`` boundary, but importable
standalone without side effects).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

__all__ = [
    "OpenBoxDidIdentityConfig",
    "OktaAiAgentIdentityConfig",
    "AgentIdentityVerification",
    "AgentIdentityTransitionCandidate",
]


@dataclass(frozen=True)
class OpenBoxDidIdentityConfig:
    """v1 OpenBox DID identity configuration (Ed25519 request signing).

    ``private_key`` is the base64 raw 32-byte Ed25519 seed — the same
    encoding :func:`identity.load_ed25519_seed` already expects. Excluded
    from ``repr`` (non-repudiation material).
    """

    did: str
    private_key: str = field(repr=False)
    method: Literal["openbox_did"] = "openbox_did"


@dataclass(frozen=True)
class OktaAiAgentIdentityConfig:
    """v2 Okta AI Agent identity configuration (RS256 assertion signing).

    ``private_key`` is a PKCS8 PEM string — the one canonical private-key
    encoding for this release (proposal §13.1 rule 8; private JWK input is
    deferred). Excluded from ``repr``.
    """

    openbox_agent_id: str
    organization_id: str
    deployment_id: str
    external_agent_id: str
    key_id: str
    audience: str
    private_key: str = field(repr=False)
    algorithm: Literal["RS256"] = "RS256"
    method: Literal["okta_ai_agent"] = "okta_ai_agent"


# The discriminated configuration a caller may select as an agent's ACTIVE
# verification method (excludes legacy_unsigned — see module docstring).
AgentIdentityVerification = OpenBoxDidIdentityConfig | OktaAiAgentIdentityConfig

# The explicit candidate identity a transition-preflight helper signs with
# (proposal §13.5). Same two shapes as AgentIdentityVerification — a
# separate alias only because §13.5 names it distinctly; it is not a
# different type.
AgentIdentityTransitionCandidate = OpenBoxDidIdentityConfig | OktaAiAgentIdentityConfig
