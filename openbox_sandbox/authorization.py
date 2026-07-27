from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,511}\Z")


class AuthorizationSource(str, Enum):
    TRUSTED_APPLICATION = "trusted_application"
    VERIFIED_RECEIPT = "verified_receipt"


@dataclass(frozen=True, slots=True, repr=False)
class SandboxAuthorization:
    """Bounded proof identity for one already-authorized ``CONSTRAIN``.

    Authorization is established by the framework wrapper before this value is
    constructed. The sandbox engine accepts no other verdict and never calls
    OpenBox Core. Arbitrary caller metadata is intentionally not retained.
    """

    authorization_id: str
    source: AuthorizationSource

    def __post_init__(self) -> None:
        if (
            not isinstance(self.authorization_id, str)
            or _IDENTIFIER.fullmatch(self.authorization_id) is None
            or not isinstance(self.source, AuthorizationSource)
        ):
            raise ValueError("sandbox authorization rejected")

    @classmethod
    def trusted_application(cls, authorization_id: str) -> SandboxAuthorization:
        return cls(authorization_id, AuthorizationSource.TRUSTED_APPLICATION)

    @classmethod
    def verified_receipt(cls, authorization_id: str) -> SandboxAuthorization:
        return cls(authorization_id, AuthorizationSource.VERIFIED_RECEIPT)

    @property
    def governance_event_id(self) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, self.authorization_id))

    @property
    def raw(self) -> dict[str, Any]:
        return {
            "governance_event_id": self.governance_event_id,
            "verdict": "constrain",
            "risk_score": 0.0,
            "action": "constrain",
            "fallback_used": False,
            "constraints": ["run_in_sandbox"],
            "authorization_id": self.authorization_id,
            "authorization_source": self.source.value,
        }

    def __repr__(self) -> str:
        return f"SandboxAuthorization(source={self.source.value!r}, authorization_id=<redacted>)"
