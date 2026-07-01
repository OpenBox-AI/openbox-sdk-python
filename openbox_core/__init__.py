"""OpenBox base SDK — governance core shared by every OpenBox framework SDK.

IMPORT SAFETY: this module exports only pure names (version + errors). It must
never eagerly import ``client``, ``identity``, ``gate``, ``runtime``, or any
module that pulls in httpx, cryptography, OTel instrumentation, logging,
wall-clock time, or random generation. Constrained framework paths (e.g. the
Temporal workflow sandbox) rely on ``import openbox_core`` staying side-effect
free — enforced by ``tests/test_import_safety.py``.

Heavy entry points are imported explicitly by non-sandbox code:

    from openbox_core.client import EvaluationClient
    from openbox_core.runtime import OpenBoxRuntime
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("openbox-sdk-python")
except PackageNotFoundError:  # pragma: no cover - editable installs without metadata
    __version__ = "0.0.0"

from .errors import (
    ApprovalExpiredError,
    ApprovalRejectedError,
    ApprovalTimeoutError,
    ContractError,
    GovernanceAPIError,
    GovernanceBlockedError,
    GovernanceHaltError,
    GuardrailsValidationError,
    OpenBoxAuthError,
    OpenBoxConfigError,
    OpenBoxError,
    OpenBoxInsecureURLError,
    OpenBoxNetworkError,
    OpenBoxSigningError,
    extract_governance_error,
)

__all__ = [
    "__version__",
    "OpenBoxError",
    "ContractError",
    "OpenBoxConfigError",
    "OpenBoxAuthError",
    "OpenBoxNetworkError",
    "OpenBoxInsecureURLError",
    "OpenBoxSigningError",
    "GovernanceBlockedError",
    "GovernanceHaltError",
    "GovernanceAPIError",
    "GuardrailsValidationError",
    "ApprovalExpiredError",
    "ApprovalRejectedError",
    "ApprovalTimeoutError",
    "extract_governance_error",
]
