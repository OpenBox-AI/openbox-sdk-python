"""OpenBox base SDK — governance core shared by every OpenBox framework SDK.

IMPORT SAFETY: this module exports only pure names (version + errors). It must
never eagerly import ``client``, ``identity``, ``gate``, ``runtime``, or any
module that pulls in httpx, cryptography, OTel instrumentation, logging,
wall-clock time, or random generation. Constrained framework paths (e.g. the
workflow sandbox) rely on ``import openbox_core`` staying side-effect free —
enforced by ``tests/test_import_safety.py``.

Heavy entry points are imported explicitly by non-sandbox code:

    from openbox_core.client import EvaluationClient
    from openbox_core.runtime import OpenBoxRuntime
"""

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
from .exposure import (
    Participant,
    Resource,
    current_exposure_fields,
    exposure_scope,
    governed_action,
)
from .on_behalf_of import (
    current_on_behalf_of,
    on_behalf_of,
    reset_on_behalf_of,
    set_on_behalf_of,
)

# STATIC on purpose — never read via importlib.metadata. A metadata lookup
# OPENS A FILE; with file instrumentation active (frameworks patch
# builtins.open/io.open with governed wrappers) that read re-enters
# governance; eagerly it can deadlock package init as a circular import, and
# lazily it can recurse unboundedly when a per-request header builder resolves
# the version. Keep in sync with pyproject.toml on release.
__version__ = "1.4.0"

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
    "on_behalf_of",
    "set_on_behalf_of",
    "reset_on_behalf_of",
    "current_on_behalf_of",
    "Resource",
    "Participant",
    "exposure_scope",
    "governed_action",
    "current_exposure_fields",
]
