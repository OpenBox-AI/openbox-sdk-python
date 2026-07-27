"""Framework-neutral execution of already-authorized sandbox constraints.

Exports are loaded on first access so deterministic framework code can import
``openbox_sandbox.contracts`` without importing runtime, TLS, signing, telemetry,
or filesystem modules.
"""

from __future__ import annotations

from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "ApprovedSandboxRelease": ("release", "ApprovedSandboxRelease"),
    "AuthorizationSource": ("authorization", "AuthorizationSource"),
    "AuthorizedConstrain": ("receipts", "AuthorizedConstrain"),
    "CleanupBacklog": ("telemetry", "CleanupBacklog"),
    "CleanupReconciliationResult": ("result", "CleanupReconciliationResult"),
    "CleanupStatus": ("result", "CleanupStatus"),
    "CommandProfileBundle": ("profiles", "CommandProfileBundle"),
    "CommandProfileBundleError": ("command_profiles", "CommandProfileBundleError"),
    "CommandResultValidationError": (
        "command_profiles",
        "CommandResultValidationError",
    ),
    "DecimalArgument": ("registry", "DecimalArgument"),
    "Disposition": ("result", "Disposition"),
    "EnumArgument": ("registry", "EnumArgument"),
    "ExecutionMetadata": ("result", "ExecutionMetadata"),
    "GOVERNED_COMMAND_ACTIVITY_TYPE": ("contracts", "GOVERNED_COMMAND_ACTIVITY_TYPE"),
    "GovernedCommandDeploymentError": ("errors", "GovernedCommandDeploymentError"),
    "IdentifierArgument": ("registry", "IdentifierArgument"),
    "IdentifierResultField": ("registry", "IdentifierResultField"),
    "InMemoryTelemetrySink": ("telemetry", "InMemoryTelemetrySink"),
    "IntegerResultField": ("registry", "IntegerResultField"),
    "LiteralArgument": ("registry", "LiteralArgument"),
    "NormalizedSandboxError": ("errors", "NormalizedSandboxError"),
    "ProfileValidationError": ("errors", "ProfileValidationError"),
    "ReceiptSigner": ("receipts", "ReceiptSigner"),
    "SandboxActivityResult": ("contracts", "GovernedCommandActivityResult"),
    "SandboxAuthorization": ("authorization", "SandboxAuthorization"),
    "SandboxCommand": ("command", "SandboxCommand"),
    "SandboxCommandArgument": ("contracts", "StructuredCommandArgument"),
    "SandboxCommandDefinition": ("registry", "GovernedCommandDefinition"),
    "SandboxCommandRegistry": ("registry", "GovernedCommandRegistry"),
    "SandboxCommandRegistryError": ("registry", "GovernedCommandRegistryError"),
    "SandboxCommandRequest": ("contracts", "GovernedCommandRequest"),
    "SandboxDeployment": ("deployment", "SandboxDeployment"),
    "SandboxDeploymentConfig": ("deployment", "SandboxDeploymentConfig"),
    "SandboxEngineConfig": ("engine", "SandboxEngineConfig"),
    "SandboxErrorCode": ("errors", "SandboxErrorCode"),
    "SandboxExecutionConfig": ("engine", "SandboxExecutionConfig"),
    "SandboxExecutionEngine": ("engine", "SandboxExecutionEngine"),
    "SandboxExecutionResult": ("result", "SandboxExecutionResult"),
    "SandboxHealth": ("deployment", "SandboxHealth"),
    "SandboxInputError": ("contracts", "GovernedCommandInputError"),
    "SandboxReceipt": ("contracts", "GovernedCommandReceipt"),
    "SandboxReceiptError": ("receipts", "GovernedCommandReceiptError"),
    "SandboxReceiptVerifier": ("receipts", "GovernedCommandReceiptVerifier"),
    "SandboxReleaseMaterial": ("release", "SandboxReleaseMaterial"),
    "SandboxResultValue": ("contracts", "GovernedCommandResultValue"),
    "SandboxTypedResult": ("contracts", "GovernedCommandTypedResult"),
    "SandboxValidationError": ("errors", "SandboxValidationError"),
    "StructuredCommandProfileBundle": (
        "command_profiles",
        "StructuredCommandProfileBundle",
    ),
    "TelemetryEvent": ("telemetry", "TelemetryEvent"),
    "TelemetrySink": ("telemetry", "TelemetrySink"),
    "TimeoutStatus": ("result", "TimeoutStatus"),
    "TypedJsonResultSchema": ("registry", "TypedJsonResultSchema"),
    "UnixAgentExecutionConfig": ("engine", "UnixAgentExecutionConfig"),
    "approved_sandbox_release": ("release", "approved_sandbox_release"),
    "asset_bundle_sha256": ("receipts", "asset_bundle_sha256"),
    "command_sha256": ("receipts", "command_sha256"),
    "issue_sandbox_receipt": ("receipts", "issue_sandbox_receipt"),
    "load_approved_sandbox_release": ("release", "load_approved_sandbox_release"),
    "load_sandbox_deployment": ("deployment", "load_sandbox_deployment"),
    "materialize_approved_sandbox_release": (
        "release",
        "materialize_approved_sandbox_release",
    ),
    "receipt_binding": ("receipts", "receipt_binding"),
    "request_arguments_sha256": ("receipts", "request_arguments_sha256"),
    "sandbox_command_registry": ("registry", "governed_command_registry"),
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    module = __import__(f"{__name__}.{module_name}", fromlist=[attribute_name])
    value = getattr(module, attribute_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted((*globals(), *__all__))
