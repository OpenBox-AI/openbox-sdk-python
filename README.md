# openbox-sdk-python

OpenBox base SDK (`import openbox_core`) — the standalone core every OpenBox
framework SDK builds on. It owns:

- **Contracts** — event and result dataclasses (`EventEnvelope`,
  `EvaluationResult`, `ApprovalResult`, `Verdict`).
- **Always-strict governance gate** — malformed event/runtime contracts raise
  `ContractError` before send; there are no configurable gate modes.
- **Identity & signing** — AIP DID validation + Ed25519 request signing,
  byte-compatible with the Temporal SDK signing contract.
- **Evaluate client** — sync + async calls to OpenBox Core
  (`/api/v1/governance/evaluate`, `/approval`, `/auth/validate`).
- **Context & runtime** — `ActivityContext`, `ContextStore`, trace
  correlation, `FrameworkAdapter` protocol, `OpenBoxRuntime`.
- **OTel span wire serialization** — OTel spans are the internal source of
  truth, projected to the current Core `SpanData` wire shape before send.
- **Generic instrumentation** — HTTP/DB/file/function wrappers with a
  started/completed hook runtime enforcing preflight before real operations.
- **Conformance kit** — reusable fixtures framework SDKs run to prove parity.

Framework SDKs (Temporal, LangGraph, LangChain, DeepAgent, CrewAI) are thin
adapters: they bind framework lifecycle into `ActivityContext`, emit lifecycle
events, and translate `EvaluationResult` into native behavior.

## Install

```bash
uv sync                 # core
uv sync --extra http    # + HTTP instrumentation targets
uv sync --extra db      # + DB instrumentation targets
```

## Import safety

`openbox_core.__init__` and all `openbox_core.contracts.*` modules import
without pulling in `httpx`, `cryptography`, `requests`, or OTel
instrumentation — safe for constrained framework paths such as the Temporal
workflow sandbox. `tests/test_import_safety.py` enforces this in CI.

## Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff check .
```
