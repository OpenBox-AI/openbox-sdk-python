"""Calls through a verdict-bound Executor (exposure barriers, Phase 3).

An agent whose evaluate returned ``EvaluationResult.verdict_token`` makes the
call it was allowed through the Executor, with exactly the body it hashed
and the participants it declared::

    body = json.dumps({"q": "merger"}).encode()
    dest = Participant("destination", "dms:main")
    with governed_action("retrieve", participants=[dest], payload_hash=hash_payload(body)):
        result = client.evaluate(...)
    response = relay_via_executor(
        "https://executor.internal", "dms:main", body, [dest], result.verdict_token,
    )

The Executor refuses a call without a valid token for that exact body and
participant set, and drops results the admission gate refuses. A refusal
raises :class:`ExecutorRefused`, which says the class of refusal:
``verdict_token`` or ``executor`` for the gateway's own refusals, and
``policy`` when governance refused the results, the same class as any other
block. It never names labels, rules or that a barrier was involved.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from .exposure import Participant

HEADER_VERDICT_TOKEN = "X-OpenBox-Verdict-Token"
HEADER_PARTICIPANTS = "X-OpenBox-Participants"
HEADER_RELAY_ID = "X-OpenBox-Relay-Id"

__all__ = [
    "ExecutorRefused",
    "arelay_via_executor",
    "executor_request",
    "relay_via_executor",
]


class ExecutorRefused(Exception):
    """The Executor did not return the destination's answer."""

    def __init__(self, status: int, reason_class: str, reason: str | None,
                 relay_id: str | None) -> None:
        self.status = status
        self.reason_class = reason_class
        self.reason = reason
        self.relay_id = relay_id
        detail = reason or ""
        super().__init__(f"executor refused the call ({reason_class}{': ' + detail if detail else ''})")


def executor_request(
    executor_url: str,
    destination: str,
    body: bytes | str,
    participants: Iterable[Participant],
    verdict_token: str | None,
    content_type: str = "application/json",
) -> tuple[str, dict[str, str], bytes]:
    """The URL, headers and body of a relayed call. ``body`` must be the
    exact bytes hashed with :func:`openbox_core.hash_payload`."""
    if not destination or "/" in destination:
        raise ValueError("destination must be a destination id")
    raw = body.encode() if isinstance(body, str) else bytes(body)
    headers = {
        "Content-Type": content_type,
        HEADER_PARTICIPANTS: json.dumps([p.to_wire() for p in participants], separators=(",", ":")),
    }
    if verdict_token:
        headers[HEADER_VERDICT_TOKEN] = verdict_token
    return f"{executor_url.rstrip('/')}/v1/relay/{destination}", headers, raw


def _check(response: Any) -> Any:
    if response.status_code < 300:
        return response
    reason_class, reason = "executor", None
    try:
        data = response.json()
        if isinstance(data, dict) and data.get("refused"):
            reason_class = data.get("reason_class") or reason_class
            reason = data.get("reason")
    except ValueError:
        pass
    raise ExecutorRefused(response.status_code, reason_class, reason,
                          response.headers.get(HEADER_RELAY_ID))


def relay_via_executor(
    executor_url: str,
    destination: str,
    body: bytes | str,
    participants: Iterable[Participant],
    verdict_token: str | None,
    *,
    content_type: str = "application/json",
    timeout: float = 60.0,
    transport: Any = None,
) -> Any:
    """Make the allowed call through the Executor and return the
    ``httpx.Response``. Raises :class:`ExecutorRefused` on a refusal."""
    import httpx

    url, headers, raw = executor_request(executor_url, destination, body, participants, verdict_token, content_type)
    with httpx.Client(timeout=timeout, transport=transport) as http:
        return _check(http.post(url, headers=headers, content=raw))


async def arelay_via_executor(
    executor_url: str,
    destination: str,
    body: bytes | str,
    participants: Iterable[Participant],
    verdict_token: str | None,
    *,
    content_type: str = "application/json",
    timeout: float = 60.0,
    transport: Any = None,
) -> Any:
    """Async :func:`relay_via_executor`."""
    import httpx

    url, headers, raw = executor_request(executor_url, destination, body, participants, verdict_token, content_type)
    async with httpx.AsyncClient(timeout=timeout, transport=transport) as http:
        return _check(await http.post(url, headers=headers, content=raw))
