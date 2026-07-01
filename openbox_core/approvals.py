"""Approval polling orchestration on top of ``EvaluationClient.poll_approval``.

Owns the poll loop (interval/backoff), expiry handling, and timeout budget —
but imposes NO framework retry strategy: adapters that drive their own
approval UX (e.g. Temporal's native activity-retry HITL loop) call
``client.poll_approval`` directly and skip this module entirely.

Terminal semantics:
- allow-shaped        -> return the ApprovalResult (approved)
- blocking / expired  -> return the ApprovalResult (caller inspects
  ``is_blocking()``/``expired``; adapters translate to native errors)
- budget exhausted    -> raise ApprovalTimeoutError (client-side condition)
- poll failure (None) -> still pending; keep polling
"""

from __future__ import annotations

import asyncio
import time

from .client import EvaluationClient
from .contracts.results import ApprovalResult
from .errors import ApprovalTimeoutError

__all__ = ["ApprovalPoller"]


class ApprovalPoller:
    """Poll until an approval reaches a terminal state.

    Args:
        client: The EvaluationClient to poll through.
        poll_interval_seconds: Base delay between polls.
        max_wait_seconds: Total budget; ``None`` polls indefinitely.
        backoff_multiplier: Interval growth per attempt (1.0 = constant).
        max_interval_seconds: Interval ceiling when backing off.
    """

    def __init__(
        self,
        client: EvaluationClient,
        *,
        poll_interval_seconds: float = 5.0,
        max_wait_seconds: float | None = None,
        backoff_multiplier: float = 1.0,
        max_interval_seconds: float = 60.0,
        max_consecutive_failures: int = 60,
    ):
        self._client = client
        self._interval = poll_interval_seconds
        self._max_wait = max_wait_seconds
        self._backoff = backoff_multiplier
        self._max_interval = max_interval_seconds
        # Genuine PENDING may legitimately wait forever (max_wait bounds it),
        # but an UNREACHABLE Core must not hang the governed thread
        # indefinitely: N consecutive poll failures raise ApprovalTimeoutError
        # (fail-safe: the operation does not run).
        self._max_consecutive_failures = max_consecutive_failures

    def _next_interval(self, attempt: int) -> float:
        return min(self._interval * (self._backoff**attempt), self._max_interval)

    def _timed_out(self, started_at: float) -> bool:
        return self._max_wait is not None and (time.monotonic() - started_at) >= self._max_wait

    @staticmethod
    def _is_terminal(result: ApprovalResult | None) -> bool:
        return result is not None and not result.is_pending()

    def wait_for_decision(
        self, workflow_id: str, run_id: str, activity_id: str
    ) -> ApprovalResult:
        """Block until the approval is decided/expired, or the budget runs out."""
        started_at = time.monotonic()
        attempt = 0
        consecutive_failures = 0
        while True:
            result = self._client.poll_approval(workflow_id, run_id, activity_id)
            if self._is_terminal(result):
                return result  # type: ignore[return-value]
            consecutive_failures = consecutive_failures + 1 if result is None else 0
            if consecutive_failures >= self._max_consecutive_failures:
                raise ApprovalTimeoutError()
            if self._timed_out(started_at):
                raise ApprovalTimeoutError(int(self._max_wait * 1000))  # type: ignore[arg-type]
            time.sleep(self._next_interval(attempt))
            attempt += 1

    async def await_decision(
        self, workflow_id: str, run_id: str, activity_id: str
    ) -> ApprovalResult:
        """Async :meth:`wait_for_decision`."""
        started_at = time.monotonic()
        attempt = 0
        consecutive_failures = 0
        while True:
            result = await self._client.apoll_approval(workflow_id, run_id, activity_id)
            if self._is_terminal(result):
                return result  # type: ignore[return-value]
            consecutive_failures = consecutive_failures + 1 if result is None else 0
            if consecutive_failures >= self._max_consecutive_failures:
                raise ApprovalTimeoutError()
            if self._timed_out(started_at):
                raise ApprovalTimeoutError(int(self._max_wait * 1000))  # type: ignore[arg-type]
            await asyncio.sleep(self._next_interval(attempt))
            attempt += 1
