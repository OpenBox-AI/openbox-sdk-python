"""Bounded response capture while HTTPX callers consume decoded stream bytes.

Wrap response iterators instead of buffering the transport: HTTPX keeps ownership
of decompression, backpressure, and connection cleanup. Its raw iterator closes
the response before the decoded iterator flushes, so defer that internal close's
completion until the outer iterator finishes. An explicit close between chunks
completes immediately with the captured prefix.
"""

from __future__ import annotations

import codecs
import logging
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger(__name__)


class _Capture:
    def __init__(self, response: Any, max_chars: int, capture_text: bool):
        # Streaming capture must remain bounded even when ordinary body
        # truncation is disabled. Keep one extra character for the wire gate's
        # existing truncation diagnostic when a positive limit is configured.
        self.limit = max_chars if max_chars and max_chars > 0 else 65536
        self.remaining = self.limit + (1 if max_chars and max_chars > 0 else 0)
        self.parts: list[str] = []
        self.in_next = False
        self.eof = False
        self.finished = False
        self.error: str | None = None
        self.decoder = None
        if capture_text:
            try:
                decoder = codecs.getincrementaldecoder(response.encoding or "utf-8")
            except LookupError:
                decoder = codecs.getincrementaldecoder("utf-8")
            self.decoder = decoder(errors="replace")

    def _append(self, text: str) -> None:
        part = text[: self.remaining]
        if part:
            self.parts.append(part)
            self.remaining -= len(part)

    def feed(self, chunk: bytes) -> None:
        if self.decoder is None or self.finished:
            return
        # Decode in bounded slices, including when a transport yields a large
        # chunk. Incremental decoding preserves characters split across chunks.
        for offset in range(0, len(chunk), 4096):
            if self.remaining <= 0:
                break
            self._append(self.decoder.decode(chunk[offset : offset + 4096]))

    def failed(self, error: BaseException) -> None:
        if not isinstance(error, GeneratorExit) and self.error is None:
            self.error = f"{type(error).__name__}: {error}"

    def body(self) -> str | None:
        if self.decoder is None:
            return None
        if self.remaining > 0:
            self._append(self.decoder.decode(b"", final=True))
        return "".join(self.parts)


def capture_response_stream(
    response: Any,
    *,
    max_chars: int,
    capture_text: bool,
    complete: Callable[[str | None, str | None, bool], None],
) -> None:
    """Capture sync decoded bytes and complete once at EOF, close, or error."""
    capture = _Capture(response, max_chars, capture_text)
    original_iter = response.iter_bytes
    original_close = response.close

    def finish() -> None:
        if capture.finished or capture.in_next:
            return
        capture.finished = True
        try:
            complete(capture.body(), capture.error, not capture.eof)
        except Exception:
            logger.warning("stream completed-hook telemetry failed", exc_info=True)

    def iter_bytes(*args: Any, **kwargs: Any):
        iterator = iter(original_iter(*args, **kwargs))
        try:
            while True:
                capture.in_next = True
                try:
                    chunk = next(iterator)
                except StopIteration:
                    capture.eof = True
                    break
                finally:
                    capture.in_next = False
                capture.feed(chunk)
                yield chunk
        except BaseException as exc:
            capture.failed(exc)
            raise
        finally:
            try:
                capture.in_next = True
                if hasattr(iterator, "close"):
                    iterator.close()
            finally:
                capture.in_next = False
                finish()

    def close() -> None:
        try:
            original_close()
        except BaseException as exc:
            capture.failed(exc)
            raise
        finally:
            finish()

    response.iter_bytes = iter_bytes
    response.close = close


def capture_async_response_stream(
    response: Any,
    *,
    max_chars: int,
    capture_text: bool,
    complete: Callable[[str | None, str | None, bool], Awaitable[None]],
) -> None:
    """Async counterpart; never prefetches chunks or schedules background work."""
    capture = _Capture(response, max_chars, capture_text)
    original_iter = response.aiter_bytes
    original_close = response.aclose

    async def finish() -> None:
        if capture.finished or capture.in_next:
            return
        capture.finished = True
        try:
            await complete(capture.body(), capture.error, not capture.eof)
        except Exception:
            logger.warning("stream completed-hook telemetry failed", exc_info=True)

    async def aiter_bytes(*args: Any, **kwargs: Any):
        iterator = original_iter(*args, **kwargs).__aiter__()
        try:
            while True:
                capture.in_next = True
                try:
                    chunk = await anext(iterator)
                except StopAsyncIteration:
                    capture.eof = True
                    break
                finally:
                    capture.in_next = False
                capture.feed(chunk)
                yield chunk
        except BaseException as exc:
            capture.failed(exc)
            raise
        finally:
            try:
                capture.in_next = True
                if hasattr(iterator, "aclose"):
                    await iterator.aclose()
            finally:
                capture.in_next = False
                await finish()

    async def aclose() -> None:
        try:
            await original_close()
        except BaseException as exc:
            capture.failed(exc)
            raise
        finally:
            await finish()

    response.aiter_bytes = aiter_bytes
    response.aclose = aclose
