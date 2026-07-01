"""HTTP wrappers — requests + httpx (sync/async) via OTel instrumentor hooks.

The instrumentor creates the OTel span and invokes our request hook BEFORE
the real request is sent; raising from the hook (via hook runtime -> adapter)
prevents the request. The wrapper itself never interprets verdicts.

Self-instrumentation guard: URLs under any ignored prefix (always including
the OpenBox ``api_url``) are skipped so evaluate calls never govern
themselves (no recursion).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from ..contracts.otel_spans import HookType
from .shared import get_hook_runtime

logger = logging.getLogger(__name__)

__all__ = [
    "set_ignored_url_prefixes",
    "should_ignore_url",
    "install_requests",
    "uninstall_requests",
    "install_httpx",
    "uninstall_httpx",
]

_ignored_url_prefixes: set[str] = set()

# span_id -> perf_counter at request start (duration for the response hook).
_HOOK_TIMINGS_MAX = 4096
_hook_timings: dict[int, float] = {}


def set_ignored_url_prefixes(prefixes: set[str]) -> None:
    global _ignored_url_prefixes
    _ignored_url_prefixes = {p.rstrip("/") for p in prefixes if p}


def should_ignore_url(url: str | None) -> bool:
    if not url:
        return True
    return any(url.startswith(prefix) for prefix in _ignored_url_prefixes)


def _record_timing(span: Any) -> None:
    try:
        span_id = span.get_span_context().span_id
    except Exception:
        return
    if len(_hook_timings) >= _HOOK_TIMINGS_MAX:
        _hook_timings.clear()
    _hook_timings[span_id] = time.perf_counter()


def _pop_duration_ns(span: Any) -> int | None:
    try:
        span_id = span.get_span_context().span_id
    except Exception:
        return None
    started = _hook_timings.pop(span_id, None)
    return int((time.perf_counter() - started) * 1e9) if started is not None else None


# ── requests ─────────────────────────────────────────────────────────────────


def _requests_request_hook(span: Any, request: Any) -> None:
    runtime = get_hook_runtime()
    if runtime is None:
        return
    url = str(getattr(request, "url", "") or "")
    if should_ignore_url(url):
        return
    body = None
    try:
        raw = getattr(request, "body", None)
        if raw:
            body = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
    except Exception:
        pass
    headers = dict(request.headers) if getattr(request, "headers", None) else None
    _record_timing(span)
    runtime.preflight(
        span,
        hook_type=HookType.HTTP_REQUEST,
        identifier=url,
        fields={
            "http_method": getattr(request, "method", None) or "UNKNOWN",
            "http_url": url,
            "request_body": body,
            "request_headers": headers,
        },
    )


def _requests_response_hook(span: Any, request: Any, response: Any) -> None:
    runtime = get_hook_runtime()
    if runtime is None:
        return
    url = str(getattr(request, "url", "") or "")
    if should_ignore_url(url):
        return
    status_code = getattr(response, "status_code", None)
    body = None
    try:
        content_type = response.headers.get("content-type", "") if response.headers else ""
        if any(t in content_type for t in ("json", "text", "xml")):
            body = response.text
    except Exception:
        pass
    runtime.completed(
        span,
        hook_type=HookType.HTTP_REQUEST,
        fields={
            "http_method": getattr(request, "method", None) or "UNKNOWN",
            "http_url": url,
            "http_status_code": status_code,
            "response_body": body,
            "response_headers": dict(response.headers) if getattr(response, "headers", None) else None,
            "duration_ns": _pop_duration_ns(span),
            "error": f"HTTP {status_code}" if status_code and status_code >= 400 else None,
        },
    )


def install_requests() -> bool:
    try:
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
    except ImportError:
        logger.info("requests instrumentation not available (install extra [http]) — deferred")
        return False
    RequestsInstrumentor().instrument(
        request_hook=_requests_request_hook, response_hook=_requests_response_hook
    )
    return True


def uninstall_requests() -> None:
    try:
        from opentelemetry.instrumentation.requests import RequestsInstrumentor

        RequestsInstrumentor().uninstrument()
    except Exception:
        logger.debug("requests uninstrument skipped", exc_info=True)


# ── httpx (sync + async) ─────────────────────────────────────────────────────


def _httpx_url(request_info: Any) -> str:
    return str(getattr(request_info, "url", "") or "")


def _httpx_started_fields(request_info: Any) -> dict:
    method = getattr(request_info, "method", b"")
    if isinstance(method, bytes):
        method = method.decode("ascii", errors="ignore")
    headers = getattr(request_info, "headers", None)
    return {
        "http_method": method or "UNKNOWN",
        "http_url": _httpx_url(request_info),
        "request_headers": dict(headers) if headers else None,
    }


def _httpx_request_hook(span: Any, request_info: Any) -> None:
    runtime = get_hook_runtime()
    if runtime is None:
        return
    url = _httpx_url(request_info)
    if should_ignore_url(url):
        return
    _record_timing(span)
    runtime.preflight(
        span,
        hook_type=HookType.HTTP_REQUEST,
        identifier=url,
        fields=_httpx_started_fields(request_info),
    )


async def _httpx_async_request_hook(span: Any, request_info: Any) -> None:
    runtime = get_hook_runtime()
    if runtime is None:
        return
    url = _httpx_url(request_info)
    if should_ignore_url(url):
        return
    _record_timing(span)
    await runtime.apreflight(
        span,
        hook_type=HookType.HTTP_REQUEST,
        identifier=url,
        fields=_httpx_started_fields(request_info),
    )


def _httpx_completed_fields(span: Any, request_info: Any, response_info: Any) -> dict:
    status_code = getattr(response_info, "status_code", None)
    if status_code is None:  # ResponseInfo may pack (status, headers, stream, ext)
        try:
            status_code = response_info[0]
        except Exception:
            status_code = None
    fields = _httpx_started_fields(request_info)
    fields.update(
        {
            "http_status_code": status_code,
            "duration_ns": _pop_duration_ns(span),
            "error": f"HTTP {status_code}" if status_code and status_code >= 400 else None,
        }
    )
    return fields


def _httpx_response_hook(span: Any, request_info: Any, response_info: Any) -> None:
    runtime = get_hook_runtime()
    if runtime is None or should_ignore_url(_httpx_url(request_info)):
        return
    runtime.completed(
        span,
        hook_type=HookType.HTTP_REQUEST,
        fields=_httpx_completed_fields(span, request_info, response_info),
    )


async def _httpx_async_response_hook(span: Any, request_info: Any, response_info: Any) -> None:
    runtime = get_hook_runtime()
    if runtime is None or should_ignore_url(_httpx_url(request_info)):
        return
    await runtime.acompleted(
        span,
        hook_type=HookType.HTTP_REQUEST,
        fields=_httpx_completed_fields(span, request_info, response_info),
    )


def install_httpx() -> bool:
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    except ImportError:
        logger.info("httpx instrumentation not available (install extra [http]) — deferred")
        return False
    HTTPXClientInstrumentor().instrument(
        request_hook=_httpx_request_hook,
        response_hook=_httpx_response_hook,
        async_request_hook=_httpx_async_request_hook,
        async_response_hook=_httpx_async_response_hook,
    )
    return True


def uninstall_httpx() -> None:
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        HTTPXClientInstrumentor().uninstrument()
    except Exception:
        logger.debug("httpx uninstrument skipped", exc_info=True)
