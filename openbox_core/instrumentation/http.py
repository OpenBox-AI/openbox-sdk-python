"""HTTP wrappers — requests + httpx (sync/async) via OTel instrumentor hooks.

The instrumentor creates the OTel span and invokes our request hook BEFORE
the real request is sent; raising from the hook (via hook runtime -> adapter)
prevents the request. The wrapper itself never interprets verdicts.

Self-instrumentation guard: URLs under any ignored prefix (always including
the OpenBox ``api_url``) are skipped so evaluate calls never govern
themselves (no recursion).
"""

from __future__ import annotations

import contextvars
import logging
import time
from typing import Any

from ..contracts.otel_spans import HookType
from .shared import get_hook_runtime

logger = logging.getLogger(__name__)

__all__ = [
    "set_ignored_url_prefixes",
    "should_ignore_url",
    "sanitize_headers",
    "install_requests",
    "uninstall_requests",
    "install_httpx",
    "uninstall_httpx",
    "install_httpx_body_capture",
    "uninstall_httpx_body_capture",
]

# Content-type markers safe to capture as a text body.
_TEXT_CONTENT_MARKERS = ("json", "text", "xml")


def _is_text_content_type(content_type: str | None) -> bool:
    """True when the content type indicates text (safe to read as a body)."""
    if not content_type:
        return True  # assume text when unspecified
    return any(marker in content_type.lower() for marker in _TEXT_CONTENT_MARKERS)

_ignored_url_prefixes: set[str] = set()

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalize_url_prefix(url: str) -> str:
    """Canonical prefix form: lowercase scheme/host, explicit default port,
    no trailing slash. httpx normalizes request URLs (lowercased host,
    default port stripped) — comparing RAW config strings against that would
    miss e.g. ``https://Core.example`` vs ``https://core.example`` and let
    the evaluate call govern itself (unbounded recursion)."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return url.rstrip("/")
    if not parts.scheme or not parts.hostname:
        return url.rstrip("/")
    scheme = parts.scheme.lower()
    port = parts.port if parts.port is not None else _DEFAULT_PORTS.get(scheme)
    netloc = parts.hostname.lower() + (f":{port}" if port is not None else "")
    return f"{scheme}://{netloc}{parts.path}".rstrip("/")

# span_id -> perf_counter at request start (duration for the response hook).
_HOOK_TIMINGS_MAX = 4096
_hook_timings: dict[int, float] = {}


def set_ignored_url_prefixes(prefixes: set[str]) -> None:
    global _ignored_url_prefixes
    _ignored_url_prefixes = {_normalize_url_prefix(p) for p in prefixes if p}


# Headers whose values are credentials/secrets — never ship them into
# governance payloads (they land in Core logs verbatim otherwise).
_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-amz-security-token",
    }
)


def sanitize_headers(headers: Any) -> dict | None:
    """Copy headers with credential values redacted; bytes decoded."""
    if not headers:
        return None
    sanitized = {}
    for key, value in dict(headers).items():
        if isinstance(key, bytes):
            key = key.decode("latin-1", errors="ignore")
        if isinstance(value, bytes):
            value = value.decode("latin-1", errors="ignore")
        sanitized[key] = "[REDACTED]" if str(key).lower() in _SENSITIVE_HEADERS else value
    return sanitized


def should_ignore_url(url: str | None) -> bool:
    if not url:
        return True
    normalized = _normalize_url_prefix(url)
    return any(normalized.startswith(prefix) for prefix in _ignored_url_prefixes)


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
    headers = sanitize_headers(getattr(request, "headers", None))
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


def _requests_body(request: Any) -> str | None:
    """Best-effort request body from a requests PreparedRequest."""
    try:
        raw = getattr(request, "body", None)
        if not raw:
            return None
        return raw.decode("utf-8", errors="ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
    except Exception:
        return None


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
        if _is_text_content_type(content_type):
            body = response.text
    except Exception:
        pass
    # Completed retains the request body/headers alongside the response
    # (Temporal parity — the completed stage carries the full exchange).
    runtime.completed(
        span,
        hook_type=HookType.HTTP_REQUEST,
        fields={
            "http_method": getattr(request, "method", None) or "UNKNOWN",
            "http_url": url,
            "http_status_code": status_code,
            "request_body": _requests_body(request),
            "request_headers": sanitize_headers(getattr(request, "headers", None)),
            "response_body": body,
            "response_headers": sanitize_headers(getattr(response, "headers", None)),
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
#
# httpx bodies are NOT available in the OTel hooks: the request hook sees an
# unread stream and the response hook sees a ResponseInfo whose stream cannot be
# consumed safely. So the split mirrors the Temporal SDK:
#   - OTel request hook → started/preflight (best-effort request body) + stash
#     the httpx CLIENT span for the completed stage.
#   - a Client.send / AsyncClient.send patch → the SINGLE completed event, with
#     the full request/response bodies + headers captured after send returns.
# The OTel response hook is intentionally NOT registered — completed lives in
# the send patch to avoid a double completed event.

# Task/thread-local stash: the request hook publishes the httpx CLIENT span here
# so the send patch (running after that span has ended) attaches the completed
# event to the SAME span identity.
_httpx_span_var: contextvars.ContextVar = contextvars.ContextVar("_httpx_span", default=None)


def _httpx_url(request_info: Any) -> str:
    return str(getattr(request_info, "url", "") or "")


def _decode_method(method: Any) -> str:
    """httpx methods arrive as bytes (b"POST"); plain str() would mangle them."""
    if isinstance(method, bytes):
        return method.decode("ascii", errors="ignore") or "UNKNOWN"
    return str(method) if method else "UNKNOWN"


def _httpx_request_body(request_info: Any) -> str | None:
    """Best-effort request body from an OTel httpx RequestInfo.

    Reads ONLY already-buffered bytes (stream ``_stream``/``body``/``_body`` or
    a bytes ``_content``) — never triggers a property that could consume a live
    stream.
    """
    try:
        raw: Any = None
        stream = getattr(request_info, "stream", None)
        if stream is not None:
            for attr in ("_stream", "body", "_body"):
                candidate = getattr(stream, attr, None)
                if isinstance(candidate, (bytes, bytearray)):
                    raw = candidate
                    break
            if raw is None and isinstance(stream, (bytes, bytearray)):
                raw = stream
        if raw is None:
            content = getattr(request_info, "_content", None)
            if isinstance(content, (bytes, bytearray)):
                raw = content
        if raw is None:
            return None
        return bytes(raw).decode("utf-8", errors="ignore")
    except Exception:
        return None


def _httpx_started_fields(request_info: Any) -> dict:
    return {
        "http_method": _decode_method(getattr(request_info, "method", b"")),
        "http_url": _httpx_url(request_info),
        "request_headers": sanitize_headers(getattr(request_info, "headers", None)),
        "request_body": _httpx_request_body(request_info),
    }


def _httpx_request_hook(span: Any, request_info: Any) -> None:
    runtime = get_hook_runtime()
    if runtime is None:
        return
    url = _httpx_url(request_info)
    if should_ignore_url(url):
        return
    # Stash the span for the send patch's completed stage, then preflight.
    _httpx_span_var.set(span)
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
    _httpx_span_var.set(span)
    await runtime.apreflight(
        span,
        hook_type=HookType.HTTP_REQUEST,
        identifier=url,
        fields=_httpx_started_fields(request_info),
    )


def install_httpx() -> bool:
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    except ImportError:
        logger.info("httpx instrumentation not available (install extra [http]) — deferred")
        return False
    # Only request hooks: completed is emitted by the send patch (see below).
    HTTPXClientInstrumentor().instrument(
        request_hook=_httpx_request_hook,
        async_request_hook=_httpx_async_request_hook,
    )
    return True


def uninstall_httpx() -> None:
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        HTTPXClientInstrumentor().uninstrument()
    except Exception:
        logger.debug("httpx uninstrument skipped", exc_info=True)


# ── httpx body capture (Client.send / AsyncClient.send patch) ────────────────
#
# Separate from OTel instrumentation: OTel hooks receive streams that cannot be
# consumed. Patching send lets us read the request body (buffered before send)
# and the response body (cached by httpx after a non-streaming send) safely.

_original_httpx_send: Any = None
_original_httpx_async_send: Any = None


def _pop_httpx_span() -> Any:
    """Retrieve + clear the span stashed by the request hook (fallback: current
    span, so completed still resolves context if the stash missed)."""
    span = _httpx_span_var.get(None)
    _httpx_span_var.set(None)
    if span is None:
        from opentelemetry import trace

        span = trace.get_current_span()
    return span


def _capture_httpx_request(request: Any) -> tuple[str | None, dict | None]:
    """(request_body, request_headers) — reads only buffered content."""
    body = None
    headers = None
    try:
        raw = getattr(request, "_content", None)
        if isinstance(raw, (bytes, bytearray)):
            body = bytes(raw).decode("utf-8", errors="ignore")
        headers = sanitize_headers(getattr(request, "headers", None))
    except Exception:
        pass
    return body, headers


def _capture_httpx_response(response: Any) -> tuple[str | None, dict | None]:
    """(response_body, response_headers) — never consumes a stream.

    ``response.text`` raises ``ResponseNotRead`` for an unread streaming
    response; that is caught, leaving the body None (safe, no consumption).
    """
    body = None
    headers = None
    try:
        headers = sanitize_headers(getattr(response, "headers", None))
        content_type = ""
        try:
            content_type = response.headers.get("content-type", "") if response.headers else ""
        except Exception:
            content_type = ""
        if _is_text_content_type(content_type):
            try:
                body = response.text
            except Exception:
                body = None
    except Exception:
        pass
    return body, headers


def _httpx_completed_fields(
    request: Any,
    response: Any,
    duration_ns: int | None,
    request_body: str | None,
    request_headers: dict | None,
    response_body: str | None,
    response_headers: dict | None,
) -> dict:
    status_code = getattr(response, "status_code", None)
    return {
        "http_method": _decode_method(getattr(request, "method", None)),
        "http_url": str(getattr(request, "url", "") or ""),
        "http_status_code": status_code,
        "request_body": request_body,
        "request_headers": request_headers,
        "response_body": response_body,
        "response_headers": response_headers,
        "duration_ns": duration_ns,
        "error": f"HTTP {status_code}" if isinstance(status_code, int) and status_code >= 400 else None,
    }


def install_httpx_body_capture() -> bool:
    """Patch httpx ``Client.send``/``AsyncClient.send`` for completed body
    capture. Idempotent; must be installed AFTER ``install_httpx`` so the
    captured original send already carries the OTel request hook."""
    global _original_httpx_send, _original_httpx_async_send
    if _original_httpx_send is not None:
        return True
    try:
        import httpx
    except ImportError:
        logger.info("httpx not available for body capture — deferred")
        return False

    _original_httpx_send = httpx.Client.send
    _original_httpx_async_send = httpx.AsyncClient.send

    def _patched_send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
        runtime = get_hook_runtime()
        url = str(getattr(request, "url", "") or "")
        if runtime is None or should_ignore_url(url):
            return _original_httpx_send(self, request, *args, **kwargs)
        request_body, request_headers = _capture_httpx_request(request)
        start = time.perf_counter()
        # The OTel request hook fires inside here (preflight). A BLOCK/HALT
        # raises out — the request never completes and no completed is emitted.
        response = _original_httpx_send(self, request, *args, **kwargs)
        duration_ns = int((time.perf_counter() - start) * 1e9)
        response_body, response_headers = _capture_httpx_response(response)
        runtime.completed(
            _pop_httpx_span(),
            hook_type=HookType.HTTP_REQUEST,
            fields=_httpx_completed_fields(
                request, response, duration_ns,
                request_body, request_headers, response_body, response_headers,
            ),
        )
        return response

    async def _patched_async_send(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
        runtime = get_hook_runtime()
        url = str(getattr(request, "url", "") or "")
        if runtime is None or should_ignore_url(url):
            return await _original_httpx_async_send(self, request, *args, **kwargs)
        request_body, request_headers = _capture_httpx_request(request)
        start = time.perf_counter()
        response = await _original_httpx_async_send(self, request, *args, **kwargs)
        duration_ns = int((time.perf_counter() - start) * 1e9)
        response_body, response_headers = _capture_httpx_response(response)
        await runtime.acompleted(
            _pop_httpx_span(),
            hook_type=HookType.HTTP_REQUEST,
            fields=_httpx_completed_fields(
                request, response, duration_ns,
                request_body, request_headers, response_body, response_headers,
            ),
        )
        return response

    httpx.Client.send = _patched_send
    httpx.AsyncClient.send = _patched_async_send
    return True


def uninstall_httpx_body_capture() -> None:
    """Restore httpx send (idempotent). Call BEFORE ``uninstall_httpx`` so the
    original chain is unwound in reverse install order."""
    global _original_httpx_send, _original_httpx_async_send
    if _original_httpx_send is None:
        return
    try:
        import httpx

        httpx.Client.send = _original_httpx_send
        httpx.AsyncClient.send = _original_httpx_async_send
    except Exception:
        logger.debug("httpx body-capture restore skipped", exc_info=True)
    _original_httpx_send = None
    _original_httpx_async_send = None
