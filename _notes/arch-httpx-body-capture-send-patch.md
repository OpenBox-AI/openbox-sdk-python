---
type: arch
date: 2026-07-03
tags: [http, httpx, instrumentation, otel]
status: active
---

# httpx body capture uses a `Client.send` patch, not OTel hooks

httpx request/response **bodies are not capturable in the OTel hooks**: the OTel
request hook receives an unread stream, and the OTel response hook receives a
`ResponseInfo` whose stream cannot be consumed safely. So `instrumentation/http.py`
mirrors the Temporal SDK and splits httpx across two mechanisms:

- **OTel request hook** (`_httpx_request_hook`/async) → started/preflight (this is
  where a BLOCK/HALT raises and prevents the request) + best-effort request body
  from already-buffered bytes + **stashes the httpx CLIENT span** in a ContextVar
  (`_httpx_span_var`).
- **`Client.send`/`AsyncClient.send` patch** (`install_httpx_body_capture`) → the
  SINGLE completed event. Runs the original send (preflight fires inside it),
  then after it returns reads `request._content` (buffered) and `response.text`
  (cached by httpx after a non-streaming send) and fires `runtime.completed`
  against the stashed span.

## Sharp edges

- The OTel httpx **response hook is intentionally NOT registered** — completed
  lives only in the send patch. Registering both = double completed events
  (caught by `test_async_allow_sends` asserting exactly 1 completed).
- `response.text` on an unread streaming response raises `ResponseNotRead`; that
  is caught → body stays None. We **never consume a stream**.
- Install ORDER matters: `install_httpx_body_capture` runs AFTER `install_httpx`
  so the captured original send already carries the OTel request hook. Uninstall
  is reverse order (`manager.py`).
- No recursion: the evaluate call to Core's own URL is skipped by
  `should_ignore_url` in both the request hook and the send patch.
- `requests`/urllib3 bodies ARE available in their OTel hooks, so only httpx
  needs the send patch. requests completed now also retains request body/headers.

Contract this feeds: [[decision-flat-hook-span-contract]].
