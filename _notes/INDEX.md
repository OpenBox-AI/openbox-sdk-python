# openbox-sdk-python — notes index

Persistent project memory. One line per note.

## Decisions
- [[decision-flat-hook-span-contract]] — hook spans are flat Core SpanData, no `data.otel`; base SDK is the shared source of truth.
- [[decision-redis-mongo-urllib-coverage]] — v0.2.0 added Redis/Mongo/urllib3/urllib (parity for the Temporal flip); pymongo dual mechanism + gotchas; rejected raw dbapi driver instrumentors (break SQLAlchemy).

## Architecture
- [[arch-httpx-body-capture-send-patch]] — httpx bodies captured via a `Client.send` patch (OTel hooks can't read the stream); requests/urllib3 use OTel hooks.
