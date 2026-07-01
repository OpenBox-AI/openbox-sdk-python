"""Generate the golden signing fixture by executing the LIVE Temporal signer.

Loads openbox/request_signing.py from the Temporal SDK repo as a standalone
module (stubbing its build_auth_headers sibling — auth headers are not part of
the signed material), injects a fixed timestamp + nonce, and pins the exact
canonical string, body bytes, body hash, signature, and signed headers.

Run manually to (re)generate tests/signing/golden_temporal_signed_request.json:

    uv run python tests/signing/generate_golden_fixture_from_temporal_signer.py

The pinned JSON is committed; tests never import the Temporal repo.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
import sys
import types
from unittest import mock

TEMPORAL_SIGNER = pathlib.Path(
    "/Users/tino/code/openbox-temporal-sdk-python/openbox/request_signing.py"
)
OUT = pathlib.Path(__file__).parent / "golden_temporal_signed_request.json"

# ── Fixed inputs (deterministic) ────────────────────────────────────────────
SEED_BYTES = bytes(range(32))
SEED_B64 = base64.b64encode(SEED_BYTES).decode("ascii")
AGENT_DID = "did:aip:12345678-1234-5678-1234-567812345678"
API_KEY = "obx_test_goldenfixture"
METHOD = "POST"
PATH = "/api/v1/governance/evaluate"
TIMESTAMP = "2026-07-02T00:00:00.123456+00:00"  # datetime.now(utc).isoformat() shape
NONCE = "Zm9vYmFyLWdvbGRlbi1ub25jZS1mixed"  # token_urlsafe(24)-shaped, fixed
PAYLOAD = {
    "source": "workflow-telemetry",
    "event_type": "ActivityStarted",
    "workflow_id": "wf-golden",
    "run_id": "run-golden",
    "workflow_type": "GoldenWorkflow",
    "task_queue": "golden-queue",
    "activity_id": "act-1",
    "activity_type": "charge_card",
    "hook_trigger": True,
    "spans": [{"span_id": "00f067aa0ba902b7", "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"}],
    "span_count": 1,
    "timestamp": "2026-07-02T00:00:00.000Z",
    "note": "unicode-café-☕",
}


def load_temporal_signer() -> types.ModuleType:
    pkg = types.ModuleType("temporal_openbox")
    pkg.__path__ = [str(TEMPORAL_SIGNER.parent)]
    sys.modules["temporal_openbox"] = pkg
    # Stub the sibling import — auth headers are NOT signed material.
    hg = types.ModuleType("temporal_openbox.hook_governance")
    hg.build_auth_headers = lambda api_key: {"Authorization": f"Bearer {api_key}"}
    sys.modules["temporal_openbox.hook_governance"] = hg
    spec = importlib.util.spec_from_file_location(
        "temporal_openbox.request_signing", TEMPORAL_SIGNER
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["temporal_openbox.request_signing"] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signer = Ed25519PrivateKey.from_private_bytes(SEED_BYTES)
    rs = load_temporal_signer()

    class FixedDatetime:
        @staticmethod
        def now(tz=None):
            import datetime as _dt

            return _dt.datetime.fromisoformat(TIMESTAMP)

    fixed_secrets = types.SimpleNamespace(token_urlsafe=lambda n=32: NONCE)

    with mock.patch.object(rs, "datetime", FixedDatetime), mock.patch.object(
        rs, "secrets", fixed_secrets
    ):
        headers, body_bytes = rs.prepare_signed_request(
            METHOD, PATH, PAYLOAD, api_key=API_KEY, agent_did=AGENT_DID, signer=signer
        )

    import hashlib

    body_sha256 = hashlib.sha256(body_bytes).hexdigest()
    canonical = "\n".join([METHOD, PATH, TIMESTAMP, NONCE, body_sha256])

    fixture = {
        "_generated_by": "tests/signing/generate_golden_fixture_from_temporal_signer.py",
        "_source_signer": "openbox-temporal-sdk-python/openbox/request_signing.py",
        "method": METHOD,
        "path": PATH,
        "payload": PAYLOAD,
        "api_key": API_KEY,
        "agent_did": AGENT_DID,
        "seed_b64": SEED_B64,
        "timestamp": TIMESTAMP,
        "nonce": NONCE,
        "canonical": canonical,
        "body_b64": base64.b64encode(body_bytes).decode("ascii"),
        "body_sha256": body_sha256,
        "signed_headers": {
            "X-OpenBox-Agent-DID": headers["X-OpenBox-Agent-DID"],
            "X-OpenBox-Agent-Timestamp": headers["X-OpenBox-Agent-Timestamp"],
            "X-OpenBox-Agent-Nonce": headers["X-OpenBox-Agent-Nonce"],
            "X-OpenBox-Agent-Signature": headers["X-OpenBox-Agent-Signature"],
            "X-OpenBox-Body-SHA256": headers["X-OpenBox-Body-SHA256"],
        },
        "empty_body_sha256": rs.EMPTY_BODY_SHA256,
    }
    OUT.write_text(json.dumps(fixture, indent=2, ensure_ascii=True) + "\n")
    print(f"wrote {OUT}")
    print(f"signature: {headers['X-OpenBox-Agent-Signature']}")


if __name__ == "__main__":
    main()
