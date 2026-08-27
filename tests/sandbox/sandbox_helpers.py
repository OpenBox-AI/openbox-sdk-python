from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from openbox_sandbox import StructuredCommandProfileBundle

from .helpers import KEY_ID, NOW, SECRET


def sign(payload: dict[str, Any]) -> bytes:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return json.dumps(
        {
            "payload": payload,
            "signature": {
                "algorithm": "hmac-sha256",
                "key_id": KEY_ID,
                "value": hmac.new(SECRET, canonical, hashlib.sha256).hexdigest(),
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def typed_result_schema() -> dict[str, Any]:
    return {
        "name": "openbox.proof.v1",
        "max_bytes": 256,
        "fields": [
            {"name": "job", "kind": "identifier", "max_bytes": 32},
            {"name": "count", "kind": "integer", "minimum": 1, "maximum": 5},
        ],
    }


def structured_payload(
    *,
    sensitive: bool = False,
    free_form: bool = False,
    typed_result: bool = False,
) -> dict[str, Any]:
    profile: dict[str, Any] = {
        "id": "proof",
        "executable": "/usr/bin/proof",
        "arguments": [
            {"kind": "literal", "value": "--mode"},
            {"kind": "field_enum", "field": "mode", "values": ["safe", "audit"]},
            {"kind": "field_decimal", "field": "count", "minimum": 1, "maximum": 5},
            {"kind": "field_identifier", "field": "job", "max_bytes": 32},
        ],
        "sensitive": sensitive,
        "free_form": free_form,
        "result_mode": "typed_json_v1" if typed_result else "metadata_only",
    }
    if typed_result:
        profile["result_schema"] = typed_result_schema()
    return {
        "schema_version": 1,
        "bundle_version": "structured-test-v1",
        "key_id": KEY_ID,
        "issued_at": "2026-07-16T00:00:00Z",
        "expires_at": "2027-07-17T00:00:00Z",
        "profiles": [profile],
    }


def structured_profiles(*, typed_result: bool = False) -> StructuredCommandProfileBundle:
    return StructuredCommandProfileBundle.load(
        sign(structured_payload(typed_result=typed_result)),
        secret=SECRET,
        expected_key_id=KEY_ID,
        now=NOW,
    )
