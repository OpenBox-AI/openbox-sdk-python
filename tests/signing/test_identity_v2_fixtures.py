"""Cross-language checks for the v2 agent-identity golden fixtures.

The fixtures are owned by openbox-core (``testdata/identity-v2``) and copied here by its
``scripts/sync-identity-fixtures.sh``. These tests prove the fixture parses in Python and
that this repo computes byte-identical hashes, so a contract change cannot land in Go only.

Do not edit files under ``tests/signing/identity_v2`` — CI runs the drift check.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "identity_v2"

EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

POSITIVE_CASES = [
    "evaluate.json",
    "approval.json",
    "auth-validate.json",
    "handoff.json",
    "transition-proof.json",
]

REQUIRED_CLAIMS = [
    "iss",
    "sub",
    "aud",
    "obx_deployment_id",
    "obx_organization_id",
    "obx_agent_id",
    "obx_api_key_sha256",
    "iat",
    "exp",
    "jti",
    "htm",
    "htu",
    "body_sha256",
]


def read_fixture(*segments: str) -> dict:
    return json.loads(FIXTURE_DIR.joinpath(*segments).read_text())


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_segment(segment: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


@pytest.mark.parametrize("filename", POSITIVE_CASES)
def test_positive_fixture_is_internally_consistent(filename: str) -> None:
    fixture = read_fixture(filename)
    assert fixture["expect"]["valid"] is True

    body = base64.b64decode(fixture["body_base64"])
    assert sha256_hex(body) == fixture["body_sha256"]
    assert sha256_hex(fixture["api_key"].encode()) == fixture["claims"]["obx_api_key_sha256"]

    segments = fixture["assertion"].split(".")
    assert len(segments) == 3

    header = decode_segment(segments[0])
    assert header["alg"] == "RS256"
    assert header["typ"] == "openbox-agent-proof+jwt"
    for forbidden in ("jwk", "jku", "x5u"):
        assert forbidden not in header

    claims = decode_segment(segments[1])
    for claim in REQUIRED_CLAIMS:
        assert claim in claims, f"missing claim {claim}"

    assert claims["htm"] == fixture["method"]
    assert claims["htu"] == fixture["path"]
    assert claims["body_sha256"] == fixture["body_sha256"]
    assert claims["iss"] == claims["sub"]

    lifetime = claims["exp"] - claims["iat"]
    assert 0 < lifetime <= 60

    # A shared audience such as "openbox-core" would let a staging assertion
    # authenticate against production.
    assert claims["aud"].startswith("urn:openbox:")
    assert claims["aud"].endswith(":core")


def test_auth_validate_uses_empty_body_hash() -> None:
    fixture = read_fixture("auth-validate.json")
    assert fixture["method"] == "GET"
    assert fixture["body_sha256"] == EMPTY_BODY_SHA256
    assert sha256_hex(b"") == EMPTY_BODY_SHA256


def test_transition_proof_carries_transition_claims() -> None:
    fixture = read_fixture("transition-proof.json")
    claims = decode_segment(fixture["assertion"].split(".")[1])
    assert claims["obx_transition_purpose"]
    assert claims["obx_transition_id"]
    assert claims["obx_transition_challenge"]


def test_every_tamper_fixture_declares_a_reason_code() -> None:
    files = sorted(p for p in (FIXTURE_DIR / "tamper").glob("*.json"))
    assert files

    for path in files:
        fixture = json.loads(path.read_text())
        assert fixture["expect"]["valid"] is False, f"{path.name} is marked valid"
        assert fixture["expect"]["reason_code"], f"{path.name} has no reason code"


def test_fixtures_match_the_manifest_published_by_openbox_core() -> None:
    """Guards against a fixture edited here instead of regenerated in openbox-core."""
    recorded: dict[str, str] = {}
    for line in (FIXTURE_DIR / "MANIFEST.sha256").read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        digest, relative = stripped.split()
        recorded[relative] = digest

    assert recorded

    on_disk = {
        str(path.relative_to(FIXTURE_DIR))
        for path in FIXTURE_DIR.rglob("*")
        if path.is_file() and path.name != "MANIFEST.sha256"
    }

    for relative in sorted(on_disk):
        digest = sha256_hex((FIXTURE_DIR / relative).read_bytes())
        assert relative in recorded, f"{relative} is not in the manifest"
        assert digest == recorded[relative], f"{relative} has drifted from openbox-core"

    for relative in sorted(recorded):
        assert relative in on_disk, f"{relative} is in the manifest but missing on disk"


def test_fixture_keypair_is_rsa2048_and_marked_non_production() -> None:
    keypair = read_fixture("keypair.json")

    assert "never deploy" in keypair["WARNING"]
    assert keypair["public_jwk"]["kty"] == "RSA"
    assert keypair["public_jwk"]["alg"] == "RS256"
    assert keypair["private_jwk"]["d"]

    def modulus_bits(jwk: dict) -> int:
        n = jwk["n"]
        padding = "=" * (-len(n) % 4)
        return len(base64.urlsafe_b64decode(n + padding)) * 8

    assert modulus_bits(keypair["public_jwk"]) >= 2048
    assert modulus_bits(keypair["undersized_key_for_negative_test"]["public_jwk"]) < 2048
