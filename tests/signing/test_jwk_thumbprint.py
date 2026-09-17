"""RFC 7638 JWK thumbprint tests.

The pinned vector here is identical to the one in openbox-core and
openbox-sdk-ts, against byte-identical copies of the same fixture keypair. That
is the cross-repo agreement the bootstrap flow depends on: Core computes the
thumbprint from the stored public JWK, each SDK computes it from its local
private key, and the two are compared before any governed request. A
canonicalization drift in any of the three repos must fail a test rather than
silently break every bootstrapping client.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from openbox_core.errors import OpenBoxConfigError
from openbox_core.jwk_thumbprint import jwk_thumbprint_sha256, thumbprints_match

FIXTURE_DIR = pathlib.Path(__file__).parent / "identity_v2"

# Pinned, never re-derived from the code under test.
FIXTURE_THUMBPRINT = "P8EMAIrSnD-kQcn47Cpq_LlDPywhP3mqfM1RhwySFdk"
FIXTURE_UNDERSIZED_THUMBPRINT = "mvZ_gJ0t0lSgT1112pD9yjrvBBi0-20HzVE7nzfz41c"


def _b64url_to_int(segment: str) -> int:
    padding = "=" * (-len(segment) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(segment + padding), "big")


def _keypair() -> dict:
    return json.loads((FIXTURE_DIR / "keypair.json").read_text())


def _private_key_from_jwk(jwk: dict) -> rsa.RSAPrivateKey:
    numbers = rsa.RSAPrivateNumbers(
        p=_b64url_to_int(jwk["p"]),
        q=_b64url_to_int(jwk["q"]),
        d=_b64url_to_int(jwk["d"]),
        dmp1=_b64url_to_int(jwk["dp"]),
        dmq1=_b64url_to_int(jwk["dq"]),
        iqmp=_b64url_to_int(jwk["qi"]),
        public_numbers=rsa.RSAPublicNumbers(
            e=_b64url_to_int(jwk["e"]), n=_b64url_to_int(jwk["n"])
        ),
    )
    return numbers.private_key()


class TestJwkThumbprintSha256:
    def test_matches_pinned_cross_repo_vector(self):
        key = _private_key_from_jwk(_keypair()["private_jwk"])
        assert jwk_thumbprint_sha256(key) == FIXTURE_THUMBPRINT

    def test_matches_rfc7638_reference_vector(self):
        """RFC 7638 §3.1's own published example, through the real function.

        Independent of the fixture: proves the implementation follows the
        standard, so a mistake replicated across all three repos — an added
        member, a lost sort, a different separator — is still caught here.
        """
        n = (
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1"
            "L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4"
            "QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbO"
            "pbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csF"
            "Cur-kEgU8awapJzKnqDKgw"
        )
        public_key = rsa.RSAPublicNumbers(
            e=_b64url_to_int("AQAB"), n=_b64url_to_int(n)
        ).public_key()

        assert jwk_thumbprint_sha256(public_key) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

    def test_private_and_public_halves_agree(self):
        """The same key must hash identically whichever half is supplied.

        This is what makes the cross-repo comparison sound: Core hashes the stored
        public JWK, the SDK hashes its local private key, and the two must meet.
        """
        private_key = _private_key_from_jwk(_keypair()["private_jwk"])
        assert jwk_thumbprint_sha256(private_key) == FIXTURE_THUMBPRINT
        assert jwk_thumbprint_sha256(private_key.public_key()) == FIXTURE_THUMBPRINT

    def test_distinguishes_different_keys(self):
        undersized = _private_key_from_jwk(
            _keypair()["undersized_key_for_negative_test"]["private_jwk"]
        )
        assert jwk_thumbprint_sha256(undersized) == FIXTURE_UNDERSIZED_THUMBPRINT
        assert jwk_thumbprint_sha256(undersized) != FIXTURE_THUMBPRINT

    def test_encoding_is_unpadded_base64url(self):
        thumbprint = jwk_thumbprint_sha256(_private_key_from_jwk(_keypair()["private_jwk"]))

        assert "=" not in thumbprint
        assert "+" not in thumbprint
        assert "/" not in thumbprint
        assert len(base64.urlsafe_b64decode(thumbprint + "=")) == 32

    def test_rejects_non_rsa_key(self):
        with pytest.raises(OpenBoxConfigError) as excinfo:
            jwk_thumbprint_sha256(ed25519.Ed25519PrivateKey.generate())
        # Never echoes key material.
        assert "key bytes not shown" in str(excinfo.value)


class TestThumbprintsMatch:
    def test_true_for_identical_values(self):
        assert thumbprints_match(FIXTURE_THUMBPRINT, FIXTURE_THUMBPRINT) is True

    def test_false_for_different_values(self):
        assert thumbprints_match(FIXTURE_THUMBPRINT, FIXTURE_UNDERSIZED_THUMBPRINT) is False

    def test_returns_false_never_raises_on_length_mismatch(self):
        assert thumbprints_match(FIXTURE_THUMBPRINT, "short") is False
        assert thumbprints_match("", FIXTURE_THUMBPRINT) is False
        assert thumbprints_match("", "") is True

    def test_detects_single_character_difference(self):
        tampered = FIXTURE_THUMBPRINT[:-1] + "X"
        assert len(tampered) == len(FIXTURE_THUMBPRINT)
        assert thumbprints_match(FIXTURE_THUMBPRINT, tampered) is False
