from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path

from openbox_sandbox.runtime import (
    AssetBundleIdentity,
    ExecCompleted,
    ExecRequest,
    OutputLimits,
    PolicyDocument,
    PolicyIdentity,
    ProtocolValidationError,
    SandboxRuntimeClientConfig,
    SandboxServiceTransportError,
    TransportFailureCode,
    capability_token,
    request_owned_id,
)
from openbox_sandbox.runtime.client import _decode_response


class ProtocolTests(unittest.TestCase):
    def policy(self) -> PolicyIdentity:
        return PolicyIdentity("deny-network", 1, "b" * 64)

    def bundle(self) -> AssetBundleIdentity:
        return AssetBundleIdentity(
            runtime_contract_version=1,
            adapter_build_sha256="a" * 64,
            template="registry.invalid/sandbox@sha256:" + "c" * 64,
            policy=self.policy(),
            compatibility_id="linux-arm64-v1",
        )

    def test_exact_argv_and_binary_fields_round_trip_without_repr_leak(self) -> None:
        request = ExecRequest(
            ["/bin/proof", "", "space value", "$HOME", "雪"],
            30,
            OutputLimits(64, 64, 96, 128),
        )
        self.assertEqual(
            request.to_wire()["argv"],
            ["/bin/proof", "", "space value", "$HOME", "雪"],
        )
        self.assertNotIn("/bin/proof", repr(request))

        result = ExecCompleted.from_wire(
            {
                "exit_code": 7,
                "stdout_base64": base64.b64encode(b"\x00\xff").decode("ascii"),
                "stderr_base64": base64.b64encode(b"\xfe\x00").decode("ascii"),
                "timeout": "not_observed",
            }
        )
        self.assertEqual(result.stdout, b"\x00\xff")
        self.assertEqual(result.stderr, b"\xfe\x00")
        self.assertNotIn("xff", repr(result))

    def test_invalid_identifiers_base64_and_unknown_result_fields_fail_closed(self) -> None:
        with self.assertRaises(ProtocolValidationError):
            request_owned_id("sbx-not-a-uuid")
        with self.assertRaises(ProtocolValidationError):
            capability_token("00000000-0000-1000-8000-000000000000")
        with self.assertRaises(ProtocolValidationError):
            ExecCompleted.from_wire(
                {
                    "exit_code": -1,
                    "stdout_base64": "***",
                    "stderr_base64": "",
                    "timeout": "unknown",
                }
            )
        with self.assertRaises(ProtocolValidationError):
            ExecCompleted.from_wire(
                {
                    "exit_code": 0,
                    "stdout_base64": "",
                    "stderr_base64": "",
                    "timeout": "not_observed",
                    "unexpected": True,
                }
            )
        with self.assertRaises(ProtocolValidationError):
            ExecCompleted.from_wire(
                {
                    "exit_code": True,
                    "stdout_base64": "",
                    "stderr_base64": "",
                    "timeout": "not_observed",
                }
            )
        with self.assertRaises(ProtocolValidationError):
            OutputLimits(1024 * 1024 + 1, 1, 1, 1)
        with self.assertRaises(ProtocolValidationError):
            OutputLimits(True, 1, 1, 1)
        with self.assertRaises(ProtocolValidationError):
            ExecRequest(["/bin/proof\x00hidden"], 30, OutputLimits(1, 1, 1, 1))
        with self.assertRaises(ProtocolValidationError):
            ExecRequest(["/bin/proof"], True, OutputLimits(1, 1, 1, 1))

    def test_response_version_operation_and_duplicate_fields_are_strict(self) -> None:
        operation = "550e8400-e29b-41d4-a716-446655440000"
        body = json.dumps(
            {
                "protocol_version": 1,
                "operation_id": operation,
                "response": {"response": "terminally_absent"},
            }
        ).encode()
        response = _decode_response(body, operation)
        self.assertEqual(response.response, "terminally_absent")

        for invalid in [
            body.replace(b'"protocol_version": 1', b'"protocol_version": 2'),
            body.replace(operation.encode(), b"550e8400-e29b-41d4-a716-446655440001"),
            b'{"protocol_version":1,"protocol_version":1,"operation_id":"'
            + operation.encode()
            + b'","response":{"response":"health"}}',
        ]:
            with self.assertRaises(SandboxServiceTransportError) as captured:
                _decode_response(invalid, operation)
            self.assertEqual(captured.exception.code, TransportFailureCode.PROTOCOL)

    def test_bundle_policy_document_and_config_validation(self) -> None:
        document = PolicyDocument("application/yaml", b"version: 1\n")
        self.assertNotIn("version: 1", repr(document))
        self.assertEqual(
            document.to_wire()["document_base64"],
            base64.b64encode(b"version: 1\n").decode("ascii"),
        )
        config = SandboxRuntimeClientConfig(
            host="127.0.0.1",
            port=7443,
            server_name="sandbox.service.local",
            ca_path=Path("/sensitive/ca"),
            certificate_path=Path("/sensitive/cert"),
            private_key_path=Path("/sensitive/key"),
            asset_bundle=self.bundle(),
        )
        self.assertNotIn("/sensitive", repr(config))
        with self.assertRaises(ProtocolValidationError):
            SandboxRuntimeClientConfig(
                host="192.0.2.1",
                port=7443,
                server_name="sandbox.service.local",
                ca_path=Path("ca"),
                certificate_path=Path("cert"),
                private_key_path=Path("key"),
                asset_bundle=self.bundle(),
            )


if __name__ == "__main__":
    unittest.main()
