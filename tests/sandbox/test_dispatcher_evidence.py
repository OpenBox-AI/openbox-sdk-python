import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from openbox_sandbox.dispatcher.command import GovernedCommand
from openbox_sandbox.dispatcher.dispatcher import GovernedDispatcher, _sandbox_completed_hook
from openbox_sandbox.dispatcher.governance import GovernanceDecision
from openbox_sandbox.dispatcher.result import (
    CleanupStatus,
    Directive,
    DispatchResult,
    Disposition,
    ExecutionMetadata,
    TimeoutStatus,
)
from openbox_sandbox.runtime_client import AssetBundleIdentity, PolicyIdentity
from openbox_sandbox.runtime_client.types import EgressDecisionEvidence


def _completed_hook(template: str, *, parent_span_id: str | None = "00f067aa0ba902b7") -> dict:
    command = GovernedCommand(
        workflow_id="workflow-1",
        run_id="run-1",
        activity_id="activity-1",
        workflow_type="PaymentWorkflow",
        task_queue="payment-demo",
        profile_id="post-batch",
        argv=("/usr/bin/curl", "https://example.com/"),
        parent_span_id=parent_span_id,
    )
    result = DispatchResult(
        disposition=Disposition.EXECUTED_IN_SANDBOX,
        directive=Directive.CONTINUE,
        execution=ExecutionMetadata(
            sandbox_id="sbx-1",
            exit_code=0,
            stdout=b'{"http_status":200}',
            stderr=b"",
            timeout_status=TimeoutStatus.NOT_OBSERVED,
            cleanup_status=CleanupStatus.DELETED,
            egress_decisions=(
                EgressDecisionEvidence("denied", "blocked.example", 443),
                EgressDecisionEvidence("allowed", "api.example", 8443),
            ),
            violation_count=2,
            violation_categories=("denied_network", "denied_file_write"),
        ),
        error=None,
        _governance=None,
    )
    bundle = AssetBundleIdentity(
        runtime_contract_version=1,
        adapter_build_sha256="a" * 64,
        template=template,
        policy=PolicyIdentity("openbox-allow-network-dev", 1, "b" * 64),
        compatibility_id="native-srt-v1",
    )
    config = SimpleNamespace(
        sandbox=SimpleNamespace(asset_bundle=bundle),
        profiles=SimpleNamespace(bundle_version="profiles-1"),
    )
    return _sandbox_completed_hook(
        command,
        result,
        config,
        started_ns=1_000_000_000,
        completed_ns=1_000_000_001,
    )


def test_dispatch_identity_is_stable_per_attempt_and_profile() -> None:
    values = {
        "workflow_id": "workflow-1",
        "run_id": "run-1",
        "activity_id": "activity-1",
        "profile_id": "post-batch",
        "argv": ("/usr/bin/true",),
    }
    first = GovernedCommand(**values)
    duplicate = GovernedCommand(**values)
    retry = GovernedCommand(**values, attempt=2)

    assert duplicate.dispatch_id == first.dispatch_id
    assert retry.dispatch_id != first.dispatch_id
    assert duplicate.attempt == 1
    assert retry.attempt == 2


@pytest.mark.asyncio
async def test_duplicate_dispatch_identity_executes_once() -> None:
    values = {
        "workflow_id": "workflow-1",
        "run_id": "run-1",
        "activity_id": "activity-1",
        "profile_id": "post-batch",
        "argv": ("/usr/bin/true",),
    }
    command = GovernedCommand(**values)
    duplicate = GovernedCommand(**values)
    decision = GovernanceDecision.parse(
        {
            "governance_event_id": "00000000-0000-4000-8000-000000000001",
            "verdict": "constrain",
            "risk_score": 0.0,
            "action": "constrain",
            "fallback_used": False,
            "constraints": ["run_in_sandbox"],
        }
    )
    expected = SimpleNamespace(disposition="executed_in_sandbox")
    dispatcher = GovernedDispatcher.__new__(GovernedDispatcher)
    dispatcher._dispatch_tasks = {}
    dispatcher._dispatch_decision = AsyncMock(return_value=expected)

    left, right = await asyncio.gather(
        dispatcher._dispatch_decision_once(command, decision, report_core=False),
        dispatcher._dispatch_decision_once(duplicate, decision, report_core=False),
    )

    assert left is expected
    assert right is expected
    dispatcher._dispatch_decision.assert_awaited_once()


def test_native_srt_completion_emits_persistable_sandbox_hook() -> None:
    event = _completed_hook("native://srt")

    assert event["event_type"] == "ActivityStarted"
    assert event["hook_trigger"] is True
    assert event["span_count"] == 1
    span = event["spans"][0]
    assert span["name"] == "openbox.sandbox_execution"
    assert span["hook_type"] == "sandbox_execution"
    assert span["stage"] == "completed"
    assert span["parent_span_id"] == "00f067aa0ba902b7"
    assert span["attributes"]["openbox.sandbox.provider"] == "srt"
    assert span["attributes"]["openbox.sandbox.profile_id"] == "post-batch"
    assert span["attributes"]["openbox.sandbox.dispatch_id"] == (
        "30d35aa3252c8c9e8602c85bddaefa7687b0f73e1f7a6d810ed5ca81bc3fd522"
    )
    assert (
        span["attributes"]["openbox.sandbox.disposition"]
        == "executed_in_sandbox"
    )
    assert "openbox.sandbox.image_digest" not in span["attributes"]
    assert span["attributes"]["openbox.sandbox.egress.count"] == 2
    assert span["attributes"]["openbox.sandbox.egress.0.decision"] == "denied"
    assert span["attributes"]["openbox.sandbox.egress.0.host"] == "blocked.example"
    assert span["attributes"]["openbox.sandbox.egress.0.port"] == 443
    assert span["attributes"]["openbox.sandbox.violations.count"] == 2
    assert span["attributes"]["openbox.sandbox.violations.categories"] == (
        "denied_network,denied_file_write"
    )


def test_completion_derives_stable_activity_parent_without_adapter_context() -> None:
    first = _completed_hook("native://srt", parent_span_id=None)
    second = _completed_hook("native://srt", parent_span_id=None)

    parent_span_id = first["spans"][0]["parent_span_id"]
    assert parent_span_id == second["spans"][0]["parent_span_id"]
    assert isinstance(parent_span_id, str)
    assert len(parent_span_id) == 16


def test_openshell_completion_keeps_immutable_image_evidence() -> None:
    event = _completed_hook("registry.invalid/openbox@sha256:" + "c" * 64)
    attributes = event["spans"][0]["attributes"]

    assert attributes["openbox.sandbox.provider"] == "openshell"
    assert attributes["openbox.sandbox.image_digest"] == "sha256:" + "c" * 64
