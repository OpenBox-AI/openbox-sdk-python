"""Lifecycle error wire compatibility with Core's ErrorInfo contract."""

from copy import deepcopy
from types import MappingProxyType

import pytest

from openbox_core.contracts.events import activity_completed, workflow_failed


@pytest.fixture(params=[workflow_failed, activity_completed], ids=["workflow", "activity"])
def make_event(request):
    def build(**kwargs):
        fields = {"workflow_id": "wf", "run_id": "run", "workflow_type": "Demo"}
        if request.param is activity_completed:
            fields.update(activity_id="llm", activity_type="llm_call")
        return request.param(**fields, **kwargs)

    return build


@pytest.mark.parametrize("message", ["Original LLM exception", ""])
def test_string_error_uses_core_error_info_shape(make_event, message):
    # A JSON string is rejected by Go's *ErrorInfo decoder before evaluation.
    payload = make_event(error=message).to_payload_dict()
    assert payload["error"] == {"type": "Exception", "message": message}


def test_structured_error_preserves_core_fields_without_mutation(make_event):
    error = {
        "type": "APIConnectionError",
        "message": "Connection failed",
        "stack_trace": "original stack",
        "cause": {"type": "TimeoutError", "message": "Request timed out"},
        "error_type": "provider_connection",
        "non_retryable": False,
    }
    original = deepcopy(error)
    payload = make_event(error=MappingProxyType(error)).to_payload_dict()
    assert payload["error"] == original
    assert error == original
    assert payload["error"] is not error


def test_success_omits_error(make_event):
    assert "error" not in make_event().to_payload_dict()
    assert "error" not in make_event(error=None).to_payload_dict()
