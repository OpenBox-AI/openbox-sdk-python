"""PROD-1112: the withheld list is for the adapter, never for the agent."""

from openbox_core import WITHHELD_NOTICE, notify_withheld, on_withheld_notice, withheld_notice
from openbox_core.contracts.results import EvaluationResult, Withheld


def test_withheld_is_parsed_and_stripped_from_raw():
    r = EvaluationResult.from_dict(
        {"verdict": "allow", "withheld": {"uris": ["dms://pepsi/1"], "notify_user": True}}
    )
    assert r.withheld == Withheld(uris=("dms://pepsi/1",), notify_user=True)
    assert "withheld" not in r.raw


def test_notice_off_unless_the_firm_set_it():
    r = EvaluationResult.from_dict({"verdict": "allow", "withheld": {"uris": ["dms://a"]}})
    assert r.withheld == Withheld(uris=("dms://a",), notify_user=False)


def test_a_refusal_never_carries_withheld():
    r = EvaluationResult.from_dict({"verdict": "block", "withheld": {"uris": ["dms://a"]}})
    assert r.withheld is None
    assert "withheld" not in r.raw


def test_malformed_or_absent_is_none():
    for bad in (None, [], {"uris": "x"}, {"uris": []}, {"uris": [1, ""]}):
        assert EvaluationResult.from_dict({"verdict": "allow", "withheld": bad}).withheld is None
    assert EvaluationResult.from_dict({"verdict": "allow"}).withheld is None


def test_notice_goes_to_the_host_only_when_asked():
    seen: list[str] = []
    assert notify_withheld(True) is False  # nobody listening
    with withheld_notice(seen.append):
        assert notify_withheld(False) is False
        assert notify_withheld(True) is True
    assert seen == [WITHHELD_NOTICE]
    on_withheld_notice(seen.append)
    try:
        assert notify_withheld(True) is True
    finally:
        on_withheld_notice(None)
    assert seen == [WITHHELD_NOTICE, WITHHELD_NOTICE]
    assert "withheld" in WITHHELD_NOTICE.lower() and ":" not in WITHHELD_NOTICE
