"""Hidden-parameter discovery helpers: harvesting, candidate building,
reflection detection and URL seeding."""
from app.analysis.param_discovery import (
    _body_keys,
    _candidate_list,
    _query_keys,
    _reflected,
    _with_params,
)


def test_query_keys():
    assert set(_query_keys("https://t/x?a=1&b=2&a=3")) == {"a", "b"}
    assert _query_keys("https://t/x") == []


def test_body_keys_json():
    full = {"request_content_type": "application/json",
            "request_body_preview": {"encoding": "text", "text": '{"name":1,"role":"x"}'}}
    assert set(_body_keys(full)) == {"name", "role"}


def test_body_keys_form():
    full = {"request_content_type": "application/x-www-form-urlencoded",
            "request_body_preview": {"encoding": "text", "text": "user=a&pass=b"}}
    assert set(_body_keys(full)) == {"user", "pass"}


def test_body_keys_non_text():
    assert _body_keys({"request_body_preview": {}}) == []


def test_candidate_list_prioritises_harvested_and_dedupes():
    cands = _candidate_list({"custom_param", "id"})
    assert "custom_param" in cands
    # harvested names come before the common list
    assert cands.index("custom_param") < cands.index("page")
    # de-duped even though "id" is also in the common list
    assert cands.count("id") == 1


def test_reflected_detects_only_present_markers():
    markers = {"a": "axhk111", "b": "axhk222", "c": "axhk333"}
    text = "page contains axhk111 and axhk333 somewhere"
    assert set(_reflected(markers, text)) == {"a", "c"}


def test_with_params_builds_query():
    seeded = _with_params("https://t/search", ["q", "page"])
    assert seeded.startswith("https://t/search?")
    assert "q=1" in seeded and "page=1" in seeded
