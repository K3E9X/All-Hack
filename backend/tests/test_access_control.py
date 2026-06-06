"""Access-control analyzer helpers: auth detection, JSON-write detection,
body field extraction."""
from app.analysis.access_control import (
    _body_field_names,
    _is_json_write,
    _is_static,
    _was_authenticated,
)


def test_was_authenticated_bearer():
    assert _was_authenticated({"request_headers": [["Authorization", "Bearer abc"]]})


def test_was_authenticated_cookie():
    assert _was_authenticated({"request_headers": [["Cookie", "session=abcdef123"]]})


def test_not_authenticated():
    assert not _was_authenticated({"request_headers": [["Accept", "*/*"]]})
    # A trivially short cookie is not treated as a real session.
    assert not _was_authenticated({"request_headers": [["Cookie", "a=b"]]})


def test_is_json_write():
    assert _is_json_write({"request_content_type": "application/json"})
    assert not _is_json_write({"request_content_type": "text/html"})


def test_body_field_names():
    full = {"request_body_preview": {"encoding": "text",
                                     "text": '{"name":"a","role":"x","id":1}'}}
    fields = _body_field_names(full)
    assert set(fields) == {"name", "role", "id"}


def test_body_field_names_handles_non_json():
    assert _body_field_names({"request_body_preview": {"encoding": "text", "text": "not json"}}) == []
    assert _body_field_names({"request_body_preview": {}}) == []


def test_is_static():
    assert _is_static("https://t/main.css")
    assert not _is_static("https://t/api/users")
