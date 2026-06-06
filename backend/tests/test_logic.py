"""IDOR id-finding, privileged-path detection and CSRF heuristics."""
from app.analysis.logic import (
    _detect_csrf,
    _find_numeric_id,
    _is_privileged,
    _is_static,
    _neighbour,
)


def test_neighbour():
    assert _neighbour("5") == "4"
    assert _neighbour("1") == "2"
    assert _neighbour("abc") == "abc"


def test_find_numeric_id_in_path():
    loc, orig, modified = _find_numeric_id("https://t/users/5/profile")
    assert loc == "path" and orig == "5"
    assert "/users/4/profile" in modified


def test_find_numeric_id_in_query():
    loc, orig, modified = _find_numeric_id("https://t/item?id=10&x=1")
    assert loc == "query:id" and orig == "10"
    assert "id=9" in modified


def test_find_numeric_id_none():
    assert _find_numeric_id("https://t/about") is None


def test_is_privileged():
    assert _is_privileged("https://t/admin/users")
    assert _is_privileged("https://t/api/admin/x")
    assert not _is_privileged("https://t/profile")


def test_is_static():
    assert _is_static("https://t/app.js")
    assert not _is_static("https://t/api/data")


def _full(headers, method="POST", body_text=None):
    body = {"encoding": "text", "text": body_text} if body_text is not None else {}
    return {"request_headers": headers, "method": method, "request_body_preview": body}


def test_csrf_detected_for_cookie_without_token():
    full = _full([["Cookie", "session=abc"]])
    assert _detect_csrf(full) is not None


def test_csrf_skipped_for_bearer_auth():
    full = _full([["Authorization", "Bearer xyz"], ["Cookie", "session=abc"]])
    assert _detect_csrf(full) is None


def test_csrf_skipped_when_csrf_header_present():
    full = _full([["Cookie", "session=abc"], ["X-CSRF-Token", "t"]])
    assert _detect_csrf(full) is None


def test_csrf_skipped_when_token_in_body():
    full = _full([["Cookie", "session=abc"]], body_text='{"csrf_token":"t"}')
    assert _detect_csrf(full) is None


def test_csrf_skipped_without_cookie():
    full = _full([["Content-Type", "application/json"]])
    assert _detect_csrf(full) is None
