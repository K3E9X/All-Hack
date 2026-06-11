"""Credential-spray pure logic: field detection, success heuristic, body build."""
from app.exploit.auth_brute import (DEFAULT_CREDS, _is_session_cookie,
                                     _parse_body, detect_login_fields, is_success)


def test_detect_login_fields():
    assert detect_login_fields(["username", "password", "csrf"]) == ("username", "password")
    assert detect_login_fields(["email", "passwd"]) == ("email", "passwd")
    assert detect_login_fields(["foo", "bar"]) is None
    assert detect_login_fields(["username"]) is None  # needs both


def test_session_cookie_detection():
    assert _is_session_cookie("PHPSESSID=abc; HttpOnly")
    assert _is_session_cookie("auth_token=xyz")
    assert not _is_session_cookie("theme=dark")


def test_is_success_redirect():
    base = {"status": 200, "session_cookie": False}
    assert is_success(base, {"status": 302, "session_cookie": False})
    assert not is_success(base, {"status": 200, "session_cookie": False})


def test_is_success_status_flip():
    assert is_success({"status": 401, "session_cookie": False},
                      {"status": 200, "session_cookie": False})


def test_is_success_new_session_cookie():
    base = {"status": 200, "session_cookie": False}
    assert is_success(base, {"status": 200, "session_cookie": True})


def test_parse_body_form_and_json():
    assert _parse_body("user=a&password=b", is_json=False) == {"user": "a", "password": "b"}
    assert _parse_body('{"user":"a","password":"b"}', is_json=True) == {"user": "a", "password": "b"}


def test_default_creds_are_spray_not_brute():
    # a short, curated default list (spray), not a brute wordlist
    assert 5 <= len(DEFAULT_CREDS) <= 25
    assert ("admin", "admin") in DEFAULT_CREDS
