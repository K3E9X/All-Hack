"""PoC parsing for the sandbox runner."""
from app.sandbox_util import parse_curl, parse_http_raw, parse_poc


def test_parse_curl_basic_get():
    m, u, h = parse_curl("curl -s 'https://t/?p=1'")
    assert m == "GET" and u == "https://t/?p=1"


def test_parse_curl_headers_and_method():
    m, u, h = parse_curl("curl -X POST -H 'Authorization: Bearer x' -H 'X-Y: z' https://t/api")
    assert m == "POST" and u == "https://t/api"
    assert h["Authorization"] == "Bearer x" and h["X-Y"] == "z"


def test_parse_curl_data_implies_post():
    m, u, _ = parse_curl("curl --data 'a=1' https://t/login")
    assert m == "POST" and u == "https://t/login"


def test_parse_http_raw():
    raw = "GET /v1/users/2 HTTP/1.1\nHost: api.t\nAuthorization: Bearer a\n\n"
    m, u, h = parse_http_raw(raw)
    assert m == "GET" and u == "https://api.t/v1/users/2"
    assert h["Authorization"] == "Bearer a"


def test_parse_poc_falls_back_to_target():
    m, u, h = parse_poc("curl", "curl -H 'A: b'", "https://t/x")
    assert u == "https://t/x" and h["A"] == "b"


def test_parse_poc_unknown_type():
    m, u, h = parse_poc("python", "print(1)", "https://t/x")
    assert u == "https://t/x" and m == "GET"
