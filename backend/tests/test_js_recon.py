"""JS mining: secret patterns, endpoint extraction, redaction, JS detection."""
from types import SimpleNamespace

from app.analysis.js_recon import (
    _ENDPOINT_RE,
    _FULLURL_RE,
    _SECRET_PATTERNS,
    _looks_like_js,
    _redact,
)


def _detect_secret(text):
    return {name for name, pat, _sev in _SECRET_PATTERNS if pat.search(text)}


def test_detects_cloud_keys_and_private_key():
    # Build the sample secrets at runtime so no contiguous secret-looking
    # literal lives in the source (keeps secret scanners happy); the regexes
    # still see the assembled strings.
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    google = "AIza" + "Sy" + "A1234567890abcdefghijklmnopqrstuv"
    stripe = "sk_" + "live_" + "abcdef0123456789ABCDEF99"
    text = (
        f'k="{aws}";'
        f'g="{google}";'
        f's="{stripe}";'
        '-----BEGIN RSA PRIVATE KEY-----'
    )
    found = _detect_secret(text)
    assert "AWS access key id" in found
    assert "Google API key" in found
    assert "Stripe live secret key" in found
    assert "Private key block" in found


def test_generic_api_key_assignment():
    found = _detect_secret('const api_key = "abcdef0123456789ABCDEFxyz";')
    assert "Generic API key/secret assignment" in found


def test_basic_auth_in_url():
    found = _detect_secret('fetch("https://user:p4ssw0rd@internal.example/x")')
    assert "Basic-auth credentials in URL" in found


def test_no_false_positive_on_plain_code():
    assert _detect_secret('const total = items.length * 2;') == set()


def test_endpoint_extraction():
    text = 'fetch("/api/v1/users");axios.get("/admin/settings");x("/static/app")'
    eps = set(_ENDPOINT_RE.findall(text))
    assert "/api/v1/users" in eps
    assert "/admin/settings" in eps
    assert "/static/app" not in eps  # not an interesting prefix


def test_fullurl_extraction():
    text = 'const u = "https://api.example.com/internal/keys";'
    assert "https://api.example.com/internal/keys" in _FULLURL_RE.findall(text)


def test_redact_keeps_head_and_tail():
    r = _redact("AKIAIOSFODNN7EXAMPLE")
    assert r.startswith("AKIAIOSF") and r.endswith("MPLE") and "..." in r


def test_looks_like_js():
    assert _looks_like_js(SimpleNamespace(url="https://t/app.js", response_content_type=None))
    assert _looks_like_js(SimpleNamespace(url="https://t/x", response_content_type="application/javascript"))
    assert not _looks_like_js(SimpleNamespace(url="https://t/data", response_content_type="application/json"))
