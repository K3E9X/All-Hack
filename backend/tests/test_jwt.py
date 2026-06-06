"""JWT weakness detection: decode, offline HMAC crack, and the per-token
assessment (alg=none, weak secret, kid/jku, missing exp, sensitive claims)."""
import base64
import hashlib
import hmac
import json

from app.analysis.jwt_analysis import _assess, _crack_hs, _decode


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make_token(header: dict, payload: dict, secret: str | None = None) -> str:
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps(payload).encode())
    if secret is None:
        return f"{h}.{p}."
    sig = _b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def test_decode_valid_and_invalid():
    tok = _make_token({"alg": "HS256"}, {"sub": "1"}, secret="secret")
    header, payload = _decode(tok)
    assert header["alg"] == "HS256"
    assert payload["sub"] == "1"
    assert _decode("not.a.jwt") == (None, None)


def test_crack_finds_known_secret():
    tok = _make_token({"alg": "HS256"}, {"sub": "1"}, secret="secret")
    assert _crack_hs(tok) == "secret"


def test_crack_returns_none_for_strong_secret():
    tok = _make_token({"alg": "HS256"}, {"sub": "1"},
                      secret="9f3c1b7e-not-in-any-wordlist-xyz")
    assert _crack_hs(tok) is None


def _classes(findings):
    return [f.title for f in findings]


def test_alg_none_is_critical():
    tok = _make_token({"alg": "none"}, {"sub": "1"})
    findings = _assess(tok, {"alg": "none"}, {"sub": "1"}, "http://t/")
    assert any("alg=none" in t for t in _classes(findings))
    assert any(f.severity == "critical" for f in findings)


def test_weak_hmac_secret_is_confirmed():
    tok = _make_token({"alg": "HS256"}, {"sub": "1"}, secret="secret")
    findings = _assess(tok, {"alg": "HS256"}, {"sub": "1"}, "http://t/")
    weak = [f for f in findings if "HMAC" in f.title]
    assert weak and weak[0].metadata["status"] == "confirmed"
    assert weak[0].severity == "critical"


def test_kid_header_flagged():
    tok = _make_token({"alg": "HS256", "kid": "1"}, {"sub": "1"}, secret="x")
    findings = _assess(tok, {"alg": "HS256", "kid": "1"}, {"sub": "1"}, "http://t/")
    assert any("injection surface" in f.title for f in findings)


def test_missing_exp_flagged():
    tok = _make_token({"alg": "HS256"}, {"sub": "1"}, secret="x")
    findings = _assess(tok, {"alg": "HS256"}, {"sub": "1"}, "http://t/")
    assert any("no expiry" in f.title for f in findings)


def test_sensitive_claims_flagged_when_not_already_confirmed():
    payload = {"sub": "1", "role": "user", "exp": 9999999999}
    tok = _make_token({"alg": "HS256"}, payload, secret="x")  # strong-ish: not cracked
    findings = _assess(tok, {"alg": "HS256"}, payload, "http://t/")
    assert any("authorization claims" in f.title for f in findings)
