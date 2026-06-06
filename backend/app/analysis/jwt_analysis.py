"""JWT weakness analysis over captured traffic (Tier-1, high signal).

We already capture authenticated traffic through the proxy; JSON Web Tokens
appear in Authorization headers, cookies and bodies. A weak token is frequently
a one-step account takeover, so this is high-value and low-noise.

For every distinct JWT we see we check, entirely offline (no requests sent):
  * alg=none            -> signature can be stripped (critical).
  * HS256/384/512       -> try to crack the HMAC secret against a small list of
                           common/default secrets (safe, local) -> forge any token.
  * kid / jku / x5u     -> header injection surface (algorithm confusion / SSRF).
  * missing exp         -> token never expires.
  * sensitive claims    -> role/admin/scope present -> tampering target.

Stored as a synthetic job (tool="jwt").
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.proxy import FlowRepository
from app.scans.models import Finding

logger = logging.getLogger("allhack.analysis.jwt")

MAX_FLOWS = 1000
MAX_BODY = 256 * 1024
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{2,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")

# Small, safe wordlist of common/default HMAC secrets (local brute force only).
_COMMON_SECRETS = [
    "secret", "secretkey", "secret_key", "jwt_secret", "jwtsecret", "your-256-bit-secret",
    "password", "changeme", "admin", "test", "key", "private", "mysecret", "supersecret",
    "123456", "qwerty", "token", "jwt", "auth", "default", "s3cr3t", "Sn1f", "0",
    "your_jwt_secret", "JWT_SECRET", "secretKey", "shhhh", "topsecret", "p@ssw0rd",
    "HS256", "secret123", "access_token_secret", "refreshsecret", "node", "express",
]

_SENSITIVE_CLAIMS = ("role", "roles", "admin", "is_admin", "isadmin", "scope",
                     "scopes", "permissions", "authorities", "grp", "group", "tier")


async def analyze_jwt(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    flows_repo = FlowRepository()
    summaries = await flows_repo.list_flows(limit=MAX_FLOWS)
    from urllib.parse import urlparse
    in_scope = [f for f in summaries
                if eng.host_in_scope((urlparse(f.url).hostname or "").lower())]

    findings: List[Finding] = []
    seen: set[str] = set()

    for f in in_scope[:300]:
        full = await flows_repo.get_flow(f.id)
        if not full:
            continue
        for token in _collect_tokens(full):
            head, payload = _decode(token)
            if head is None:
                continue
            sig = token.split(".")[0]  # stable-enough dedupe key (header+alg)
            dedupe = sig + ":" + ",".join(sorted((payload or {}).keys()))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            findings.extend(_assess(token, head, payload or {}, f.url))

    await save_analysis_job(engagement_id, "jwt", findings, target="(JWT tokens)")

    crit = sum(1 for x in findings if x.severity in ("critical", "high"))
    logger.info("[%s] jwt: distinct=%d findings=%d (high/crit=%d)",
                engagement_id, len(seen), len(findings), crit)
    return {"jwt_tokens": len(seen), "findings": len(findings)}


# --------------------------------------------------------------------------- #

def _collect_tokens(full: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for hdrs in (full.get("request_headers") or [], full.get("response_headers") or []):
        for _n, v in hdrs:
            out.extend(_JWT_RE.findall(str(v)))
    for key in ("request_body_preview", "response_body_preview"):
        body = full.get(key) or {}
        if body.get("encoding") == "text":
            out.extend(_JWT_RE.findall((body.get("text") or "")[:MAX_BODY]))
    return out


def _b64url(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _decode(token: str) -> Tuple[Optional[dict], Optional[dict]]:
    try:
        h, p, _sig = token.split(".")
        header = json.loads(_b64url(h))
        payload = json.loads(_b64url(p))
        if not isinstance(header, dict):
            return None, None
        return header, payload if isinstance(payload, dict) else {}
    except Exception:  # noqa: BLE001
        return None, None


def _crack_hs(token: str) -> Optional[str]:
    """Try to recover an HMAC secret from a tiny common-secret list (offline)."""
    try:
        h, p, sig = token.split(".")
    except ValueError:
        return None
    signing_input = f"{h}.{p}".encode()
    try:
        want = _b64url(sig)
    except Exception:  # noqa: BLE001
        return None
    alg = (json.loads(_b64url(h)).get("alg") or "").upper()
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}.get(alg)
    if digest is None:
        return None
    for secret in _COMMON_SECRETS:
        mac = hmac.new(secret.encode(), signing_input, digest).digest()
        if hmac.compare_digest(mac, want):
            return secret
    return None


def _assess(token: str, header: dict, payload: dict, url: str) -> List[Finding]:
    out: List[Finding] = []
    alg = str(header.get("alg") or "").lower()
    short = token[:24] + "..."

    def mk(sev, vclass, title, desc, status, conf, poc=""):
        return Finding(severity=sev, title=title, description=desc, target=url,
                       evidence=poc or f"token {short} (alg={alg}) seen at {url}",
                       metadata={"vuln_class": vclass, "status": status,
                                 "confidence": conf, "alg": alg, "jwt_alg": alg})

    if alg in ("none", ""):
        out.append(mk("critical", "jwt", "JWT accepts alg=none",
                      "The token uses alg=none; an attacker can strip the signature "
                      "and forge arbitrary claims.", "likely", 0.7))

    if alg.startswith("hs"):
        secret = _crack_hs(token)
        if secret is not None:
            out.append(mk("critical", "jwt", "JWT signed with a weak/known HMAC secret",
                          f"The HS* signing secret was recovered offline ('{secret}'); "
                          "any token (incl. admin) can be forged.", "confirmed", 0.95,
                          poc=f"HMAC secret '{secret}' validates the signature of {short}."))

    if any(k in header for k in ("kid", "jku", "x5u")):
        keys = ", ".join(k for k in ("kid", "jku", "x5u") if k in header)
        out.append(mk("medium", "jwt", f"JWT header injection surface ({keys})",
                      "Header parameters that point at a key (kid/jku/x5u) can enable "
                      "algorithm confusion or SSRF to a key the attacker controls.",
                      "unconfirmed", 0.35))

    if "exp" not in payload:
        out.append(mk("low", "jwt", "JWT has no expiry (exp)",
                      "The token carries no exp claim; a leaked token is valid forever.",
                      "likely", 0.5))

    present = [c for c in _SENSITIVE_CLAIMS if c in payload]
    if present and not any(f.metadata.get("status") == "confirmed" for f in out):
        out.append(mk("info", "jwt", f"JWT carries authorization claims ({', '.join(present)})",
                      "Authorization decisions ride in the token; combined with any "
                      "signature weakness this is a privilege-escalation target.",
                      "unconfirmed", 0.3))
    return out
