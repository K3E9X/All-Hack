"""JavaScript mining: hidden endpoints + leaked secrets (Tier-1 recon).

Modern apps ship their whole API surface and, too often, live credentials in
their JS bundles. Scanners pointed at a URL never read those bundles; this does.

We pull every in-scope JavaScript response captured through the proxy and:
  * extract API endpoints / paths referenced in the code (fetch/axios/url
    literals) -> unique attack surface that feeds the rest of the engagement;
  * extract secrets (cloud keys, tokens, private keys, basic-auth URLs) with
    a curated set of high-signal regexes (the same families gitleaks/trufflehog
    look for) -> often the single highest-value finding on a target.

Everything is read-only: we only parse bodies already captured. Discovered
endpoints are also seeded as engagement assets so later phases test them.

Stored as a synthetic job (tool="js-recon").
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.proxy import FlowRepository
from app.scans.models import Finding

logger = logging.getLogger("allhack.analysis.js_recon")

MAX_JS_FLOWS = 200
MAX_BODY = 2 * 1024 * 1024

# High-signal secret patterns. (name, regex, severity). Kept deliberately tight
# to minimise false positives - generic "password=" style matches are noisy.
_SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]", str]] = [
    ("AWS access key id", re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"), "high"),
    ("AWS secret access key", re.compile(r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z/+]{40})['\"]"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{20,}\b"), "high"),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), "critical"),
    ("Stripe restricted key", re.compile(r"\brk_live_[0-9a-zA-Z]{20,}\b"), "high"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "medium"),
    ("Twilio account SID", re.compile(r"\bAC[0-9a-fA-F]{32}\b"), "medium"),
    ("SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"), "high"),
    ("Mailgun key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "medium"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical"),
    ("Firebase database URL", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), "low"),
    ("Basic-auth credentials in URL", re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"), "high"),
    ("Generic API key/secret assignment",
     re.compile(r"(?i)(?:api[_-]?key|api[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{16,})['\"]"),
     "medium"),
]

# Endpoint references inside JS: string literals that look like a path or URL.
_ENDPOINT_RE = re.compile(r"""['"`](/(?:api|v\d|rest|graphql|admin|internal|user|account|auth)[A-Za-z0-9_\-/.?=&{}:]*)['"`]""")
_FULLURL_RE = re.compile(r"""['"`](https?://[A-Za-z0-9.\-]+/[A-Za-z0-9_\-/.?=&{}:]*)['"`]""")

# Don't flag obvious framework / library noise as a secret-bearing endpoint.
_NOISE = ("/api/placeholder", "schema.org", "w3.org", "googleapis.com/css")


async def analyze_js(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    flows_repo = FlowRepository()
    summaries = await flows_repo.list_flows(limit=1000)
    js_flows = [
        f for f in summaries
        if eng.host_in_scope((urlparse(f.url).hostname or "").lower())
        and _looks_like_js(f)
    ][:MAX_JS_FLOWS]

    findings: List[Finding] = []
    endpoints: set[str] = set()
    secrets_seen: set[str] = set()

    for f in js_flows:
        full = await flows_repo.get_flow(f.id)
        if not full:
            continue
        body = full.get("response_body_preview") or {}
        if body.get("encoding") != "text":
            continue
        text = (body.get("text") or "")[:MAX_BODY]
        if not text:
            continue

        # ---- secrets ----
        for name, pattern, severity in _SECRET_PATTERNS:
            for m in pattern.finditer(text):
                raw = m.group(0)
                key = f"{name}:{raw[:60]}"
                if key in secrets_seen:
                    continue
                secrets_seen.add(key)
                findings.append(Finding(
                    severity=severity,
                    title=f"Secret leaked in JavaScript: {name}",
                    description=f"A {name} appears in client-side JavaScript served at {f.url}.",
                    target=f.url,
                    evidence=f"{name} found in {f.url}\n  match: {_redact(raw)}",
                    metadata={"vuln_class": "secret_exposure", "status": "confirmed",
                              "confidence": 0.9, "secret_type": name, "source": f.url},
                ))

        # ---- endpoints ----
        for m in _ENDPOINT_RE.finditer(text):
            endpoints.add(m.group(1))
        for m in _FULLURL_RE.finditer(text):
            u = m.group(1)
            if eng.host_in_scope((urlparse(u).hostname or "").lower()):
                endpoints.add(u)

    endpoints = {e for e in endpoints if not any(n in e for n in _NOISE)}

    # One roll-up finding listing the discovered surface (info).
    if endpoints:
        sample = sorted(endpoints)[:80]
        findings.append(Finding(
            severity="info",
            title=f"{len(endpoints)} endpoint(s) discovered in JavaScript",
            description="Endpoints/paths referenced in client-side JS - additional "
                        "attack surface not necessarily linked from the UI.",
            target=eng.target_url,
            evidence="\n".join(sample) + ("\n..." if len(endpoints) > len(sample) else ""),
            metadata={"vuln_class": "endpoint_discovery", "status": "unconfirmed",
                      "confidence": 0.3, "count": len(endpoints)},
        ))

    await save_analysis_job(engagement_id, "js-recon", findings, target="(javascript bundles)")

    # Seed in-scope endpoints as assets so later phases test the new surface.
    seeded = await _seed_endpoints(engagement_id, eng, endpoints)

    secret_n = sum(1 for x in findings if x.metadata.get("vuln_class") == "secret_exposure")
    logger.info("[%s] js-recon: js_flows=%d secrets=%d endpoints=%d seeded=%d",
                engagement_id, len(js_flows), secret_n, len(endpoints), seeded)
    return {"js_flows": len(js_flows), "secrets": secret_n,
            "endpoints": len(endpoints), "seeded": seeded}


def _looks_like_js(flow) -> bool:
    ct = (flow.response_content_type or "").lower()
    if "javascript" in ct or "ecmascript" in ct:
        return True
    path = urlparse(flow.url).path.lower()
    return path.endswith(".js") or path.endswith(".mjs")


def _redact(raw: str) -> str:
    """Show enough to identify the secret, not enough to fully expose it."""
    raw = raw.strip()
    if len(raw) <= 12:
        return raw[:4] + "***"
    return raw[:8] + "..." + raw[-4:]


async def _seed_endpoints(engagement_id: str, eng, endpoints: set) -> int:
    """Add discovered same-origin endpoints to the engagement state as assets."""
    try:
        from app.orchestrator.state import EngagementState
    except Exception:  # noqa: BLE001
        return 0
    state = EngagementState(engagement_id)
    base = eng.target_url
    count = 0
    for ep in endpoints:
        if count >= 200:
            break
        url = ep if ep.startswith("http") else urljoin(base, ep)
        host = (urlparse(url).hostname or "").lower()
        if not eng.host_in_scope(host):
            continue
        try:
            await state.add_asset("endpoint", url, source="js")
            count += 1
        except Exception:  # noqa: BLE001
            continue
    return count
