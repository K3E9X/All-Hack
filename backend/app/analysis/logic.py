"""Application-logic analysis over captured proxy traffic (IDOR + CSRF).

These classes can't be found by scanners pointed at a URL: they need real
authenticated requests. So we analyze the flows the operator captured through
the MITM proxy (while logged in) and look for:

  * IDOR / BOLA - GET requests whose path/query carry an object identifier.
    We confirm *safely* by re-requesting a neighbouring id through the
    in-scope, read-only SafePoC channel: a 200 on an id you were never given
    is a strong access-control signal; a 401/403/404 means it's protected.
  * CSRF - cookie-authenticated state-changing requests (POST/PUT/PATCH/
    DELETE) with no anti-CSRF token and no bearer auth.

Results are stored as a synthetic scan job (tool="logic") so they flow through
the normal validation / report / kill-chain pipeline unchanged. An optional
LLM pass (best-effort) refines severity and wording.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app import events
from app.engagements import EngagementRepository
from app.llm import ROLE_VALIDATOR, LLMError, get_router
from app.proxy import FlowRepository
from app.scans.models import Finding, Job, JobStatus
from app.scans.storage import JobRepository, new_job_id
from app.validation.safe_poc import SafePoC, ScopeError

logger = logging.getLogger("allhack.analysis.logic")

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
_CSRF_HEADERS = {"x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken", "x-xsrf"}
_CSRF_BODY_KEYS = (
    "csrf", "_csrf", "csrf_token", "csrfmiddlewaretoken",
    "authenticity_token", "__requestverificationtoken", "_token",
)
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".woff", ".woff2", ".ttf", ".ico", ".map", ".webp")

MAX_FLOWS = 1000
MAX_IDOR_CONFIRM = 25


async def analyze_logic(
    engagement_id: str, *, active_idor: bool = True, use_llm: bool = True
) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    flows_repo = FlowRepository()
    summaries = await flows_repo.list_flows(limit=MAX_FLOWS)
    in_scope = [f for f in summaries if eng.host_in_scope(_host(f.url))]

    safe = SafePoC(in_scope=eng.host_in_scope)
    findings: List[Finding] = []

    # ---- IDOR (from summaries; safe re-fetch to confirm) ----
    confirmed_count = 0
    for f in in_scope:
        if (f.method or "").upper() != "GET":
            continue
        if _is_static(f.url):
            continue
        if f.status_code != 200:
            continue
        ident = _find_numeric_id(f.url)
        if ident is None:
            continue
        location, original, modified_url = ident

        status, confidence, poc = "likely", 0.5, (
            f"Authenticated GET {f.url} exposes an object by id "
            f"({location}={original}); access control not verified."
        )
        if active_idor and confirmed_count < MAX_IDOR_CONFIRM:
            confirmed_count += 1
            verdict = await _confirm_idor(safe, f, modified_url, original)
            if verdict is None:
                # Protected (401/403/404) -> not an IDOR; skip.
                continue
            status, confidence, poc = verdict

        findings.append(Finding(
            severity="high",
            title=f"Possible IDOR on {urlparse(f.url).path}",
            description="Object referenced by a guessable id in an authenticated request.",
            target=f.url,
            evidence=poc,
            metadata={"vuln_class": "idor", "status": status, "confidence": confidence,
                      "id_location": location, "id_value": original},
        ))

    # ---- CSRF (needs headers/body -> get_flow on state-changing requests) ----
    csrf_candidates = [f for f in in_scope if (f.method or "").upper() in _STATE_CHANGING]
    for f in csrf_candidates[:200]:
        full = await flows_repo.get_flow(f.id)
        if not full:
            continue
        verdict = _detect_csrf(full)
        if verdict is None:
            continue
        findings.append(Finding(
            severity="medium",
            title=f"Possible CSRF: {f.method} {urlparse(f.url).path}",
            description="Cookie-authenticated state-changing request with no anti-CSRF token.",
            target=f.url,
            evidence=verdict,
            metadata={"vuln_class": "csrf", "status": "likely", "confidence": 0.55,
                      "method": f.method},
        ))

    if use_llm:
        await _llm_refine(findings)

    await _save_logic_job(engagement_id, findings)

    idor_n = sum(1 for x in findings if x.metadata.get("vuln_class") == "idor")
    csrf_n = sum(1 for x in findings if x.metadata.get("vuln_class") == "csrf")
    await events.emit(
        engagement_id, events.VALIDATED,
        f"Logic analysis: {idor_n} IDOR, {csrf_n} CSRF candidate(s) "
        f"from {len(in_scope)} captured flows",
        level=events.LEVEL_VERBOSE,
    )
    logger.info("[%s] logic analysis: idor=%d csrf=%d (flows=%d)",
                engagement_id, idor_n, csrf_n, len(in_scope))
    return {"flows_analyzed": len(in_scope), "idor": idor_n, "csrf": csrf_n,
            "total": len(findings)}


# --------------------------------------------------------------------------- #
# IDOR
# --------------------------------------------------------------------------- #

def _find_numeric_id(url: str) -> Optional[Tuple[str, str, str]]:
    """Return (location, original_value, modified_url) for the first numeric id
    found in the path or query, with the id shifted to a neighbour."""
    parsed = urlparse(url)

    # Path segment that is all digits.
    segments = parsed.path.split("/")
    for i, seg in enumerate(segments):
        if seg.isdigit() and len(seg) >= 1:
            neighbour = _neighbour(seg)
            new_segments = segments.copy()
            new_segments[i] = neighbour
            modified = urlunparse(parsed._replace(path="/".join(new_segments)))
            return ("path", seg, modified)

    # Query param with a numeric value.
    params = parse_qsl(parsed.query, keep_blank_values=True)
    for idx, (k, v) in enumerate(params):
        if v.isdigit():
            new_params = params.copy()
            new_params[idx] = (k, _neighbour(v))
            modified = urlunparse(parsed._replace(query=urlencode(new_params)))
            return (f"query:{k}", v, modified)

    return None


def _neighbour(value: str) -> str:
    try:
        n = int(value)
    except ValueError:
        return value
    return str(n - 1) if n > 1 else str(n + 1)


async def _confirm_idor(
    safe: SafePoC, flow, modified_url: str, original_id: str
) -> Optional[Tuple[str, float, str]]:
    """Safely re-request a neighbouring id (GET, in-scope). Returns
    (status, confidence, poc) or None when the resource is protected."""
    try:
        resp = await safe.fetch(modified_url, method="GET")
    except ScopeError:
        return ("likely", 0.5, f"Re-test skipped (out of scope): {modified_url}")
    if resp is None:
        return ("likely", 0.5, f"Neighbour id not reachable: {modified_url}")
    if resp.status_code in (401, 403, 404):
        # Access control is enforced for the neighbour -> not an IDOR.
        return None
    if resp.status_code == 200:
        orig_size = getattr(flow, "response_size", None) or 0
        new_size = len(resp.text)
        differs = orig_size == 0 or abs(new_size - orig_size) > max(64, orig_size * 0.05)
        conf = 0.75 if differs else 0.6
        poc = (
            f"Authenticated request used id {original_id}. Re-requesting a "
            f"neighbouring id returned HTTP 200 ({new_size} bytes) at "
            f"{modified_url} - access to another object without authorization."
        )
        return ("likely", conf, poc)
    # Other codes (5xx, redirects): inconclusive but worth noting.
    return ("likely", 0.5, f"Neighbour id returned HTTP {resp.status_code}: {modified_url}")


# --------------------------------------------------------------------------- #
# CSRF
# --------------------------------------------------------------------------- #

def _detect_csrf(full: Dict[str, Any]) -> Optional[str]:
    headers = full.get("request_headers") or []
    names = {str(n).lower(): str(v) for n, v in headers}

    if "cookie" not in names:
        return None  # not cookie-authenticated -> classic CSRF doesn't apply
    auth = names.get("authorization", "").lower()
    if auth.startswith("bearer "):
        return None  # token-auth APIs are not CSRF-able via the browser

    # Anti-CSRF header present?
    if any(h in names for h in _CSRF_HEADERS):
        return None

    # Anti-CSRF token in the body?
    body = full.get("request_body_preview") or {}
    body_text = (body.get("text") or "").lower() if body.get("encoding") == "text" else ""
    if any(k in body_text for k in _CSRF_BODY_KEYS):
        return None

    method = full.get("method", "?")
    return (f"{method} request authenticated by cookie with no anti-CSRF token "
            f"(no CSRF header, none in body). Forgeable cross-site.")


# --------------------------------------------------------------------------- #
# optional LLM refinement
# --------------------------------------------------------------------------- #

async def _llm_refine(findings: List[Finding]) -> None:
    if not findings:
        return
    client = get_router().get(ROLE_VALIDATOR)
    if not client.configured:
        return
    payload = [
        {"i": i, "class": f.metadata.get("vuln_class"), "title": f.title,
         "target": f.target, "evidence": f.evidence[:300]}
        for i, f in enumerate(findings)
    ]
    system = (
        "You review candidate IDOR/CSRF findings from authenticated traffic. "
        "For each, keep or drop it and set severity (low/medium/high/critical) "
        "and a one-sentence note. Reply JSON only: "
        '{"items":[{"i":0,"keep":true,"severity":"high","note":"..."}]}'
    )
    try:
        reply = await client.chat(
            [{"role": "system", "content": system},
             {"role": "user", "content": json.dumps(payload)}],
            temperature=0.1, max_tokens=1200,
        )
    except LLMError:
        return
    decisions = _parse_items(reply)
    keep: List[Finding] = []
    for i, f in enumerate(findings):
        d = decisions.get(i)
        if d is None:
            keep.append(f)
            continue
        if d.get("keep") is False:
            continue
        if d.get("severity"):
            f.severity = str(d["severity"]).lower()
        if d.get("note"):
            f.description = str(d["note"])
        keep.append(f)
    findings[:] = keep


def _parse_items(reply: str) -> Dict[int, Dict[str, Any]]:
    text = reply.strip()
    if text.startswith("```"):
        text = text.strip("`").split("\n", 1)[-1]
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        s, e = text.find("{"), text.rfind("}")
        if s == -1 or e == -1:
            return {}
        try:
            obj = json.loads(text[s:e + 1])
        except json.JSONDecodeError:
            return {}
    out: Dict[int, Dict[str, Any]] = {}
    for it in (obj.get("items") or []) if isinstance(obj, dict) else []:
        if isinstance(it, dict) and "i" in it:
            try:
                out[int(it["i"])] = it
            except (TypeError, ValueError):
                continue
    return out


# --------------------------------------------------------------------------- #
# persistence: store as a synthetic 'logic' job
# --------------------------------------------------------------------------- #

async def _save_logic_job(engagement_id: str, findings: List[Finding]) -> None:
    repo = JobRepository()
    await repo.delete_by_tool(engagement_id, "logic")
    now = time.time()
    job = Job(
        id=new_job_id(),
        tool="logic",
        target="(captured traffic)",
        args=[],
        status=JobStatus.SUCCEEDED,
        created_at=now,
        started_at=now,
        finished_at=now,
        exit_code=0,
        findings=findings,
        engagement_id=engagement_id,
    )
    await repo.create(job)


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _is_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXT)
