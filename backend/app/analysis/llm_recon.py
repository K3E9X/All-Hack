"""LLM response analyst (intelligence layer #1).

The regex/heuristic analyzers catch known shapes; this one gives the captured
traffic an analyst's eye. It feeds the model real request/response excerpts and
asks it to flag what a signature would miss - a verbose error revealing a
framework/version, a reflected parameter, a leaked internal endpoint, an unusual
header, a debug/stacktrace page.

Grounding (non-negotiable): every finding must quote a substring that actually
appears in the data we sent. `findings_from_llm` drops anything that can't, so
the model cannot invent a vulnerability. Read-only: it only reads already-
captured traffic, sends nothing to the target. Best-effort: no LLM -> no-op.

Stored as a synthetic job (tool="llm-recon"), status="likely" (hypotheses); the
LLM judge / safe-PoC validation can promote or kill them.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.llm import ROLE_EXECUTOR, LLMError, get_router
from app.llm.analyzer import _flow_to_context
from app.llm.grounding import (clamp_confidence, extract_json, norm_severity,
                               quote_is_grounded)
from app.proxy import FlowRepository
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.llm_recon")

# How much traffic we hand the analyst is a context-window question, so it is
# configurable (see Settings.llm_recon_*). Long-context models (Qwen3.8-27B and
# friends) can take an order of magnitude more than the old fixed 12 flows,
# which is where the cross-endpoint correlations a human analyst spots live.
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".woff", ".woff2", ".ttf", ".ico", ".map", ".webp")

_SYSTEM = (
    "You are a senior web-app penetration tester reviewing captured HTTP "
    "traffic. Identify security-relevant signals a signature scanner would miss: "
    "verbose errors / stack traces, framework or version disclosure, reflected "
    "input, leaked internal endpoints or hosts, debug pages, dangerous headers, "
    "secrets in responses. Report ONLY what is visible in the provided data. "
    "For each item you MUST copy an exact short substring from the data as "
    "'evidence' (it will be verified; invented evidence is discarded). "
    "Reply JSON only: {\"findings\":[{\"title\":\"...\",\"severity\":"
    "\"critical|high|medium|low|info\",\"vuln_class\":\"...\",\"confidence\":0.0-1.0,"
    "\"url\":\"<one of the provided urls>\",\"evidence\":\"<exact substring>\","
    "\"why\":\"<short reason>\"}]}. Empty findings list is fine."
)


async def analyze_llm_recon(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}
    client = get_router().get(ROLE_EXECUTOR)
    if not client.configured:
        return {"skipped": 1, "reason": "no LLM configured"}

    from app.config import settings
    max_flows = max(1, int(settings.llm_recon_max_flows))
    body_chars = max(500, int(settings.llm_recon_body_chars))
    budget = max(10_000, int(settings.llm_recon_budget_chars))

    flows_repo = FlowRepository()
    try:
        summaries = await flows_repo.list_flows(limit=2000)
    except Exception:  # noqa: BLE001
        summaries = []

    # 1. In-scope, non-static, one entry per (method, path).
    candidates = []
    seen_paths = set()
    for f in summaries:
        host = (urlparse(f.url).hostname or "").lower()
        if not eng.host_in_scope(host) or _is_static(f.url):
            continue
        key = (f.method, urlparse(f.url).path)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        candidates.append(f)

    # 2. Rank before fetching bodies: with a budget, WHICH flows we send matters
    # more than how many. Errors and parameterised endpoints come first.
    candidates.sort(key=lambda f: (
        flow_priority(f.method, f.status_code, f.url, f.response_content_type),
        -(f.response_size or 0),
    ))

    # 3. Fill up to the flow count / character budget, whichever binds first.
    contexts: List[Dict] = []
    used = 0
    for f in candidates[:max_flows * 2]:
        if len(contexts) >= max_flows:
            break
        full = await flows_repo.get_flow(f.id)
        if not full:
            continue
        ctx = _flow_to_context(full, req_cap=body_chars, resp_cap=body_chars)
        size = context_size(ctx)
        if contexts and used + size > budget:
            break
        contexts.append(ctx)
        used += size

    if not contexts:
        await save_analysis_job(engagement_id, "llm-recon", [], target="(captured traffic)")
        return {"flows": 0, "findings": 0}

    corpus = _corpus(contexts)
    try:
        raw = await client.chat(
            [{"role": "system", "content": _SYSTEM},
             {"role": "user", "content": _user_prompt(contexts)}],
            temperature=0.1, max_tokens=2000,
        )
    except LLMError as exc:
        logger.warning("[%s] llm-recon unavailable: %s", engagement_id, exc)
        return {"skipped": 1, "reason": "llm error"}

    findings = findings_from_llm(extract_json(raw), corpus)
    await save_analysis_job(engagement_id, "llm-recon", findings, target="(captured traffic)")
    logger.info("[%s] llm-recon: flows=%d/%d chars=%d/%d findings=%d (grounded)",
                engagement_id, len(contexts), len(candidates), used, budget,
                len(findings))
    return {"flows": len(contexts), "candidates": len(candidates),
            "chars": used, "findings": len(findings)}


# --------------------------------------------------------------------------- #
# Pure core (unit-tested)

def flow_priority(method: str, status_code, url: str,
                  response_content_type: Optional[str] = None) -> int:
    """Rank a captured flow for the analyst. LOWER sorts first.

    Ordering reflects where disclosure actually lives: server errors leak stack
    traces and versions, auth/validation errors leak internal logic, and
    parameterised or state-changing requests are the injection surface. Plain
    200s and 404s are the least informative per character spent.
    """
    sc = int(status_code or 0)
    if 500 <= sc < 600:
        score = 0                       # stack traces, framework internals
    elif sc in (401, 403):
        score = 10                      # auth boundaries
    elif sc in (400, 422):
        score = 12                      # validation errors leak field names
    elif 405 <= sc < 500:
        score = 15
    elif sc == 404:
        score = 60                      # mostly noise
    elif 300 <= sc < 400:
        score = 45                      # redirects, usually empty bodies
    elif 200 <= sc < 300:
        score = 30
    else:
        score = 50                      # unknown / no response recorded

    if urlparse(url or "").query:
        score -= 8                      # injection surface
    if str(method or "").upper() not in ("GET", "HEAD"):
        score -= 6                      # state-changing, richer bodies
    ct = str(response_content_type or "").lower()
    if "json" in ct or "xml" in ct:
        score -= 4                      # API surface
    return score


def context_size(ctx: Dict) -> int:
    """Approximate prompt cost (characters) of one flow context."""
    return sum(len(str(ctx.get(k, ""))) for k in
               ("url", "request_headers", "request_body_preview",
                "response_headers", "response_body_preview"))


def _corpus(contexts: List[Dict]) -> str:
    parts = []
    for c in contexts:
        parts.append(c.get("url", ""))
        parts.append(c.get("request_body_preview", ""))
        parts.append(c.get("response_headers", ""))
        parts.append(c.get("response_body_preview", ""))
    return "\n".join(p for p in parts if p)


def _user_prompt(contexts: List[Dict]) -> str:
    blocks = []
    for c in contexts:
        blocks.append(
            f"URL: {c.get('url','')}\n"
            f"Status: {c.get('status_code')}\n"
            f"Response-Headers:\n{c.get('response_headers','')}\n"
            f"Response-Body:\n{c.get('response_body_preview','')}\n---"
        )
    return "Captured flows:\n\n" + "\n".join(blocks)


def findings_from_llm(parsed, corpus: str) -> List[Finding]:
    """Turn the model's JSON into Findings, dropping any whose evidence is not
    literally present in the corpus (anti-hallucination)."""
    if not isinstance(parsed, dict):
        return []
    items = parsed.get("findings")
    if not isinstance(items, list):
        return []
    out: List[Finding] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        evidence = str(it.get("evidence", ""))
        if not quote_is_grounded(evidence, corpus):
            continue  # ungrounded -> the model invented it; drop.
        url = str(it.get("url", "")) or "(captured traffic)"
        out.append(Finding(
            severity=norm_severity(it.get("severity")),
            title=str(it.get("title", "LLM-identified signal"))[:200],
            description=str(it.get("why", ""))[:600],
            target=url,
            evidence=f"{evidence}\n\n(LLM response analysis)",
            metadata={"vuln_class": str(it.get("vuln_class", "info"))[:40],
                      "status": "likely",
                      "confidence": clamp_confidence(it.get("confidence"), 0.5),
                      "source": "llm-recon"},
        ))
    return out


def _is_static(url: str) -> bool:
    return urlparse(url).path.lower().endswith(_STATIC_EXT)
