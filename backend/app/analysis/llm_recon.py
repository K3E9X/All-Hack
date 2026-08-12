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

MAX_FLOWS = 12
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

    flows_repo = FlowRepository()
    try:
        summaries = await flows_repo.list_flows(limit=1000)
    except Exception:  # noqa: BLE001
        summaries = []

    contexts: List[Dict] = []
    seen_paths = set()
    for f in summaries:
        host = (urlparse(f.url).hostname or "").lower()
        if not eng.host_in_scope(host) or _is_static(f.url):
            continue
        path = urlparse(f.url).path
        key = (f.method, path)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        full = await flows_repo.get_flow(f.id)
        if full:
            contexts.append(_flow_to_context(full))
        if len(contexts) >= MAX_FLOWS:
            break

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
    logger.info("[%s] llm-recon: flows=%d findings=%d (grounded)",
                engagement_id, len(contexts), len(findings))
    return {"flows": len(contexts), "findings": len(findings)}


# --------------------------------------------------------------------------- #
# Pure core (unit-tested)

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
