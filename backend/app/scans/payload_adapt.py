"""Payload adaptation (intelligence layer #4): WAF-aware tamper selection.

When a WAF is fingerprinted, the deterministic baseline (app/scans/waf.py) already
applies a generic tamper set. This lets the executor LLM pick the tampers best
suited to the SPECIFIC WAF (Cloudflare vs ModSecurity vs Akamai need different
transforms) - but only from a vetted allowlist, so a hallucinated name can never
become a real flag. No LLM -> the deterministic baseline stands.

Gated by the caller on allow_active_exploit (it only matters for active
injection tools sqlmap/commix).
"""
from __future__ import annotations

import logging
from typing import List

from app.llm import ROLE_EXECUTOR, LLMError, get_router
from app.llm.grounding import extract_json

logger = logging.getLogger("allhack.scans.payload_adapt")

TAMPER_TOOLS = {"sqlmap", "commix"}

# Vetted sqlmap/commix tamper scripts (transform-only, non-destructive).
ALLOWED_TAMPERS = {
    "space2comment", "space2dash", "space2hash", "space2mssqlblank",
    "space2mysqlblank", "space2plus", "space2randomblank", "between",
    "randomcase", "charencode", "charunicodeencode", "charunicodeescape",
    "equaltolike", "greatest", "percentage", "apostrophemask",
    "apostrophenullencode", "base64encode", "bluecoat", "chardoubleencode",
    "commalesslimit", "commalessmid", "concat2concatws", "halfversionedmorekeywords",
    "ifnull2ifisnull", "modsecurityversioned", "modsecurityzeroversioned",
    "multiplespaces", "nonrecursivereplacement", "randomcomments",
    "securesphere", "unmagicquotes", "versionedkeywords", "versionedmorekeywords",
}

_SYSTEM = (
    "You are tuning a SQL/command-injection tool to evade a specific WAF. Choose "
    "the most effective tamper transforms FOR THIS WAF, only from the allowed "
    "list given. Reply JSON only: {\"tampers\":[\"name1\",\"name2\",...]} (3-6 "
    "names, ordered best first). Use only names from the allowed list."
)


def filter_tampers(names) -> List[str]:
    out: List[str] = []
    for n in (names or []):
        t = str(n).strip().lower()
        if t in ALLOWED_TAMPERS and t not in out:
            out.append(t)
    return out


def tamper_option(names) -> List[str]:
    t = filter_tampers(names)
    return [f"--tamper={','.join(t)}"] if t else []


def strip_tamper(options) -> List[str]:
    """Drop any existing --tamper option (so an adaptive one replaces it)."""
    return [o for o in (options or []) if not str(o).startswith("--tamper")]


def parse_tamper_reply(raw: str) -> List[str]:
    obj = extract_json(raw)
    if isinstance(obj, dict):
        return filter_tampers(obj.get("tampers"))
    if isinstance(obj, list):
        return filter_tampers(obj)
    return []


async def adaptive_tampers(tool: str, waf_name: str) -> List[str]:
    """Return adaptive ['--tamper=...'] for the WAF, or [] if no LLM/uncertain."""
    if tool not in TAMPER_TOOLS:
        return []
    client = get_router().get(ROLE_EXECUTOR)
    if not client.configured:
        return []
    user = (f"WAF: {waf_name or 'unknown'}\nTool: {tool}\n"
            f"Allowed tampers: {', '.join(sorted(ALLOWED_TAMPERS))}")
    try:
        raw = await client.chat(
            [{"role": "system", "content": _SYSTEM},
             {"role": "user", "content": user}],
            temperature=0.0, max_tokens=200,
        )
    except LLMError as exc:
        logger.warning("adaptive tampers unavailable: %s", exc)
        return []
    except Exception as exc:  # noqa: BLE001
        logger.warning("adaptive tampers error: %s", exc)
        return []
    return tamper_option(parse_tamper_reply(raw))
