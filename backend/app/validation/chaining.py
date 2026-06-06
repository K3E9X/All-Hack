"""Kill-chain analysis (spec §4.2 chaining requirement).

Links individual validated findings into multi-step attack paths - the single
biggest differentiator from a scanner. Deterministic rules first (reliable,
explainable), then an optional LLM pass that proposes additional chains
strictly from the existing findings (it references finding ids; it cannot
invent findings).
"""
from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Any, Dict, List

from app.llm import ROLE_PLANNER, LLMError, get_router
from app.validation.models import ValidatedFinding
from app.validation.storage import ChainRepository, ValidatedFindingRepository

logger = logging.getLogger("allhack.validation.chaining")

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _chain_id() -> str:
    return f"chain_{int(time.time()*1000)}_{secrets.token_hex(2)}"


async def build_chains(engagement_id: str, *, use_llm: bool = True) -> List[Dict[str, Any]]:
    vf_repo = ValidatedFindingRepository()
    chain_repo = ChainRepository()

    findings = [f for f in await vf_repo.list(engagement_id)
                if f.status in ("confirmed", "likely")]

    chains: List[Dict[str, Any]] = []
    chains.extend(_deterministic_chains(findings))

    if use_llm and len(findings) >= 2:
        try:
            chains.extend(await _llm_chains(findings))
        except LLMError as exc:
            logger.warning("LLM chaining unavailable: %s", exc)

    await chain_repo.replace_for_engagement(engagement_id, chains)

    # Tag the findings that participate in a chain.
    for c in chains:
        for step in c.get("steps", []):
            fid = step.get("finding_id")
            if fid:
                await vf_repo.set_chain(fid, c["id"])

    return chains


def _deterministic_chains(findings: List[ValidatedFinding]) -> List[Dict[str, Any]]:
    by_class: Dict[str, List[ValidatedFinding]] = {}
    for f in findings:
        by_class.setdefault(f.vuln_class, []).append(f)

    chains: List[Dict[str, Any]] = []

    def has(*classes: str) -> List[ValidatedFinding]:
        out = []
        for c in classes:
            out.extend(by_class.get(c, []))
        return out

    # Pattern: source/secret disclosure -> credentials -> deeper access.
    disclosure = [f for f in findings if any(
        k in (f.target or "").lower() for k in (".git", ".env", "wp-config", ".svn", "actuator/env")
    )]
    if disclosure:
        steps = [
            {"finding_id": disclosure[0].id, "action": "Read exposed source/config",
             "reason": f"{disclosure[0].title} is publicly readable"},
            {"action": "Extract credentials / secrets from disclosed files",
             "reason": "Config and source frequently embed DB creds, API keys, tokens"},
            {"action": "Authenticate or pivot using recovered secrets",
             "reason": "Recovered credentials often grant authenticated or admin access"},
        ]
        chains.append(_chain(
            title="Source/secret disclosure to credential compromise",
            severity="high",
            summary="Publicly readable source or config can leak credentials that "
                    "unlock authenticated functionality or the database.",
            steps=steps,
        ))

    # Pattern: SQLi -> data exfiltration / auth bypass.
    sqli = has("sql_injection")
    if sqli:
        steps = [
            {"finding_id": sqli[0].id, "action": "Exploit SQL injection",
             "reason": sqli[0].title},
            {"action": "Dump user/credential tables", "reason": "DB read access via the injection"},
            {"action": "Crack/replay credentials or bypass auth",
             "reason": "Recovered hashes/sessions enable account takeover"},
        ]
        chains.append(_chain(
            title="SQL injection to data breach / account takeover",
            severity="critical",
            summary="A confirmed SQL injection gives database read access, leading "
                    "to credential theft and account takeover.",
            steps=steps,
        ))

    # Pattern: command injection -> RCE foothold.
    cmdi = has("command_injection")
    if cmdi:
        steps = [
            {"finding_id": cmdi[0].id, "action": "Exploit OS command injection",
             "reason": cmdi[0].title},
            {"action": "Execute arbitrary commands as the web user",
             "reason": "Command injection yields code execution"},
            {"action": "Read secrets / pivot to internal services",
             "reason": "Foothold enables local file read and lateral movement"},
        ]
        chains.append(_chain(
            title="Command injection to remote code execution",
            severity="critical",
            summary="Confirmed command injection provides code execution on the host.",
            steps=steps,
        ))

    return chains


async def _llm_chains(findings: List[ValidatedFinding]) -> List[Dict[str, Any]]:
    client = get_router().get(ROLE_PLANNER)
    if not client.configured:
        return []

    brief = [
        {"finding_id": f.id, "vuln_class": f.vuln_class, "severity": f.severity,
         "title": f.title, "target": f.target}
        for f in findings[:40]
    ]
    system = (
        "You are a penetration tester linking confirmed findings into multi-step "
        "attack chains (kill-paths). Use ONLY the finding_ids provided; never "
        "invent findings. Output JSON only: "
        '{"chains":[{"title":"...","severity":"critical|high|medium|low",'
        '"summary":"...","steps":[{"finding_id":"<id or null>","action":"...","reason":"..."}]}]}. '
        "Only propose a chain if the steps genuinely compose into greater impact."
    )
    reply = await client.chat(
        [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps({"findings": brief})},
        ],
        temperature=0.2,
        max_tokens=1500,
    )
    parsed = _parse(reply)
    valid_ids = {f.id for f in findings}
    out: List[Dict[str, Any]] = []
    for c in parsed:
        steps = []
        for s in c.get("steps", []):
            fid = s.get("finding_id")
            if fid is not None and fid not in valid_ids:
                fid = None  # drop hallucinated ids, keep the narrative step
            steps.append({"finding_id": fid, "action": str(s.get("action", "")),
                          "reason": str(s.get("reason", ""))})
        if steps:
            out.append(_chain(
                title=str(c.get("title", "LLM chain")),
                severity=str(c.get("severity", "medium")),
                summary=str(c.get("summary", "")),
                steps=steps,
                source="llm",
            ))
    return out


def _chain(*, title: str, severity: str, summary: str, steps: list, source: str = "deterministic") -> Dict[str, Any]:
    return {
        "id": _chain_id(),
        "title": title,
        "severity": severity,
        "summary": summary,
        "steps": steps,
        "source": source,
    }


def _parse(reply: str) -> List[Dict[str, Any]]:
    text = reply.strip()
    if text.startswith("```"):
        text = text.strip("`")
        parts = text.split("\n", 1)
        if len(parts) == 2 and len(parts[0]) <= 10:
            text = parts[1]
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        s, e = text.find("{"), text.rfind("}")
        if s == -1 or e == -1:
            return []
        try:
            obj = json.loads(text[s:e + 1])
        except json.JSONDecodeError:
            return []
    chains = obj.get("chains") if isinstance(obj, dict) else None
    return chains if isinstance(chains, list) else []
