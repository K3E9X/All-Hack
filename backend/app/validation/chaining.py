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

    # Pattern: RCE -> local privilege escalation -> root.
    if cmdi:
        privesc = has("privilege_escalation")
        if privesc:
            chains.append(_chain(
                title="RCE to root via local privilege escalation",
                severity="critical",
                summary="Command execution plus a local privesc vector (passwordless "
                        "sudo / SUID GTFOBins binary) yields full root control.",
                steps=[
                    {"finding_id": cmdi[0].id, "action": "Gain code execution",
                     "reason": cmdi[0].title},
                    {"finding_id": privesc[0].id, "action": "Escalate to root locally",
                     "reason": privesc[0].title},
                    {"action": "Full host control", "reason": "Root on the host"},
                ],
            ))

    # Pattern: full kill-path -> RCE + post-exploit data access + root (the
    # "root + data accessible" terminal state). Fires only when all three are
    # independently proven (code-exec, sensitive-data read, local privesc).
    if cmdi:
        privesc_all = has("privilege_escalation")
        data_access = has("secret_exposure")
        if privesc_all and data_access:
            chains.append(_chain(
                title="Full compromise: RCE to root with data access",
                severity="critical",
                summary="Code execution, post-exploitation read of sensitive data, and "
                        "a local privilege-escalation vector together demonstrate complete "
                        "compromise: root on the host with its data readable.",
                steps=[
                    {"finding_id": cmdi[0].id, "action": "Gain code execution",
                     "reason": cmdi[0].title},
                    {"finding_id": data_access[0].id,
                     "action": "Read sensitive data as the web user",
                     "reason": data_access[0].title},
                    {"finding_id": privesc_all[0].id, "action": "Escalate to root locally",
                     "reason": privesc_all[0].title},
                    {"action": "Root on host with full data access",
                     "reason": "End-to-end compromise demonstrated"},
                ],
            ))

    # Pattern: confirmed CVE (file read / traversal) -> secrets -> deeper access,
    # or -> code execution when an injectable primitive co-exists.
    cve = has("cve")
    if cve:
        steps = [{"finding_id": cve[0].id, "action": "Exploit the confirmed CVE",
                  "reason": cve[0].title}]
        rce = cmdi or has("sql_injection")
        if rce:
            steps.append({"finding_id": rce[0].id,
                          "action": "Pivot to code execution on the host",
                          "reason": "The disclosed files/version unlock an exploitable primitive"})
            steps.append({"action": "Read local secrets and control the server",
                          "reason": "File read plus code execution compromises the host"})
            chains.append(_chain(
                title="Known CVE to host compromise",
                severity="critical",
                summary="A confirmed, actively-exploited CVE combined with a code-exec "
                        "primitive compromises the host.",
                steps=steps,
            ))
        else:
            steps.append({"action": "Recover credentials/secrets from the readable files",
                          "reason": "Traversal / file-read CVEs expose /etc/passwd, config and keys"})
            steps.append({"action": "Reuse recovered secrets for authenticated/admin access",
                          "reason": "Leaked credentials unlock privileged functionality"})
            chains.append(_chain(
                title="Known CVE (file read) to credential compromise",
                severity="high",
                summary="A confirmed file-read / path-traversal CVE exposes system and "
                        "config files that frequently embed credentials.",
                steps=steps,
            ))

    # Pattern: default/weak credentials -> authenticated foothold -> escalation.
    weakauth = has("auth")
    if weakauth:
        steps = [
            {"finding_id": weakauth[0].id, "action": "Log in with default/weak credentials",
             "reason": weakauth[0].title},
            {"action": "Operate as that account with a valid session",
             "reason": "Accepted credentials grant authenticated access"},
        ]
        priv = has("privilege_escalation", "broken_access_control", "idor")
        if priv:
            steps.append({"finding_id": priv[0].id,
                          "action": "Escalate to other users / admin scope",
                          "reason": priv[0].title})
        chains.append(_chain(
            title="Default credentials to account takeover",
            severity="critical" if priv else "high",
            summary="A login endpoint accepts default/weak credentials, granting an "
                    "authenticated foothold that can be escalated.",
            steps=steps,
        ))

    # Pattern: leaked secret -> server/account compromise (secret -> RCE/access).
    secret = has("secret_exposure")
    if secret:
        steps = [{"finding_id": secret[0].id, "action": "Recover the leaked secret",
                  "reason": secret[0].title}]
        rce = cmdi or has("sql_injection")
        if rce:
            steps.append({"finding_id": rce[0].id,
                          "action": "Use the secret to reach a code-exec primitive",
                          "reason": "Leaked creds/keys unlock the injectable surface or admin"})
            steps.append({"action": "Execute code / control the server",
                          "reason": "Combined access yields full compromise"})
            chains.append(_chain(
                title="Leaked secret to server compromise",
                severity="critical",
                summary="A secret exposed in client code/responses unlocks access that, "
                        "combined with a code-exec bug, compromises the server.",
                steps=steps,
            ))
        else:
            steps.append({"action": "Authenticate to the cloud/API/admin with the secret",
                          "reason": "Live keys/tokens grant privileged access off-app"})
            chains.append(_chain(
                title="Leaked secret to account/infrastructure takeover",
                severity="high",
                summary="A live credential exposed to the client grants privileged "
                        "access to the API, cloud or admin surface.",
                steps=steps,
            ))

    # Pattern: broken access control / IDOR / BFLA -> bulk data exposure.
    access = has("idor", "broken_access_control", "privilege_escalation")
    if access:
        steps = [
            {"finding_id": access[0].id, "action": "Abuse the access-control flaw",
             "reason": access[0].title},
            {"action": "Enumerate other users' / privileged objects",
             "reason": "Missing authorization lets one identity reach others' data"},
            {"action": "Harvest sensitive records at scale", "reason": "Bulk data exposure"},
        ]
        chains.append(_chain(
            title="Broken access control to bulk data exposure",
            severity="high",
            summary="An object/function-level authorization flaw allows reaching data "
                    "and actions belonging to other users.",
            steps=steps,
        ))

    # Pattern: weak JWT -> token forgery -> account takeover.
    jwt = has("jwt")
    if jwt:
        priv = has("privilege_escalation", "broken_access_control")
        steps = [{"finding_id": jwt[0].id, "action": "Exploit the JWT weakness",
                  "reason": jwt[0].title},
                 {"action": "Forge a token with elevated claims (role/admin)",
                  "reason": "alg=none / weak secret lets the attacker mint tokens"}]
        if priv:
            steps.append({"finding_id": priv[0].id, "action": "Reach privileged functions",
                          "reason": priv[0].title})
        chains.append(_chain(
            title="Weak JWT to account takeover",
            severity="critical" if priv else "high",
            summary="A forgeable JWT lets an attacker impersonate any user and assume "
                    "elevated roles.",
            steps=steps,
        ))

    # Pattern: SSRF -> cloud metadata -> credential theft.
    ssrf = has("ssrf")
    if ssrf:
        steps = [
            {"finding_id": ssrf[0].id, "action": "Exploit SSRF", "reason": ssrf[0].title},
            {"action": "Reach the cloud metadata endpoint (169.254.169.254)",
             "reason": "SSRF can target internal-only metadata services"},
            {"action": "Steal temporary cloud credentials / pivot internally",
             "reason": "Metadata creds grant access to cloud resources"},
        ]
        chains.append(_chain(
            title="SSRF to cloud credential theft",
            severity="critical",
            summary="Server-side request forgery can reach internal metadata services "
                    "and recover cloud credentials.",
            steps=steps,
        ))

    # Pattern: subdomain takeover -> session/credential theft.
    takeover = has("subdomain_takeover")
    if takeover:
        steps = [
            {"finding_id": takeover[0].id, "action": "Claim the dangling subdomain",
             "reason": takeover[0].title},
            {"action": "Serve attacker content on a trusted subdomain",
             "reason": "Control of an in-scope host enables phishing / cookie scoping"},
            {"action": "Steal sessions or credentials from users",
             "reason": "Same-site trust and cookie scope are abused"},
        ]
        chains.append(_chain(
            title="Subdomain takeover to session/credential theft",
            severity="high",
            summary="A dangling subdomain can be claimed and used to phish users or "
                    "capture cookies scoped to the parent domain.",
            steps=steps,
        ))

    # Pattern: GraphQL introspection -> authorization abuse.
    graphql = [f for f in by_class.get("graphql", [])
               if "introspection" in (f.title or "").lower()]
    if graphql and access:
        steps = [
            {"finding_id": graphql[0].id, "action": "Read the full GraphQL schema",
             "reason": graphql[0].title},
            {"finding_id": access[0].id, "action": "Invoke hidden/privileged operations",
             "reason": "Introspection reveals operations the UI never exposes"},
        ]
        chains.append(_chain(
            title="GraphQL introspection to authorization abuse",
            severity="high",
            summary="A readable GraphQL schema maps hidden operations that an "
                    "access-control flaw then lets the attacker call.",
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
