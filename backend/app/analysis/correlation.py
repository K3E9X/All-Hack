"""Cross-tool correlation (planner role).

Every wrapper parses its own output in isolation, and every analyzer looks at
one signal. Nobody joins them. The interesting inferences in a pentest are
almost always joins:

    wafw00f says Cloudflare
  + whatweb says WordPress 6.2
  + gau found /wp-json/wp/v2/users
  + nuclei flagged an outdated plugin
  -> the plugin is the way in, the WAF explains why the generic payloads
     bounced, and the REST route is where to confirm the version

chaining.py already does this, but only over findings that were *validated*.
By then the recon that would have redirected the scan is long gone. This runs
on the raw picture instead: assets, fingerprints and their sources, WAF, the
findings so far, and a digest of the traffic actually captured.

Why the planner role: this is the one call in the pipeline where a large
context and long-horizon reasoning pay for themselves. Kimi K3's window takes
the whole engagement without chunking, which is the difference between "here
are 12 URLs" and "here is everything we know".

Grounding is non-negotiable. The model may only reference assets that already
exist and tools from the known set; anything else is dropped. It proposes, it
never executes - the deterministic catalog remains the floor.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from app.llm import ROLE_PLANNER, LLMError, get_router
from app.llm.grounding import extract_json, safe_tokens

logger = logging.getLogger("syphax.analysis.correlation")

# Tools the model is allowed to nominate. Anything else is dropped rather than
# passed through - a hallucinated binary would fail at submit() anyway, but
# silently proposing it wastes a planning slot.
NOMINABLE_TOOLS = {
    "nuclei", "sqlmap", "ffuf", "dalfox", "commix", "nikto",
    "wpscan", "testssl", "httpx", "katana", "whatweb",
}

# Caps: this prompt is big by design, but not unbounded.
MAX_ASSETS = 120
MAX_FLOWS = 60
MAX_FINDINGS = 80
MAX_LEADS = 8


@dataclass
class Lead:
    """One correlated hypothesis the planner wants tested."""
    asset: str
    tool: str
    rationale: str
    tags: List[str] = field(default_factory=list)
    confidence: float = 0.5
    signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset": self.asset,
            "tool": self.tool,
            "rationale": self.rationale,
            "tags": self.tags,
            "confidence": self.confidence,
            "signals": self.signals,
        }


SYSTEM = """\
You are the planner of an authorized web-application penetration test.

You are given the FULL picture gathered so far: assets, fingerprinted
technologies with the tool that found each, WAF detection, findings to date,
and a digest of HTTP traffic actually captured from the target.

Your job is the part no single tool can do: JOIN these signals. A technology on
its own is not interesting; a technology plus an exposed route plus a finding
that half-confirms it is a lead.

Rules:
- Reference ONLY assets from the provided list, verbatim. Never invent a host,
  path or parameter.
- `signals` must quote the exact input items you joined, so a human can check
  your reasoning. A lead whose signals cannot be traced back is worthless.
- Pick `tool` from the provided tool list only.
- Prefer few strong leads over many weak ones. An empty list is a valid answer
  when the signals genuinely do not join.
- Do not repeat what the deterministic catalog will run anyway; add what it
  would miss.

Reply with JSON only:
{"leads":[{"asset":"<verbatim asset>","tool":"<tool>","tags":["cve","wordpress"],
"rationale":"one sentence","signals":["<quoted input>","<quoted input>"],
"confidence":0.0-1.0}],
"summary":"two sentences on how the target hangs together"}
"""


def _asset_digest(assets: List[Any]) -> List[Dict[str, Any]]:
    out = []
    for a in assets[:MAX_ASSETS]:
        out.append({
            "value": getattr(a, "value", str(a)),
            "kind": getattr(a, "kind", "?"),
            "has_params": bool(getattr(a, "has_params", False)),
            "source": getattr(a, "source", None),
        })
    return out


def _flow_digest(flows: List[Any]) -> List[Dict[str, Any]]:
    """Endpoint shape only - method, path, status, content type.

    Deliberately not bodies: the planner needs the map of what the app exposes,
    and llm_recon already reads bodies for its own analysis. Sending both would
    duplicate tokens for no extra signal.
    """
    out = []
    for f in flows[:MAX_FLOWS]:
        out.append({
            "method": getattr(f, "method", "GET"),
            "url": getattr(f, "url", ""),
            "status": getattr(f, "status_code", None),
            "content_type": getattr(f, "content_type", None),
        })
    return out


def _finding_digest(findings: List[Any]) -> List[Dict[str, Any]]:
    out = []
    for f in findings[:MAX_FINDINGS]:
        out.append({
            "title": getattr(f, "title", ""),
            "severity": getattr(f, "severity", "info"),
            "status": getattr(f, "status", ""),
            "vuln_class": getattr(f, "vuln_class", ""),
            "target": getattr(f, "target", ""),
        })
    return out


def build_payload(
    *,
    assets: List[Any],
    technologies: List[str],
    findings: List[Any],
    flows: List[Any],
    coverage_summary: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Assemble the engagement picture handed to the model."""
    return {
        "assets": _asset_digest(assets),
        "technologies": list(technologies or [])[:60],
        "findings_so_far": _finding_digest(findings),
        "captured_traffic": _flow_digest(flows),
        "coverage": coverage_summary or {},
        "available_tools": sorted(NOMINABLE_TOOLS),
    }


def parse_leads(parsed: Any, known_assets: Set[str]) -> List[Lead]:
    """Validate the model's reply against what actually exists.

    A lead pointing at an asset we never saw, or naming a tool we do not run,
    is dropped rather than corrected - guessing at intent is how an unauthorized
    target ends up in a scan queue.
    """
    if not isinstance(parsed, dict):
        return []

    leads: List[Lead] = []
    for raw in (parsed.get("leads") or [])[:MAX_LEADS * 3]:
        if not isinstance(raw, dict):
            continue
        asset = str(raw.get("asset") or "").strip()
        tool = str(raw.get("tool") or "").strip().lower()
        if asset not in known_assets:
            logger.debug("dropped lead on unknown asset %r", asset)
            continue
        if tool not in NOMINABLE_TOOLS:
            logger.debug("dropped lead with unknown tool %r", tool)
            continue

        rationale = str(raw.get("rationale") or "").strip()[:300]
        signals = [str(s).strip()[:200] for s in (raw.get("signals") or []) if str(s).strip()]
        if not signals:
            # No traceable reasoning: not actionable, and not auditable either.
            logger.debug("dropped lead with no signals on %s", asset)
            continue

        try:
            confidence = min(1.0, max(0.0, float(raw.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5

        leads.append(Lead(
            asset=asset,
            tool=tool,
            rationale=rationale,
            tags=safe_tokens(raw.get("tags"), limit=8),
            confidence=confidence,
            signals=signals[:6],
        ))

    leads.sort(key=lambda x: x.confidence, reverse=True)
    return leads[:MAX_LEADS]


async def correlate(
    *,
    assets: List[Any],
    technologies: List[str],
    findings: List[Any],
    flows: List[Any],
    coverage_summary: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Ask the planner to join the signals. Best-effort: no LLM -> no leads."""
    known = {getattr(a, "value", str(a)) for a in assets}
    if not known:
        return {"leads": [], "summary": ""}

    client = get_router().get(ROLE_PLANNER)
    if not client.configured:
        return {"leads": [], "summary": ""}

    payload = build_payload(
        assets=assets,
        technologies=technologies,
        findings=findings,
        flows=flows,
        coverage_summary=coverage_summary,
    )

    try:
        reply = await client.chat(
            [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": json.dumps(payload)},
            ],
            temperature=0.1,
            max_tokens=1600,
        )
    except LLMError as exc:
        logger.warning("correlation unavailable: %s", exc)
        return {"leads": [], "summary": ""}
    except Exception as exc:  # noqa: BLE001 - correlation must never break a run
        logger.warning("correlation failed: %s", exc)
        return {"leads": [], "summary": ""}

    parsed = extract_json(reply)
    leads = parse_leads(parsed, known)
    summary = ""
    if isinstance(parsed, dict):
        summary = str(parsed.get("summary") or "").strip()[:600]

    logger.info("correlation: %d lead(s) from %d assets / %d flows",
                len(leads), len(payload["assets"]), len(payload["captured_traffic"]))
    return {"leads": [lead.to_dict() for lead in leads], "summary": summary}
