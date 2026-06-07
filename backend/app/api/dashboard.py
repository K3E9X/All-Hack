"""Dashboard + toolchain (SBOM) endpoints for the Home screen.

GET /api/dashboard -> headline counters (engagements, jobs, confirmed findings)
                      and global LLM usage with a per-model breakdown.
GET /api/tools     -> the orchestrated toolchain grouped-friendly by phase, with
                      availability. Versions are not claimed unless known.
"""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter

from app import db
from app.scans.wrappers import available_wrappers

router = APIRouter(tags=["dashboard"])

# Map each real wrapper to a methodology phase for the SBOM grouping.
_PHASE_BY_TOOL = {
    "subfinder": "Reconnaissance", "naabu": "Reconnaissance", "httpx": "Reconnaissance",
    "dnsx": "Reconnaissance", "katana": "Reconnaissance", "gau": "Reconnaissance",
    "nmap": "Reconnaissance",
    "nuclei": "Scanning & enumeration", "ffuf": "Scanning & enumeration",
    "wafw00f": "Scanning & enumeration", "whatweb": "Scanning & enumeration",
    "nikto": "Scanning & enumeration", "testssl": "Scanning & enumeration",
    "sqlmap": "Exploitation", "dalfox": "Exploitation", "commix": "Exploitation",
    "wpscan": "Exploitation",
    "mitmproxy": "Capture & analysis",
}
_PHASE_ORDER = ["Reconnaissance", "Scanning & enumeration", "Exploitation",
                "Capture & analysis", "Other"]


@router.get("/api/tools")
async def tools() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for w in available_wrappers():
        name = w["name"]
        out.append({
            "name": name,
            "version": None,                 # not introspected; UI shows "-"
            "source": w.get("category") or "",
            "phase": _PHASE_BY_TOOL.get(name, "Other"),
            "available": bool(w["available"]),
        })
    out.sort(key=lambda t: (_PHASE_ORDER.index(t["phase"]) if t["phase"] in _PHASE_ORDER else 99,
                            t["name"]))
    return out


@router.get("/api/dashboard")
async def dashboard() -> Dict[str, Any]:
    async with db.acquire() as conn:
        active = int(await conn.fetchval(
            "SELECT COUNT(*) FROM engagements WHERE status = 'authorized'"))
        running = int(await conn.fetchval(
            "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')"))
        sev_rows = await conn.fetch(
            "SELECT severity, COUNT(*) AS n FROM validated_findings "
            "WHERE status = 'confirmed' GROUP BY severity")
        usage = await conn.fetchrow(
            "SELECT COUNT(*) AS calls, COALESCE(SUM(prompt_tokens),0) AS pt, "
            "COALESCE(SUM(completion_tokens),0) AS ct, COALESCE(SUM(cost_usd),0) AS cost "
            "FROM llm_usage")
        by_model_rows = await conn.fetch(
            "SELECT model, COALESCE(SUM(prompt_tokens+completion_tokens),0) AS tok "
            "FROM llm_usage GROUP BY model ORDER BY tok DESC")

    sev = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for r in sev_rows:
        sev[(r["severity"] or "info").lower()] = int(r["n"])

    total_tokens = int(usage["pt"]) + int(usage["ct"])
    by_model = []
    for r in by_model_rows:
        tok = int(r["tok"])
        by_model.append({
            "model": r["model"] or "(unknown)",
            "tokens": tok,
            "pct": round(tok / total_tokens * 100) if total_tokens else 0,
        })

    return {
        "active_engagements": active,
        "running_jobs": running,
        "confirmed_findings": sev,
        "llm_usage": {
            "calls": int(usage["calls"]),
            "total_tokens": total_tokens,
            "cost_usd": round(float(usage["cost"]), 4),
            "by_model": by_model,
        },
    }
