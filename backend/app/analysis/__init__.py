"""Application-layer analysis over captured proxy traffic.

Four analyzers, each saved as its own synthetic scan job so they stay cleanly
partitioned in the UI and the report:

  * logic            - IDOR/BOLA, CSRF, BFLA/privesc
  * js-recon         - secrets + hidden endpoints mined from JavaScript bundles
  * jwt              - JWT weaknesses (alg=none, weak HMAC, kid/jku, no exp)
  * access-control   - missing-auth replay, method-tampering & mass-assignment flags

`run_analysis` runs them all (best-effort: one failing analyzer never blocks
the others) and returns a merged summary.
"""
from __future__ import annotations

import logging
from typing import Dict

from app.analysis.logic import analyze_logic
from app.analysis.js_recon import analyze_js
from app.analysis.jwt_analysis import analyze_jwt
from app.analysis.access_control import analyze_access_control
from app.analysis.cors import analyze_cors
from app.analysis.param_discovery import analyze_params
from app.analysis.graphql import analyze_graphql
from app.analysis.public_exploits import analyze_public_exploits

logger = logging.getLogger("allhack.analysis")

__all__ = ["analyze_logic", "analyze_js", "analyze_jwt",
           "analyze_access_control", "analyze_cors", "analyze_params",
           "analyze_graphql", "analyze_public_exploits", "run_analysis"]


async def run_analysis(engagement_id: str, *, allow_active: bool = True) -> Dict[str, Dict]:
    """Run every traffic-driven analyzer. Each is isolated so a failure in one
    (e.g. malformed flow) doesn't abort the rest.

    `allow_active` lets the caller suppress the analyzers that send crafted
    exploit payloads (cve_checks) when exploitation was denied/stopped - they
    also self-gate on allow_active_exploit, this is the per-run override."""
    from app.exploit import run_cve_checks  # targeted CVE checks (safe-PoC GETs)
    steps = [
        ("js_recon", analyze_js),            # first: may seed new endpoints
        ("params", analyze_params),          # also seeds parameterised endpoints
        ("logic", analyze_logic),
        ("jwt", analyze_jwt),
        ("access_control", analyze_access_control),
        ("cors", analyze_cors),
        ("graphql", analyze_graphql),
    ]
    if allow_active:
        steps.append(("cve_checks", run_cve_checks))    # confirm high-value CVEs
    steps.append(("public_exploits", analyze_public_exploits))  # enriches CVE findings
    out: Dict[str, Dict] = {}
    for name, fn in steps:
        try:
            out[name] = await fn(engagement_id)
        except Exception:  # noqa: BLE001
            logger.exception("[%s] analyzer %s failed", engagement_id, name)
            out[name] = {"error": 1}
    return out
