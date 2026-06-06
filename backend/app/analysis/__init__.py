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

logger = logging.getLogger("allhack.analysis")

__all__ = ["analyze_logic", "analyze_js", "analyze_jwt",
           "analyze_access_control", "analyze_cors", "run_analysis"]


async def run_analysis(engagement_id: str) -> Dict[str, Dict]:
    """Run every traffic-driven analyzer. Each is isolated so a failure in one
    (e.g. malformed flow) doesn't abort the rest."""
    out: Dict[str, Dict] = {}
    for name, fn in (
        ("js_recon", analyze_js),            # first: may seed new endpoints
        ("logic", analyze_logic),
        ("jwt", analyze_jwt),
        ("access_control", analyze_access_control),
        ("cors", analyze_cors),
    ):
        try:
            out[name] = await fn(engagement_id)
        except Exception:  # noqa: BLE001
            logger.exception("[%s] analyzer %s failed", engagement_id, name)
            out[name] = {"error": 1}
    return out
