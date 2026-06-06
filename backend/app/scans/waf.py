"""WAF-aware exploitation: adapt active tools when a WAF is fingerprinted.

When wafw00f detects a WAF, the executor records a `waf:<name>` fingerprint in
the engagement state. The runner then prepends evasion/throttle options to the
active exploitation tools so they have a chance against the filter (and don't
get the source IP blocked), mirroring what a human operator would do.

Pure and side-effect free, so it's easy to unit test.
"""
from __future__ import annotations

from typing import List, Sequence

# Per-tool evasion + throttling applied only when a WAF is present.
_WAF_ARGS = {
    # tamper transforms + a real UA + a small delay to dodge signatures/rate.
    "sqlmap": ["--random-agent", "--tamper=between,space2comment,charencode", "--delay=1"],
    "commix": ["--random-agent", "--delay=1"],
    "dalfox": ["--delay", "100"],          # ms between requests
    "nuclei": ["-rate-limit", "20"],       # cap req/s
    "ffuf": ["-rate", "20"],
}


def is_waf_tech(techs: Sequence[str]) -> bool:
    """True if the engagement state carries a WAF fingerprint."""
    return any(str(t).lower().startswith("waf:") for t in (techs or []))


def waf_args(tool: str) -> List[str]:
    """Evasion/throttle options for a tool when a WAF is present (else empty)."""
    return list(_WAF_ARGS.get(tool, []))
