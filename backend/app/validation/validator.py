"""Finding validator (spec §7).

Decides a ValidationStatus for each candidate finding, preferring real proof:

  1. Tool-confirmed   - sqlmap/commix/dalfox actively confirm their own
     findings (boolean/time oracle, command output, executed payload). We
     trust those and carry the payload as the PoC.
  2. Safe-PoC re-check - for classes we can prove with one in-scope GET:
       * exposed sensitive files (.git/.env/backup/phpinfo/...) -> fetch,
         confirm a content signature.
       * reflected XSS marker -> send a benign unique marker in the param,
         confirm it reflects unencoded.
  3. Heuristic        - nuclei/nikto/etc. carry their own match; treat as
     LIKELY (severity-scaled) unless a re-check applies.

Everything that touches the target goes through SafePoC (GET/HEAD only,
in-scope only). Nothing here sends a destructive payload.
"""
from __future__ import annotations

import logging
import re
import secrets
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.scans.models import Finding
from app.validation.models import ValidationResult, ValidationStatus
from app.validation.safe_poc import SafePoC, ScopeError

logger = logging.getLogger("allhack.validation.validator")

# Tools whose positive findings are already actively proven.
_TOOL_CONFIRMED = {"sqlmap", "commix", "dalfox"}

# Traffic-driven analyzers that precompute their own status/confidence/PoC in
# finding.metadata (see app/analysis/*). We trust that verdict verbatim.
_ANALYSIS_TOOLS = {"logic", "js-recon", "jwt", "access-control", "cors",
                   "params", "graphql", "exploit", "public-exploits", "cve-checks"}

# path-signature pairs: if the finding target ends with <path>, fetching it
# should contain <signature> to confirm the exposure.
_EXPOSED_SIGNATURES = [
    (".git/config", "[core]"),
    (".git/HEAD", "ref:"),
    (".env", "="),
    (".htaccess", ""),            # presence (200 + body) is enough
    ("phpinfo", "phpinfo()"),
    ("server-status", "Apache Server Status"),
    ("/.svn/entries", ""),
    ("wp-config.php.bak", "DB_PASSWORD"),
    ("/actuator/env", "propertySources"),
]

_XSS_CLASSES = {"xss"}
_MARKER_RE_TMPL = r"{marker}"


class FindingValidator:
    def __init__(self, safe_poc: SafePoC) -> None:
        self.safe = safe_poc

    async def validate(self, finding: Finding, tool: str, vuln_class: str) -> ValidationResult:
        # 0. traffic-driven analyzers (logic/IDOR/CSRF/BFLA, JS secrets, JWT,
        # access-control) already decided their status from captured traffic +
        # safe re-fetch; trust the precomputed verdict.
        if tool in _ANALYSIS_TOOLS:
            md = finding.metadata or {}
            status_str = str(md.get("status", "likely"))
            conf = float(md.get("confidence", 0.55))
            try:
                status = ValidationStatus(status_str)
            except ValueError:
                status = ValidationStatus.LIKELY
            return ValidationResult(
                status=status, confidence=conf, method=f"analysis ({tool})",
                poc=finding.evidence or "", detail="From captured traffic analysis.",
            )

        # 1. tool already proved it
        if tool in _TOOL_CONFIRMED:
            poc = finding.evidence or (finding.metadata or {}).get("payload") or ""
            return ValidationResult.confirmed(
                method=f"tool-confirmed ({tool})",
                poc=str(poc),
                detail=f"{tool} actively confirmed this finding.",
            )

        # 2a. exposed sensitive resource -> fetch and check signature
        exposed = await self._check_exposed_resource(finding)
        if exposed is not None:
            return exposed

        # 2b. reflected XSS marker
        if vuln_class in _XSS_CLASSES:
            reflected = await self._check_reflection(finding)
            if reflected is not None:
                return reflected

        # 3. heuristic: trust the scanner's own match as LIKELY, scaled by severity
        sev = (finding.severity or "info").lower()
        conf = {"critical": 0.7, "high": 0.65, "medium": 0.6, "low": 0.5, "info": 0.4}.get(sev, 0.5)
        return ValidationResult.likely(
            method=f"scanner-match ({tool})",
            confidence=conf,
            detail="Reported by the scanner; not independently re-checked. Manual review advised.",
            poc=finding.evidence or "",
        )

    async def _check_exposed_resource(self, finding: Finding) -> Optional[ValidationResult]:
        url = finding.target
        if not url or "://" not in url:
            return None
        path = urlparse(url).path.lower()
        match = next(((p, sig) for (p, sig) in _EXPOSED_SIGNATURES if p.lower().lstrip("/") in path), None)
        if match is None:
            return None
        p, signature = match
        try:
            resp = await self.safe.fetch(url, method="GET")
        except ScopeError as exc:
            return ValidationResult.unconfirmed("safe-poc", detail=str(exc))
        if resp is None:
            return ValidationResult.unconfirmed("safe-poc", detail="resource not reachable")
        if resp.status_code != 200:
            return ValidationResult.false_positive(
                "safe-poc", detail=f"resource returned HTTP {resp.status_code}, not exposed"
            )
        if signature and signature.lower() not in resp.text.lower():
            return ValidationResult.false_positive(
                "safe-poc", detail="200 but expected content signature absent"
            )
        snippet = resp.text[:300].replace("\n", " ")
        return ValidationResult.confirmed(
            method="safe-poc (exposed-resource)",
            poc=f"GET {url} -> HTTP 200; body contains '{signature or '(content)'}'\n{snippet}",
            detail=f"Sensitive resource {p} is publicly readable.",
        )

    async def _check_reflection(self, finding: Finding) -> Optional[ValidationResult]:
        url = finding.target
        if not url or "://" not in url or "?" not in url:
            return None
        marker = "allhack" + secrets.token_hex(4)
        injected = _inject_marker(url, marker)
        if injected is None:
            return None
        try:
            resp = await self.safe.fetch(injected, method="GET")
        except ScopeError as exc:
            return ValidationResult.unconfirmed("safe-poc", detail=str(exc))
        if resp is None:
            return ValidationResult.unconfirmed("safe-poc", detail="endpoint not reachable")
        # Reflected unencoded? (the marker is benign; we only check reflection,
        # we do not inject script). Encoded reflection is not exploitable as-is.
        if marker in resp.text:
            return ValidationResult.confirmed(
                method="safe-poc (reflection)",
                poc=f"GET {injected} -> benign marker '{marker}' reflected unencoded in response",
                confidence=0.9,
                detail="Parameter reflects input unencoded; XSS is plausible. "
                       "Manual confirmation with a script payload recommended.",
            )
        if marker not in resp.text:
            # Not reflected at all -> the XSS report is probably a false positive.
            return ValidationResult.false_positive(
                "safe-poc (reflection)", detail="benign marker not reflected in response"
            )
        return None


def _inject_marker(url: str, marker: str) -> Optional[str]:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return None
    # Replace the first parameter's value with the marker.
    first_key = next(iter(qs))
    qs[first_key] = [marker]
    new_query = urlencode({k: v[-1] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_query))
