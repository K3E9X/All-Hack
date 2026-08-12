"""Pure helpers for the global findings view (no web framework imports, so they
stay unit-testable): dedup key, CVSS estimate, HackerOne-format export."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

TRIAGE_STATUSES = {"new", "triaged", "confirmed", "reported", "false_positive"}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CVSS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.1, "info": 1.0}


def dedup(vuln_class: str, target: str) -> str:
    return hashlib.sha1(f"{vuln_class}|{target}".encode()).hexdigest()[:16]


def cvss_for(severity: str) -> float:
    return CVSS.get((severity or "info").lower(), 1.0)


def h1_markdown(f, mapping: Dict[str, Any], cvss: float) -> str:
    """HackerOne-style report markdown for a single validated finding."""
    L: List[str] = []
    L.append(f"# {f.title}")
    L.append("")
    L.append(f"**Severity:** {f.severity} (CVSS ~{cvss})  ")
    L.append(f"**Asset:** `{f.target}`  ")
    L.append(f"**Weakness:** {mapping['cwe']} / {mapping['wstg']} / {', '.join(mapping['attack'])}")
    L.append("")
    L.append("## Summary")
    L.append((f.metadata or {}).get("description") or f.title)
    L.append("")
    L.append("## Steps To Reproduce")
    L.append("```")
    L.append((f.poc or f.evidence or "(see evidence)").strip()[:2000])
    L.append("```")
    if f.evidence and f.evidence != f.poc:
        L.append("")
        L.append("## Evidence")
        L.append("```")
        L.append(f.evidence.strip()[:2000])
        L.append("```")
    L.append("")
    L.append("## Impact")
    L.append(f"Confirmed by syphax ({f.tool}, status: {f.status}). " + (mapping.get("remediation") or ""))
    L.append("")
    L.append("## Remediation")
    L.append(mapping.get("remediation") or "Apply standard hardening for this class.")
    return "\n".join(L)
