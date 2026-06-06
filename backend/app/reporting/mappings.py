"""vuln_class -> standards mapping for the report (WSTG / ATT&CK / CWE).

Validated findings carry a coarse vuln_class; the report enriches each with
the relevant OWASP WSTG id, MITRE ATT&CK technique(s), CWE and a default
remediation line. Unknown classes fall back to generic values.
"""
from __future__ import annotations

from typing import Any, Dict

MAPPING: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "wstg": "WSTG-INPV-05", "attack": ["T1190"], "cwe": "CWE-89",
        "remediation": "Use parameterized queries / prepared statements; never "
                       "concatenate user input into SQL. Apply least-privilege DB accounts.",
    },
    "command_injection": {
        "wstg": "WSTG-INPV-12", "attack": ["T1190"], "cwe": "CWE-78",
        "remediation": "Avoid shelling out with user input; use safe APIs and "
                       "strict allow-list validation. Drop privileges.",
    },
    "xss": {
        "wstg": "WSTG-INPV-01", "attack": ["T1059.007"], "cwe": "CWE-79",
        "remediation": "Context-aware output encoding, a strict CSP, and input "
                       "validation. Prefer framework auto-escaping.",
    },
    "misconfiguration": {
        "wstg": "WSTG-CONF-02", "attack": ["T1190"], "cwe": "CWE-16",
        "remediation": "Harden the server: disable dangerous methods and "
                       "directory listing, remove backup/old files, restrict admin paths.",
    },
    "weak_tls": {
        "wstg": "WSTG-CRYP-01", "attack": ["T1190"], "cwe": "CWE-326",
        "remediation": "Disable legacy protocols/ciphers (SSLv3/TLS1.0/1.1, RC4, "
                       "3DES); enable HSTS; keep certificates valid and strong.",
    },
    "cms_vulnerability": {
        "wstg": "WSTG-CONF-01", "attack": ["T1190"], "cwe": "CWE-1035",
        "remediation": "Update the CMS core, plugins and themes; remove unused "
                       "extensions; restrict user enumeration.",
    },
    "exposed_resource": {
        "wstg": "WSTG-CONF-04", "attack": ["T1592"], "cwe": "CWE-538",
        "remediation": "Remove publicly accessible source/config (.git, .env, "
                       "backups); block them at the web server.",
    },
    "multiple": {
        "wstg": "WSTG-CONF-01", "attack": ["T1190"], "cwe": "CWE-693",
        "remediation": "Review each templated finding individually and apply the "
                       "vendor's guidance.",
    },
    "auth": {
        "wstg": "WSTG-ATHN-01", "attack": ["T1110", "T1078"], "cwe": "CWE-287",
        "remediation": "Remove default/weak credentials, enforce strong auth and "
                       "rate limiting, and fix authentication-bypass paths.",
    },
    "idor": {
        "wstg": "WSTG-ATHZ-04", "attack": ["T1190"], "cwe": "CWE-639",
        "remediation": "Enforce object-level authorization server-side: check the "
                       "current user owns/may access every referenced object id.",
    },
    "csrf": {
        "wstg": "WSTG-SESS-05", "attack": ["T1190"], "cwe": "CWE-352",
        "remediation": "Require an anti-CSRF token (or SameSite=strict cookies + "
                       "origin checks) on all state-changing requests.",
    },
    "privilege_escalation": {
        "wstg": "WSTG-ATHZ-02", "attack": ["T1068", "T1078.003"], "cwe": "CWE-285",
        "remediation": "Enforce function-level authorization server-side: check the "
                       "caller's role/permissions on every privileged endpoint and "
                       "action; deny by default. Don't rely on hiding admin UI.",
    },
    "recon": {"wstg": "WSTG-INFO-02", "attack": ["T1595"], "cwe": "CWE-200", "remediation": "Reduce exposed surface; restrict information disclosure."},
    "fingerprint": {"wstg": "WSTG-INFO-08", "attack": ["T1592"], "cwe": "CWE-200", "remediation": "Suppress version banners where practical."},
}

_FALLBACK = {"wstg": "WSTG-INFO-00", "attack": ["T1595"], "cwe": "CWE-0",
             "remediation": "Review the finding and apply standard hardening."}


def for_class(vuln_class: str) -> Dict[str, Any]:
    return MAPPING.get((vuln_class or "").lower(), _FALLBACK)
