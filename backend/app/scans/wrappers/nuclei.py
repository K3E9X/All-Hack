"""nuclei: fast template-based scanner (ProjectDiscovery).

Runs with `-jsonl` so each finding is a single JSON object per line on stdout.
"""
from __future__ import annotations

import json
import os
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult


class NucleiWrapper(BaseWrapper):
    name = "nuclei"
    binary = "nuclei"
    description = "Template-based vulnerability scanner (4000+ community templates)."
    category = "vuln"
    timeout_seconds = 30 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        # Out-of-band: nuclei confirms blind SSRF/XXE/RCE via interactsh. By
        # default it uses ProjectDiscovery's free public servers (oast.*); set
        # INTERACTSH_SERVER in .env to point at a self-hosted instance.
        interactsh = os.environ.get("INTERACTSH_SERVER", "").strip()
        cmd = [
            self.binary,
            "-u", target,
            "-jsonl",
            "-silent",
            "-disable-update-check",
            "-stats=false",
            "-no-color",
        ]
        # Default severity floor, unless the caller set its own (e.g. an
        # exposures scan also wants info-level).
        if "-severity" not in options and "-s" not in options:
            cmd += ["-severity", "low,medium,high,critical"]
        if interactsh and "-interactsh-server" not in options:
            cmd += ["-interactsh-server", interactsh]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = obj.get("info") or {}
            severity = (info.get("severity") or "info").lower()
            template_id = obj.get("template-id") or obj.get("templateID") or ""
            matched_url = obj.get("matched-at") or obj.get("matched") or target
            tags = info.get("tags")

            findings.append(
                Finding(
                    severity=severity,
                    title=info.get("name") or template_id or "nuclei finding",
                    description=info.get("description") or "",
                    target=matched_url,
                    evidence=_evidence(obj),
                    metadata={
                        "template_id": template_id,
                        "tags": tags,
                        "reference": info.get("reference"),
                        "classification": info.get("classification"),
                        "curl_command": obj.get("curl-command"),
                        # Classify each finding from its template tags so SSRF /
                        # SSTI / LFI / XXE / ... are reported as themselves rather
                        # than lumped under the generic "multiple".
                        "vuln_class": _classify(tags, template_id),
                    },
                )
            )
        return ToolResult(findings=findings)


# Template tag (substring) -> vuln_class. First match wins; order matters
# (more specific before generic).
_TAG_CLASS = [
    (("sqli", "sql-injection", "error-based-sql", "blind-sql"), "sql_injection"),
    (("xss", "rxss", "dom-xss"), "xss"),
    (("ssrf",), "ssrf"),
    (("ssti",), "ssti"),
    (("xxe",), "xxe"),
    (("lfi", "fileinclusion", "file-inclusion", "traversal", "path-traversal"), "lfi"),
    (("rce", "cmdi", "command-injection", "oast-rce"), "command_injection"),
    (("redirect", "open-redirect", "openredirect"), "open_redirect"),
    (("takeover", "subdomain-takeover"), "subdomain_takeover"),
    (("cors",), "cors"),
    (("default-login", "auth-bypass", "auth-bypas", "weak-cred"), "auth"),
    (("exposure", "exposures", "disclosure", "backup", "config"), "exposed_resource"),
    (("ssl", "tls"), "weak_tls"),
    (("wordpress", "wp-plugin", "joomla", "drupal"), "cms_vulnerability"),
]


def _classify(tags, template_id: str) -> str:
    bag = set()
    if isinstance(tags, str):
        bag = {t.strip().lower() for t in tags.split(",") if t.strip()}
    elif isinstance(tags, (list, tuple)):
        bag = {str(t).strip().lower() for t in tags}
    tid = (template_id or "").lower()
    for needles, vclass in _TAG_CLASS:
        if bag.intersection(needles) or any(n in tid for n in needles):
            return vclass
    return "multiple"


def _evidence(obj: dict) -> str:
    bits = []
    for key in ("matcher-name", "extracted-results", "request", "response"):
        val = obj.get(key)
        if val:
            if isinstance(val, list):
                bits.append(f"{key}: {', '.join(str(v) for v in val)}")
            else:
                bits.append(f"{key}: {str(val)[:400]}")
    return "\n".join(bits)
