"""testssl.sh: TLS/SSL security audit (ciphers, protocol versions, CVEs).

testssl.sh is a bash script (not a Go binary). We invoke it with
--jsonfile-pretty /dev/stdout so we get a JSON array on stdout, then
map each entry's severity to our scale.
"""
from __future__ import annotations

import json
from typing import List, Sequence
from urllib.parse import urlparse

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult


# testssl severities -> our scale.
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "low",
    "INFO": "info",
    "OK": "info",
    "DEBUG": "info",
}

# Entries with these severities are quietly dropped - they are pure
# informational output (protocol ok, etc.) and would swamp the finding list.
_DROP_SEVERITIES = {"OK", "INFO", "DEBUG"}


class TestsslWrapper(BaseWrapper):
    name = "testssl"
    binary = "testssl.sh"
    description = "TLS/SSL audit: ciphers, protocol versions, TLS CVEs, cert info."
    category = "tls"
    timeout_seconds = 30 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        host_port = _target_to_hostport(target)
        cmd = [
            self.binary,
            "--jsonfile-pretty", "/dev/stdout",
            "--quiet",
            "--color", "0",
            "--fast",
            "--sneaky",
            host_port,
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        text = stdout.decode("utf-8", errors="replace").strip()
        if not text:
            return ToolResult(findings=findings)

        # testssl may prepend a preamble before the JSON array on some
        # systems; find the first '[' to locate the JSON.
        start = text.find("[")
        if start == -1:
            return ToolResult(findings=findings)

        try:
            entries = json.loads(text[start:])
        except json.JSONDecodeError:
            return ToolResult(findings=findings)

        if not isinstance(entries, list):
            return ToolResult(findings=findings)

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            raw_sev = (entry.get("severity") or "INFO").upper()
            if raw_sev in _DROP_SEVERITIES:
                continue

            severity = _SEVERITY_MAP.get(raw_sev, "info")
            fid = entry.get("id") or "finding"
            finding_text = entry.get("finding") or ""
            cve = entry.get("cve") or ""
            cwe = entry.get("cwe") or ""

            findings.append(
                Finding(
                    severity=severity,
                    title=f"TLS: {fid}",
                    description=finding_text,
                    target=target,
                    evidence=finding_text,
                    metadata={
                        "testssl_id": fid,
                        "testssl_severity": raw_sev,
                        "cve": cve,
                        "cwe": cwe,
                        "ip": entry.get("ip"),
                        "port": entry.get("port"),
                    },
                )
            )
        return ToolResult(findings=findings)


def _target_to_hostport(target: str) -> str:
    """testssl expects 'host' or 'host:port'. Accept URLs too."""
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return f"{host}:{port}"
    return target if ":" in target else f"{target}:443"
