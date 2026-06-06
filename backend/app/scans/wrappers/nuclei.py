"""nuclei: fast template-based scanner (ProjectDiscovery).

Runs with `-jsonl` so each finding is a single JSON object per line on stdout.
"""
from __future__ import annotations

import json
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

            findings.append(
                Finding(
                    severity=severity,
                    title=info.get("name") or template_id or "nuclei finding",
                    description=info.get("description") or "",
                    target=matched_url,
                    evidence=_evidence(obj),
                    metadata={
                        "template_id": template_id,
                        "tags": info.get("tags"),
                        "reference": info.get("reference"),
                        "classification": info.get("classification"),
                        "curl_command": obj.get("curl-command"),
                    },
                )
            )
        return ToolResult(findings=findings)


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
