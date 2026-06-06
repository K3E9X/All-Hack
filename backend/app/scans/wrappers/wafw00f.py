"""wafw00f: web application firewall fingerprinting.

Informational on its own, but valuable strategy input: the planner adapts
payloads / rate when a WAF is present. wafw00f's text output is stable, so
we parse stdout lines rather than fight its JSON file flag.
"""
from __future__ import annotations

import re
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

# "The site https://x is behind Cloudflare (Cloudflare Inc.) WAF."
_BEHIND = re.compile(r"is behind\s+(?P<waf>.+?)\s+WAF", re.IGNORECASE)
_NO_WAF = re.compile(r"No WAF detected", re.IGNORECASE)


class Wafw00fWrapper(BaseWrapper):
    name = "wafw00f"
    binary = "wafw00f"
    description = "Detect and fingerprint Web Application Firewalls."
    category = "waf"
    timeout_seconds = 5 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [self.binary, target, "-a"]  # -a = test all known WAFs
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        text = stdout.decode("utf-8", errors="replace")
        findings: List[Finding] = []

        for m in _BEHIND.finditer(text):
            waf = m.group("waf").strip()
            findings.append(
                Finding(
                    severity="info",
                    title=f"WAF detected: {waf}",
                    description=(
                        f"Target is behind a {waf} WAF. Tune payloads and rate "
                        "accordingly; some scanners will be blocked."
                    ),
                    target=target,
                    evidence=m.group(0).strip(),
                    metadata={"waf": waf, "tool": "wafw00f"},
                )
            )

        if not findings and _NO_WAF.search(text):
            findings.append(
                Finding(
                    severity="info",
                    title="No WAF detected",
                    description="wafw00f did not fingerprint a WAF on this target.",
                    target=target,
                    evidence="No WAF detected",
                    metadata={"tool": "wafw00f"},
                )
            )
        return ToolResult(findings=findings)
