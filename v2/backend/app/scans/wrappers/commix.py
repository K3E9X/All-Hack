"""commix: automated command-injection exploitation.

commix is a Python tool (git checkout, no JSON output) so we run it in
--batch mode and parse its human-readable stdout for the vulnerability
verdict lines.
"""
from __future__ import annotations

import re
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

# commix prints lines like:
#   [+] The (GET) 'id' parameter is vulnerable to ... command injection.
_VULN_LINE = re.compile(
    r"the\s*\((?P<method>[A-Z]+)\)\s*'?(?P<param>[^'\s]+)'?\s*parameter is vulnerable",
    re.IGNORECASE,
)
_TECHNIQUE = re.compile(r"vulnerable to (?P<tech>[^.\n]+)", re.IGNORECASE)


class CommixWrapper(BaseWrapper):
    name = "commix"
    binary = "commix"
    description = "Automated OS command-injection detection and exploitation."
    category = "injection"
    timeout_seconds = 30 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "--url", target,
            "--batch",            # non-interactive
            "--disable-coloring",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        text = stdout.decode("utf-8", errors="replace")
        findings: List[Finding] = []
        seen = set()

        for m in _VULN_LINE.finditer(text):
            method = m.group("method").upper()
            param = m.group("param")
            key = (method, param)
            if key in seen:
                continue
            seen.add(key)

            # Look for a technique description near this match.
            tail = text[m.end(): m.end() + 200]
            tech_m = _TECHNIQUE.search(m.group(0) + tail)
            technique = tech_m.group("tech").strip() if tech_m else "OS command injection"

            findings.append(
                Finding(
                    severity="critical",
                    title=f"Command injection in '{param}' ({method})",
                    description=f"commix confirmed {technique} via parameter '{param}'.",
                    target=target,
                    evidence=m.group(0).strip(),
                    metadata={
                        "parameter": param,
                        "method": method,
                        "technique": technique,
                        "tool": "commix",
                    },
                )
            )
        return ToolResult(findings=findings)
