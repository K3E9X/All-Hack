"""sqlmap: the reference SQL injection tool.

We run it in batch mode against a single URL. sqlmap writes structured output
to an `--output-dir`; we read `log` (human readable summary) and the target
session file to extract confirmed findings.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

_FINDING_BLOCK = re.compile(
    r"Parameter:\s*(?P<param>[^\s]+).*?Type:\s*(?P<type>[^\n]+).*?Title:\s*(?P<title>[^\n]+).*?Payload:\s*(?P<payload>[^\n]+)",
    re.DOTALL,
)


class SqlmapWrapper(BaseWrapper):
    name = "sqlmap"
    binary = "sqlmap"
    description = "Automatic SQL injection and database takeover tool."
    category = "injection"
    timeout_seconds = 45 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "-u", target,
            "--batch",          # no interactive prompts
            "--random-agent",
            "--level=2",
            "--risk=2",
            "--disable-coloring",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        text = stdout.decode("utf-8", errors="replace")
        findings: List[Finding] = []

        # Look for sqlmap's standard "Parameter: ... Type: ... Title: ... Payload: ..." blocks
        for match in _FINDING_BLOCK.finditer(text):
            param = match.group("param").strip()
            injection_type = match.group("type").strip()
            title = match.group("title").strip()
            payload = match.group("payload").strip()

            findings.append(
                Finding(
                    severity="high",
                    title=f"SQL injection in parameter '{param}'",
                    description=(
                        f"{injection_type} injection: {title}. "
                        "Confirmed by sqlmap."
                    ),
                    target=target,
                    evidence=f"Payload: {payload}",
                    metadata={
                        "parameter": param,
                        "injection_type": injection_type,
                        "technique_title": title,
                    },
                )
            )

        # If sqlmap concluded there was no injection and we still returned 0, leave it at 0.
        return ToolResult(findings=findings)
