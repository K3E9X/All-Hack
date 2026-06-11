"""dalfox: parameter-analysis XSS scanner."""
from __future__ import annotations

import json
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult


class DalfoxWrapper(BaseWrapper):
    name = "dalfox"
    binary = "dalfox"
    description = "Context-aware XSS scanner for URLs and pipelines."
    category = "xss"
    timeout_seconds = 20 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "url", target,
            "--format", "json",
            "--silence",
            "--no-color",
            "--mining-dom",          # discover injectable params from the DOM
            "--mining-dict",         # + dictionary-based param mining
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        text = stdout.decode("utf-8", errors="replace").strip()
        if not text:
            return ToolResult(findings=[])

        # dalfox can emit either a JSON array or one object per line.
        entries = []
        try:
            parsed = json.loads(text)
            entries = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        findings: List[Finding] = []
        for obj in entries:
            if not isinstance(obj, dict):
                continue
            severity = (obj.get("severity") or "medium").lower()
            findings.append(
                Finding(
                    severity=severity,
                    title=obj.get("type") or "XSS candidate",
                    description=obj.get("message") or obj.get("poc") or "",
                    target=obj.get("data") or obj.get("url") or target,
                    evidence=obj.get("payload") or obj.get("poc") or "",
                    metadata={
                        "method": obj.get("method"),
                        "param": obj.get("param"),
                        "cwe": obj.get("cwe"),
                        "tool": "dalfox",
                    },
                )
            )
        return ToolResult(findings=findings)
