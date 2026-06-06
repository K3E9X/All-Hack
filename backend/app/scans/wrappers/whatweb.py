"""whatweb: web technology fingerprinting.

Emits one JSON object per target (we request `--log-json=-`). Each detected
plugin becomes an info-severity Finding so the planner knows the stack
(framework, CMS, server, language) before choosing attacks.
"""
from __future__ import annotations

import json
from typing import Any, List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult


class WhatwebWrapper(BaseWrapper):
    name = "whatweb"
    binary = "whatweb"
    description = "Identify web technologies: CMS, framework, server, language."
    category = "fingerprint"
    timeout_seconds = 10 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "--log-json=-",     # JSON to stdout
            "--color=never",
            "-a", "3",          # aggression level 3 (a bit more than default)
            target,
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        text = stdout.decode("utf-8", errors="replace").strip()
        if not text:
            return ToolResult(findings=[])

        entries: List[dict] = []
        # whatweb --log-json emits either a JSON array or one object per line.
        try:
            parsed = json.loads(text)
            entries = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        findings: List[Finding] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            uri = entry.get("target") or target
            plugins = entry.get("plugins") or {}
            if not isinstance(plugins, dict):
                continue
            for name, data in plugins.items():
                detail = _plugin_detail(data)
                findings.append(
                    Finding(
                        severity="info",
                        title=f"Technology: {name}" + (f" {detail}" if detail else ""),
                        description=f"whatweb fingerprinted {name} on {uri}.",
                        target=uri,
                        evidence=f"{name}: {detail}" if detail else name,
                        metadata={"plugin": name, "data": data, "tool": "whatweb"},
                    )
                )
        return ToolResult(findings=findings)


def _plugin_detail(data: Any) -> str:
    """whatweb plugin values are dicts of lists (version/string/etc.)."""
    if not isinstance(data, dict):
        return ""
    bits: List[str] = []
    for key in ("version", "string", "module"):
        val = data.get(key)
        if isinstance(val, list) and val:
            bits.append(", ".join(str(v) for v in val))
    return " ".join(bits)
