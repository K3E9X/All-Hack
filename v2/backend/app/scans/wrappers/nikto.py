"""nikto: classic web-server misconfiguration scanner.

Catches the obvious: dangerous methods, server-status, backup/old files,
outdated server banners, default files. We request JSON to stdout and parse
the vulnerabilities array.
"""
from __future__ import annotations

import json
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult


class NiktoWrapper(BaseWrapper):
    name = "nikto"
    binary = "nikto"
    description = "Web server scanner: misconfig, dangerous files/methods, banners."
    timeout_seconds = 30 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "-h", target,
            "-Format", "json",
            "-output", "/dev/stdout",
            "-nointeractive",
            "-ask", "no",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        text = stdout.decode("utf-8", errors="replace").strip()
        if not text:
            return ToolResult(findings=[])

        # nikto prints scan progress mixed with the JSON object; isolate the JSON.
        start = text.find("{")
        if start == -1:
            return ToolResult(findings=[])
        # nikto may emit multiple JSON objects; take the last complete one.
        candidates = []
        depth = 0
        buf_start = None
        for i, ch in enumerate(text):
            if ch == "{":
                if depth == 0:
                    buf_start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and buf_start is not None:
                    candidates.append(text[buf_start : i + 1])
                    buf_start = None

        data = None
        for cand in reversed(candidates):
            try:
                data = json.loads(cand)
                break
            except json.JSONDecodeError:
                continue
        if not isinstance(data, dict):
            return ToolResult(findings=[])

        host = data.get("host") or target
        findings: List[Finding] = []
        for vuln in data.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            msg = vuln.get("msg") or ""
            url = vuln.get("url") or host
            method = vuln.get("method") or "GET"
            osvdb = vuln.get("OSVDB") or vuln.get("id") or ""
            findings.append(
                Finding(
                    severity="low",
                    title=f"nikto: {msg[:90]}" if msg else "nikto finding",
                    description=msg,
                    target=url,
                    evidence=f"{method} {url} (OSVDB:{osvdb})",
                    metadata={"osvdb": osvdb, "method": method, "tool": "nikto"},
                )
            )
        return ToolResult(findings=findings)
