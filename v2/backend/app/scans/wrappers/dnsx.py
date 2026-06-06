"""dnsx: DNS resolution / record toolkit (ProjectDiscovery).

Resolves the target host and reports A/AAAA/CNAME records as info findings.
Useful for mapping infra and spotting CNAMEs that hint at takeover targets.
"""
from __future__ import annotations

import json
from typing import List, Sequence
from urllib.parse import urlparse

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult


class DnsxWrapper(BaseWrapper):
    name = "dnsx"
    binary = "dnsx"
    description = "DNS toolkit: resolve A/AAAA/CNAME and other records."
    timeout_seconds = 10 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        host = _target_to_host(target)
        cmd = [
            self.binary,
            "-d", host,
            "-json",
            "-silent",
            "-a", "-aaaa", "-cname",
            "-resp",
        ]
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
            host = obj.get("host") or _target_to_host(target)
            a = obj.get("a") or []
            aaaa = obj.get("aaaa") or []
            cname = obj.get("cname") or []

            records = []
            if a:
                records.append("A: " + ", ".join(a))
            if aaaa:
                records.append("AAAA: " + ", ".join(aaaa))
            if cname:
                records.append("CNAME: " + ", ".join(cname))
            if not records:
                continue

            findings.append(
                Finding(
                    severity="info",
                    title=f"DNS records for {host}",
                    description="; ".join(records),
                    target=host,
                    evidence="; ".join(records),
                    metadata={"a": a, "aaaa": aaaa, "cname": cname, "tool": "dnsx"},
                )
            )
        return ToolResult(findings=findings)


def _target_to_host(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or target).lower()
    return target.split("/", 1)[0].split(":", 1)[0].lower()
