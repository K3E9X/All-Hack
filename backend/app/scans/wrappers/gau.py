"""gau (GetAllUrls): historical URLs from Wayback / Common Crawl / OTX / URLScan.

Expands the attack surface with paths and parameters that aren't linked from
the live site anymore. Plain URLs on stdout (one per line); we de-duplicate
and cap to keep finding volume sane.
"""
from __future__ import annotations

from typing import List, Sequence
from urllib.parse import urlparse

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

MAX_URLS = 2000


class GauWrapper(BaseWrapper):
    name = "gau"
    binary = "gau"
    description = "Fetch known URLs from Wayback/Common Crawl/OTX for a domain."
    category = "recon"
    timeout_seconds = 15 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        host = _target_to_host(target)
        # gau takes the domain as a positional arg.
        cmd = [self.binary, host, "--threads", "5"]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        seen = set()
        findings: List[Finding] = []
        for raw in stdout.decode("utf-8", "replace").splitlines():
            url = raw.strip()
            if not url or url in seen:
                continue
            seen.add(url)
            # Flag URLs with query parameters as more interesting (testable inputs).
            has_params = "?" in url and "=" in url
            findings.append(
                Finding(
                    severity="info",
                    title=("Historical URL with params: " if has_params else "Historical URL: ") + url[:120],
                    description="Discovered via gau (archive sources).",
                    target=url,
                    evidence=url,
                    metadata={"has_params": has_params, "tool": "gau"},
                )
            )
            if len(findings) >= MAX_URLS:
                break
        return ToolResult(findings=findings)


def _target_to_host(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or target).lower()
    return target.split("/", 1)[0].split(":", 1)[0].lower()
