"""wpscan: WordPress-specific scanner (plugins, themes, users, CVEs).

Without a WPScan API token the scanner still detects installed plugins /
themes / users, enumerates the WP version, and flags common misconfigs,
but the CVE database lookup is skipped. Users can set WPSCAN_API_TOKEN
in .env (25 free requests/day per address on wpscan.com) to enable it.
"""
from __future__ import annotations

import json
import os
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult


class WpscanWrapper(BaseWrapper):
    name = "wpscan"
    binary = "wpscan"
    description = "WordPress scanner: plugins, themes, users, vulnerabilities."
    category = "cms"
    timeout_seconds = 30 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "--url", target,
            "--format", "json",
            "--no-banner",
            "--random-user-agent",
            "--disable-tls-checks",
            "--enumerate", "vp,vt,u",  # vulnerable plugins, themes, users
        ]
        token = os.environ.get("WPSCAN_API_TOKEN")
        if token:
            cmd.extend(["--api-token", token])
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        text = stdout.decode("utf-8", errors="replace").strip()
        if not text:
            return ToolResult(findings=findings)

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ToolResult(findings=findings)

        if not isinstance(data, dict):
            return ToolResult(findings=findings)

        # WP core version + its vulns
        wp = data.get("version") or {}
        wp_version = wp.get("number")
        if wp_version:
            for vuln in wp.get("vulnerabilities") or []:
                findings.append(_wp_vuln_finding(vuln, target, f"WordPress core {wp_version}"))

        # Plugins
        for name, plugin in (data.get("plugins") or {}).items():
            version = (plugin.get("version") or {}).get("number") or "unknown"
            # One finding per plugin (info), plus one per vuln on that plugin.
            findings.append(
                Finding(
                    severity="info",
                    title=f"Plugin installed: {name} {version}",
                    description=plugin.get("location") or "",
                    target=target,
                    evidence=f"plugin={name} version={version}",
                    metadata={
                        "plugin": name,
                        "version": version,
                        "outdated": plugin.get("outdated"),
                    },
                )
            )
            for vuln in plugin.get("vulnerabilities") or []:
                findings.append(_wp_vuln_finding(vuln, target, f"Plugin {name} {version}"))

        # Themes
        for name, theme in (data.get("themes") or {}).items():
            version = (theme.get("version") or {}).get("number") or "unknown"
            findings.append(
                Finding(
                    severity="info",
                    title=f"Theme installed: {name} {version}",
                    description=theme.get("location") or "",
                    target=target,
                    evidence=f"theme={name} version={version}",
                    metadata={"theme": name, "version": version},
                )
            )
            for vuln in theme.get("vulnerabilities") or []:
                findings.append(_wp_vuln_finding(vuln, target, f"Theme {name} {version}"))

        # Enumerated users
        for login, user in (data.get("users") or {}).items():
            findings.append(
                Finding(
                    severity="low",
                    title=f"WordPress user enumerated: {login}",
                    description="Username disclosed by the WordPress installation.",
                    target=target,
                    evidence=f"login={login}",
                    metadata={"login": login, "id": user.get("id")},
                )
            )

        return ToolResult(findings=findings)


def _wp_vuln_finding(vuln: dict, target: str, component: str) -> Finding:
    title = vuln.get("title") or "WordPress vulnerability"
    refs = vuln.get("references") or {}
    cves = refs.get("cve") or []
    url_refs = refs.get("url") or []
    fixed_in = vuln.get("fixed_in")
    # wpscan does not always set a severity; default to high for a known CVE,
    # medium otherwise. Users can re-prioritize in the UI.
    severity = "high" if cves else "medium"
    return Finding(
        severity=severity,
        title=f"{component}: {title}",
        description=vuln.get("description") or "",
        target=target,
        evidence=(
            f"cve={','.join(cves)} fixed_in={fixed_in or 'n/a'} "
            f"refs={','.join(url_refs[:3])}"
        ),
        metadata={
            "component": component,
            "cve": cves,
            "fixed_in": fixed_in,
            "references": url_refs,
            "wpvulndb_id": vuln.get("id"),
        },
    )
