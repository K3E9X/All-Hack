"""nmap: ports + service/version detection + NSE script results.

We run `nmap -sV -T4 -Pn -oX - <host>` and parse the XML: one finding per open
port, plus a finding for every NSE script result that indicates a vulnerability
(`--script vuln`, vulners, http-vuln-*), with CVE ids extracted.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from app.cve_refs import normalize_cve
from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CVSS_RE = re.compile(r"\b(10\.0|\d\.\d)\b")


class NmapWrapper(BaseWrapper):
    name = "nmap"
    binary = "nmap"
    description = "Port scanner, service fingerprinter and NSE vuln engine."
    category = "recon"
    timeout_seconds = 25 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        host = _target_to_host(target)
        cmd = [self.binary, "-sV", "-T4", "-Pn", "-oX", "-", host]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        if not stdout:
            return ToolResult(findings=findings)
        try:
            root = ET.fromstring(stdout.decode("utf-8", errors="replace"))
        except ET.ParseError:
            return ToolResult(findings=findings)

        host = _target_to_host(target)
        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            addr = addr_el.get("addr") if addr_el is not None else host

            ports_el = host_el.find("ports")
            for port in (ports_el.findall("port") if ports_el is not None else []):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                protocol = port.get("protocol", "tcp")
                port_num = port.get("portid", "?")
                service = port.find("service")
                sname = service.get("name") if service is not None else ""
                product = service.get("product") if service is not None else ""
                version = service.get("version") if service is not None else ""
                findings.append(Finding(
                    severity="info",
                    title=f"Open port {port_num}/{protocol} ({sname or 'unknown'})",
                    description=f"{product or sname or 'unknown'} {version or ''}".strip(),
                    target=f"{addr}:{port_num}",
                    evidence=f"service={sname} product={product} version={version}",
                    metadata={"port": port_num, "protocol": protocol, "service": sname,
                              "product": product, "version": version, "vuln_class": "recon"},
                ))
                # NSE script results attached to this port.
                for s in port.findall("script"):
                    f = _script_finding(s, f"{addr}:{port_num}")
                    if f:
                        findings.append(f)

            # Host-level NSE scripts (e.g. smb-vuln-*).
            hostscript = host_el.find("hostscript")
            for s in (hostscript.findall("script") if hostscript is not None else []):
                f = _script_finding(s, addr)
                if f:
                    findings.append(f)
        return ToolResult(findings=findings)


def _cvss_severity(output: str) -> Tuple[str, float]:
    best = 0.0
    for m in _CVSS_RE.finditer(output):
        try:
            best = max(best, float(m.group(1)))
        except ValueError:
            pass
    if best >= 9:
        return "critical", best
    if best >= 7:
        return "high", best
    if best >= 4:
        return "medium", best
    return "low", best


def _script_finding(script_el, target: str) -> Optional[Finding]:
    sid = (script_el.get("id") or "").lower()
    output = (script_el.get("output") or "").strip()
    if not output:
        return None
    is_vuln = ("vuln" in sid or sid == "vulners" or "VULNERABLE" in output
               or bool(_CVE_RE.search(output)))
    if not is_vuln:
        return None
    cves = _CVE_RE.findall(output)
    cve = normalize_cve(cves[0]) if cves else None
    sev, _score = _cvss_severity(output)
    if cve and sev == "low":
        sev = "high"
    title = (f"{cve}: " if cve else "") + f"nmap NSE {sid} on {target}"
    meta = {"vuln_class": "cve" if cve else "misconfiguration", "nse_script": sid}
    if cve:
        meta["cve_id"] = cve
    return Finding(severity=sev, title=title,
                   description=f"NSE script '{sid}' reported a vulnerability.",
                   target=target, evidence=output[:1500], metadata=meta)


def _target_to_host(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split("/", 1)[0]
