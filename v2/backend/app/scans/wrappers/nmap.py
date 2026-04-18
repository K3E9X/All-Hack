"""nmap: ports + service detection.

We run `nmap -sV -T4 -oX - <host>` and parse the XML output, yielding one
finding per open port.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List, Sequence
from urllib.parse import urlparse

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult


class NmapWrapper(BaseWrapper):
    name = "nmap"
    binary = "nmap"
    description = "Port scanner and service fingerprinter."
    timeout_seconds = 20 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        host = _target_to_host(target)
        cmd = [
            self.binary,
            "-sV",
            "-T4",
            "-Pn",          # skip host discovery; assume target is up
            "-oX", "-",
            host,
        ]
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
            if ports_el is None:
                continue

            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                protocol = port.get("protocol", "tcp")
                port_num = port.get("portid", "?")
                service = port.find("service")
                service_name = service.get("name") if service is not None else ""
                product = service.get("product") if service is not None else ""
                version = service.get("version") if service is not None else ""

                findings.append(
                    Finding(
                        severity="info",
                        title=f"Open port {port_num}/{protocol} ({service_name or 'unknown'})",
                        description=f"{product or service_name or 'unknown'} {version or ''}".strip(),
                        target=f"{addr}:{port_num}",
                        evidence=f"service={service_name} product={product} version={version}",
                        metadata={
                            "port": port_num,
                            "protocol": protocol,
                            "service": service_name,
                            "product": product,
                            "version": version,
                        },
                    )
                )
        return ToolResult(findings=findings)


def _target_to_host(target: str) -> str:
    """Accept either a URL or a bare hostname/IP."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split("/", 1)[0]
