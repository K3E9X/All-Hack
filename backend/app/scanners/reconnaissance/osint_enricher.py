"""Local OSINT enrichment helpers."""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from typing import Any, Dict, List
from urllib.parse import urlparse

import dns.resolver  # type: ignore

from app.utils.http_client import PentestHTTPClient

logger = logging.getLogger(__name__)


class LocalOSINTEnricher:
    """Gather certificate, DNS and secret exposure hints for local scans."""

    def __init__(self, target_url: str, client: PentestHTTPClient):
        self.target_url = target_url
        self.client = client

    async def collect(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        cert_info = await asyncio.to_thread(self._collect_certificate)
        if cert_info:
            findings.append({"type": "certificate", **cert_info})

        dns_info = await asyncio.to_thread(self._collect_dns)
        if dns_info:
            findings.append({"type": "dns", **dns_info})

        secret_files = await self._check_secret_files()
        findings.extend(secret_files)

        return findings

    def _collect_certificate(self) -> Dict[str, Any]:
        parsed = urlparse(self.target_url)
        if parsed.scheme != "https":
            return {}

        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return {}

        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
        except Exception as exc:  # pragma: no cover - network specific
            logger.debug("Failed to retrieve certificate for %s: %s", host, exc)
            return {}

        subject = dict(x[0] for x in cert.get("subject", []))
        alt_names = [entry[1] for entry in cert.get("subjectAltName", [])]
        return {
            "common_name": subject.get("commonName"),
            "issuer": dict(x[0] for x in cert.get("issuer", [])).get("commonName"),
            "sans": alt_names,
            "not_after": cert.get("notAfter"),
        }

    def _collect_dns(self) -> Dict[str, Any]:
        parsed = urlparse(self.target_url)
        host = parsed.hostname
        if not host:
            return {}

        resolver = dns.resolver.Resolver()
        results: Dict[str, Any] = {"txt": [], "mx": []}

        try:
            answers = resolver.resolve(host, "TXT")
            results["txt"] = [b"".join(r.strings).decode("utf-8", "ignore") for r in answers]
        except Exception:
            pass

        try:
            mx_answers = resolver.resolve(host, "MX")
            results["mx"] = [str(r.exchange).rstrip('.') for r in mx_answers]
        except Exception:
            pass

        return results

    async def _check_secret_files(self) -> List[Dict[str, Any]]:
        paths = ["/.env", "/.git/config", "/backup.zip", "/credentials.json"]
        findings: List[Dict[str, Any]] = []

        for path in paths:
            response = await self.client.get(path)
            if response and response.status_code == 200:
                snippet = response.text[:200] if hasattr(response, "text") else ""
                findings.append({
                    "type": "exposed_file",
                    "path": path,
                    "status": response.status_code,
                    "snippet": snippet,
                })

        return findings

