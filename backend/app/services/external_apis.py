"""
External APIs Integration (Free Tiers)

Integrates free security APIs for enrichment:
- Shodan (100 queries/month free)
- VirusTotal (500 req/day free)
- URLScan.io (unlimited free)
- HaveIBeenPwned (free for domain search)
- CVE/NVD (unlimited free)
- AbuseIPDB (1000 req/day free)
"""

import aiohttp
import asyncio
import json
import os
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class EnrichmentResult:
    source: str
    data: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ExternalAPIs:
    """Free external API integrations for security enrichment"""

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None

        # API Keys from environment (optional)
        self.shodan_key = os.getenv("SHODAN_API_KEY", "")
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")

    async def initialize(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15)
            )

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None

    # ==================== SHODAN ====================

    async def shodan_host(self, ip: str) -> Optional[EnrichmentResult]:
        """Get Shodan info for IP (requires free API key)"""
        if not self.shodan_key:
            return None

        await self.initialize()
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return EnrichmentResult(
                        source="shodan",
                        data={
                            "ip": ip,
                            "ports": data.get("ports", []),
                            "hostnames": data.get("hostnames", []),
                            "org": data.get("org"),
                            "isp": data.get("isp"),
                            "os": data.get("os"),
                            "vulns": data.get("vulns", [])
                        }
                    )
        except Exception as e:
            logger.debug(f"Shodan error: {e}")
        return None

    # ==================== VIRUSTOTAL ====================

    async def virustotal_url(self, url: str) -> Optional[EnrichmentResult]:
        """Check URL reputation on VirusTotal (requires free API key)"""
        if not self.virustotal_key:
            return None

        await self.initialize()
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": self.virustotal_key}

            async with self.session.get(api_url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    return EnrichmentResult(
                        source="virustotal",
                        data={
                            "url": url,
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless": stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0)
                        }
                    )
        except Exception as e:
            logger.debug(f"VirusTotal error: {e}")
        return None

    # ==================== URLSCAN.IO (FREE) ====================

    async def urlscan_search(self, domain: str) -> Optional[EnrichmentResult]:
        """Search URLScan.io for domain info (FREE, no key needed)"""
        await self.initialize()
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results = data.get("results", [])
                    return EnrichmentResult(
                        source="urlscan",
                        data={
                            "domain": domain,
                            "scan_count": len(results),
                            "recent_scans": [
                                {
                                    "url": r.get("page", {}).get("url"),
                                    "ip": r.get("page", {}).get("ip"),
                                    "server": r.get("page", {}).get("server"),
                                    "status": r.get("page", {}).get("status")
                                }
                                for r in results[:5]
                            ]
                        }
                    )
        except Exception as e:
            logger.debug(f"URLScan error: {e}")
        return None

    # ==================== CVE/NVD (FREE) ====================

    async def search_cve(self, keyword: str) -> Optional[EnrichmentResult]:
        """Search NVD for CVEs (FREE, no key needed)"""
        await self.initialize()
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=10"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    vulns = data.get("vulnerabilities", [])
                    return EnrichmentResult(
                        source="nvd",
                        data={
                            "keyword": keyword,
                            "total_results": data.get("totalResults", 0),
                            "cves": [
                                {
                                    "id": v.get("cve", {}).get("id"),
                                    "description": v.get("cve", {}).get("descriptions", [{}])[0].get("value", "")[:200],
                                    "severity": v.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                                }
                                for v in vulns[:5]
                            ]
                        }
                    )
        except Exception as e:
            logger.debug(f"NVD error: {e}")
        return None

    # ==================== ABUSEIPDB ====================

    async def check_ip_abuse(self, ip: str) -> Optional[EnrichmentResult]:
        """Check IP on AbuseIPDB (requires free API key)"""
        if not self.abuseipdb_key:
            return None

        await self.initialize()
        try:
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}

            async with self.session.get(url, headers=headers, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result = data.get("data", {})
                    return EnrichmentResult(
                        source="abuseipdb",
                        data={
                            "ip": ip,
                            "abuse_score": result.get("abuseConfidenceScore", 0),
                            "is_public": result.get("isPublic", False),
                            "country": result.get("countryCode"),
                            "isp": result.get("isp"),
                            "total_reports": result.get("totalReports", 0)
                        }
                    )
        except Exception as e:
            logger.debug(f"AbuseIPDB error: {e}")
        return None

    # ==================== HACKERTARGET (FREE) ====================

    async def hackertarget_hostsearch(self, domain: str) -> Optional[EnrichmentResult]:
        """Find subdomains via HackerTarget (FREE, no key)"""
        await self.initialize()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "error" not in text.lower():
                        hosts = []
                        for line in text.strip().split("\n"):
                            if "," in line:
                                parts = line.split(",")
                                hosts.append({"host": parts[0], "ip": parts[1] if len(parts) > 1 else ""})
                        return EnrichmentResult(
                            source="hackertarget",
                            data={
                                "domain": domain,
                                "hosts": hosts[:20]
                            }
                        )
        except Exception as e:
            logger.debug(f"HackerTarget error: {e}")
        return None

    # ==================== AGGREGATE ====================

    async def enrich_target(self, target: str) -> List[EnrichmentResult]:
        """Run all applicable enrichments for a target"""
        results = []

        from urllib.parse import urlparse
        parsed = urlparse(target)
        domain = parsed.netloc or target

        # Get IP from domain
        ip = None
        try:
            import socket
            ip = socket.gethostbyname(domain.split(":")[0])
        except:
            pass

        # Run enrichments in parallel
        tasks = [
            self.urlscan_search(domain),
            self.hackertarget_hostsearch(domain),
        ]

        if ip:
            tasks.append(self.shodan_host(ip))
            tasks.append(self.check_ip_abuse(ip))

        if target.startswith("http"):
            tasks.append(self.virustotal_url(target))

        enrichments = await asyncio.gather(*tasks, return_exceptions=True)

        for r in enrichments:
            if isinstance(r, EnrichmentResult):
                results.append(r)

        return results


# Global instance
_external_apis: Optional[ExternalAPIs] = None


def get_external_apis() -> ExternalAPIs:
    global _external_apis
    if _external_apis is None:
        _external_apis = ExternalAPIs()
    return _external_apis
