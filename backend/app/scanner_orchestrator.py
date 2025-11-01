"""
Main scanner orchestrator - coordinates all security scans
"""
import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app.models import (
    ScanRequest,
    ScanResult,
    ScanMode,
    Vulnerability,
    Misconfiguration,
    EndpointInfo,
    TechnologyInfo,
    SeverityLevel
)
from app.utils import PentestHTTPClient
from app.scanners import (
    TechnologyDetector,
    EndpointDiscovery,
    SQLInjectionScanner,
    XSSScanner,
    CommandInjectionScanner,
    SSRFScanner,
    IDORScanner,
    PrivilegeEscalationScanner,
    SecurityHeadersScanner,
    CORSScanner
)

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    """
    Orchestrates all security scans based on the scan mode (black box or grey box)
    """

    def __init__(self):
        self.active_scans: Dict[str, ScanResult] = {}

    async def start_scan(self, scan_request: ScanRequest) -> str:
        """
        Start a new security scan

        Returns:
            scan_id: Unique identifier for the scan
        """
        scan_id = str(uuid.uuid4())

        # Initialize scan result
        scan_result = ScanResult(
            scan_id=scan_id,
            target_url=scan_request.target_url,
            mode=scan_request.mode,
            start_time=datetime.utcnow(),
            status="running"
        )

        self.active_scans[scan_id] = scan_result

        # Start scan in background
        asyncio.create_task(self._execute_scan(scan_id, scan_request))

        return scan_id

    async def _execute_scan(self, scan_id: str, scan_request: ScanRequest):
        """Execute the complete scan workflow"""
        scan_result = self.active_scans[scan_id]

        try:
            logger.info(f"Starting scan {scan_id} for {scan_request.target_url}")

            # Normalize target URL
            target_url = self._normalize_url(scan_request.target_url)

            # Create HTTP client
            client = PentestHTTPClient(
                base_url=target_url,
                headers=scan_request.custom_headers,
                cookies=scan_request.cookies,
                auth_token=scan_request.auth_token,
                rate_limit=scan_request.rate_limit
            )

            # Phase 1: Reconnaissance
            logger.info(f"[{scan_id}] Phase 1: Reconnaissance")
            scan_result.status = "reconnaissance"

            # Detect technologies
            tech_detector = TechnologyDetector()
            technologies = await tech_detector.detect(client)
            scan_result.detected_technologies = technologies
            logger.info(f"[{scan_id}] Detected {len(technologies)} technologies")

            # Discover endpoints
            endpoint_discovery = EndpointDiscovery(client, max_depth=scan_request.max_depth)
            endpoints = await endpoint_discovery.discover(enable_fuzzing=scan_request.enable_fuzzing)
            scan_result.discovered_endpoints = endpoints
            logger.info(f"[{scan_id}] Discovered {len(endpoints)} endpoints")

            # Extract endpoint URLs for vulnerability scanning
            endpoint_urls = [ep.url for ep in endpoints]

            # Phase 2: OWASP Top 10 Scanning
            logger.info(f"[{scan_id}] Phase 2: OWASP Top 10 Vulnerability Scanning")
            scan_result.status = "owasp_scanning"

            vulnerabilities = []

            # SQL Injection
            if scan_request.enable_active_tests:
                sql_scanner = SQLInjectionScanner(client)
                sql_vulns = await sql_scanner.scan(endpoint_urls[:50])  # Limit for performance
                vulnerabilities.extend(sql_vulns)
                logger.info(f"[{scan_id}] SQL Injection: Found {len(sql_vulns)} vulnerabilities")

            # XSS
            if scan_request.enable_active_tests:
                xss_scanner = XSSScanner(client)
                xss_vulns = await xss_scanner.scan(endpoint_urls[:50])
                vulnerabilities.extend(xss_vulns)
                logger.info(f"[{scan_id}] XSS: Found {len(xss_vulns)} vulnerabilities")

            # Command Injection
            if scan_request.enable_active_tests:
                cmd_scanner = CommandInjectionScanner(client)
                cmd_vulns = await cmd_scanner.scan(endpoint_urls[:30])
                vulnerabilities.extend(cmd_vulns)
                logger.info(f"[{scan_id}] Command Injection: Found {len(cmd_vulns)} vulnerabilities")

            # SSRF
            ssrf_scanner = SSRFScanner(client)
            ssrf_vulns = await ssrf_scanner.scan(endpoint_urls[:30])
            vulnerabilities.extend(ssrf_vulns)
            logger.info(f"[{scan_id}] SSRF: Found {len(ssrf_vulns)} vulnerabilities")

            # Phase 3: Access Control Testing
            logger.info(f"[{scan_id}] Phase 3: Access Control Testing")
            scan_result.status = "access_control_testing"

            # IDOR
            idor_scanner = IDORScanner(client)
            idor_vulns = await idor_scanner.scan(endpoint_urls, authenticated=bool(scan_request.auth_token))
            vulnerabilities.extend(idor_vulns)
            logger.info(f"[{scan_id}] IDOR: Found {len(idor_vulns)} vulnerabilities")

            # Privilege Escalation (Grey Box only)
            if scan_request.mode == ScanMode.GREY_BOX and scan_request.auth_token:
                priv_scanner = PrivilegeEscalationScanner(client)
                priv_vulns = await priv_scanner.scan(endpoint_urls, test_users=scan_request.test_users)
                vulnerabilities.extend(priv_vulns)
                logger.info(f"[{scan_id}] Privilege Escalation: Found {len(priv_vulns)} vulnerabilities")

            # Phase 4: Security Misconfiguration
            logger.info(f"[{scan_id}] Phase 4: Security Misconfiguration")
            scan_result.status = "misconfiguration_scanning"

            misconfigurations = []

            # Security Headers
            headers_scanner = SecurityHeadersScanner(client)
            header_issues = await headers_scanner.scan()
            misconfigurations.extend(header_issues)
            logger.info(f"[{scan_id}] Security Headers: Found {len(header_issues)} issues")

            # CORS
            cors_scanner = CORSScanner(client)
            cors_issues = await cors_scanner.scan(endpoint_urls)
            misconfigurations.extend(cors_issues)
            logger.info(f"[{scan_id}] CORS: Found {len(cors_issues)} issues")

            # Update scan result
            scan_result.vulnerabilities = vulnerabilities
            scan_result.misconfigurations = misconfigurations
            scan_result.end_time = datetime.utcnow()
            scan_result.status = "completed"
            scan_result.total_requests = client.request_count

            # Calculate scan duration
            if scan_result.start_time and scan_result.end_time:
                duration = (scan_result.end_time - scan_result.start_time).total_seconds()
                scan_result.scan_duration = duration

            # Count vulnerabilities by severity
            scan_result.vulnerabilities_by_severity = self._count_by_severity(vulnerabilities)

            logger.info(f"[{scan_id}] Scan completed. Found {len(vulnerabilities)} vulnerabilities "
                       f"and {len(misconfigurations)} misconfigurations")

        except Exception as e:
            logger.error(f"[{scan_id}] Scan failed: {e}", exc_info=True)
            scan_result.status = "failed"
            scan_result.error_message = str(e)
            scan_result.end_time = datetime.utcnow()

    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Get scan result by ID"""
        return self.active_scans.get(scan_id)

    def _normalize_url(self, url: str) -> str:
        """Normalize and validate URL"""
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'

        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _count_by_severity(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for vuln in vulnerabilities:
            severity_key = vuln.severity.value
            if severity_key in counts:
                counts[severity_key] += 1

        return counts
