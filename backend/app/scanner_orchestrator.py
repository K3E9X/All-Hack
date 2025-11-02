"""
Intelligent Scanner Orchestrator V2 - With Brain, Robustness, and Adaptive Strategy
"""
import asyncio
import logging
import uuid
from datetime import datetime, timedelta
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
from app.utils.target_validator import TargetValidator
from app.utils.robust_scanner import RobustScanner
from app.intelligence import ScanBrain
from app.persistence import ScanStorage
from app.config import settings
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
    CORSScanner,
    PortScanner,
    DirectoryFuzzer,
    SubdomainScanner,
    SSLScanner
)

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    """
    Intelligent orchestrator with:
    - Adaptive testing strategy based on findings
    - Robust error handling with retry
    - IP address support
    - Scan persistence (resume on crash)
    - Detailed reasoning and correlation
    """

    def __init__(self):
        self.active_scans: Dict[str, ScanResult] = {}
        self.scan_brains: Dict[str, ScanBrain] = {}
        self.robust_scanner = RobustScanner(
            max_retries=settings.MAX_RETRIES,
            base_timeout=settings.BASE_TIMEOUT,
            max_timeout=settings.MAX_TIMEOUT,
            backoff_factor=settings.BACKOFF_FACTOR
        )
        self.storage = ScanStorage(settings.SCAN_STORAGE_DIR)
        self.last_save_time: Dict[str, datetime] = {}

    async def start_scan(self, scan_request: ScanRequest) -> str:
        """Start a new intelligent scan"""
        scan_id = str(uuid.uuid4())

        # Validate target (supports IP!)
        is_valid, target_url, error = TargetValidator.validate_and_normalize(
            scan_request.target_url
        )

        if not is_valid:
            raise ValueError(f"Invalid target: {error}")

        logger.info(f"🚀 Starting intelligent scan {scan_id} for {target_url}")
        logger.info(f"📊 Target validated: {target_url}")

        # Initialize scan result
        scan_result = ScanResult(
            scan_id=scan_id,
            target_url=target_url,
            mode=scan_request.mode,
            start_time=datetime.utcnow(),
            status="initializing"
        )

        self.active_scans[scan_id] = scan_result
        self.scan_brains[scan_id] = ScanBrain()
        self.last_save_time[scan_id] = datetime.utcnow()

        # Initial save
        self.storage.save_scan(scan_result)

        # Start scan in background
        asyncio.create_task(self._execute_intelligent_scan(scan_id, scan_request, target_url))

        return scan_id

    async def _execute_intelligent_scan(
        self,
        scan_id: str,
        scan_request: ScanRequest,
        target_url: str
    ):
        """Execute complete intelligent scan with adaptation"""
        scan_result = self.active_scans[scan_id]
        brain = self.scan_brains[scan_id]

        try:
            logger.info(f"🧠 [SCAN {scan_id}] Initializing intelligent pentest...")

            # Create HTTP client
            client = PentestHTTPClient(
                base_url=target_url,
                headers=scan_request.custom_headers,
                cookies=scan_request.cookies,
                auth_token=scan_request.auth_token,
                rate_limit=scan_request.rate_limit
            )

            vulnerabilities = []
            misconfigurations = []

            # ===== PHASE 0: INFRASTRUCTURE RECONNAISSANCE =====
            logger.info(f"\n{'='*70}")
            logger.info(f"🔍 [PHASE 0] INFRASTRUCTURE RECONNAISSANCE")
            logger.info(f"{'='*70}")
            scan_result.status = "infrastructure_recon"
            await self._auto_save(scan_id)

            # Port Scanning
            logger.info(f"🔌 Scanning ports and services...")
            open_ports, port_vulns, port_misconfigs = await self.robust_scanner.execute_with_retry(
                self._safe_port_scan, target_url
            )
            vulnerabilities.extend(port_vulns or [])
            misconfigurations.extend(port_misconfigs or [])
            logger.info(f"✅ Found {len(open_ports or [])} open ports, {len(port_vulns or [])} vulnerabilities")

            # SSL/TLS Analysis
            if target_url.startswith('https://'):
                logger.info(f"🔐 Analyzing SSL/TLS configuration...")
                ssl_vulns, ssl_misconfigs = await self.robust_scanner.execute_with_retry(
                    self._safe_ssl_scan, target_url
                )
                vulnerabilities.extend(ssl_vulns or [])
                misconfigurations.extend(ssl_misconfigs or [])
                logger.info(f"✅ SSL/TLS: Found {len(ssl_vulns or [])} vulnerabilities")

            # Subdomain Enumeration
            logger.info(f"🌐 Enumerating subdomains...")
            subdomains = await self.robust_scanner.execute_with_retry(
                self._safe_subdomain_scan, target_url
            )
            logger.info(f"✅ Found {len(subdomains or [])} subdomains")

            # 🧠 INTELLIGENT ANALYSIS: Infrastructure
            logger.info(f"\n🧠 [BRAIN] Analyzing infrastructure results...")
            infra_intelligence = brain.analyze_infrastructure(open_ports or [], subdomains or [])

            for reasoning in infra_intelligence.get('reasoning', []):
                logger.info(f"💡 {reasoning}")

            await self._auto_save(scan_id)

            # ===== PHASE 1: APPLICATION RECONNAISSANCE =====
            logger.info(f"\n{'='*70}")
            logger.info(f"🔍 [PHASE 1] APPLICATION RECONNAISSANCE")
            logger.info(f"{'='*70}")
            scan_result.status = "reconnaissance"

            # Technology Detection
            logger.info(f"🔬 Detecting technologies...")
            tech_detector = TechnologyDetector()
            technologies = await self.robust_scanner.execute_with_retry(
                tech_detector.detect, client
            )
            scan_result.detected_technologies = technologies or []
            logger.info(f"✅ Detected {len(technologies or [])} technologies")

            # 🧠 INTELLIGENT ANALYSIS: Technologies
            logger.info(f"\n🧠 [BRAIN] Analyzing technology stack...")
            tech_intelligence = brain.analyze_technologies(technologies or [])

            for reasoning in tech_intelligence.get('reasoning', []):
                logger.info(f"💡 {reasoning}")

            # Endpoint Discovery - Basic Crawling
            logger.info(f"🕷️  Crawling application...")
            endpoint_discovery = EndpointDiscovery(client, max_depth=scan_request.max_depth)
            endpoints = await self.robust_scanner.execute_with_retry(
                endpoint_discovery.discover, enable_fuzzing=False
            )
            logger.info(f"✅ Initial crawl found {len(endpoints or [])} endpoints")

            # Advanced Directory Fuzzing
            logger.info(f"💣 Starting aggressive directory fuzzing...")
            directory_fuzzer = DirectoryFuzzer(client)
            fuzzed_endpoints = await self.robust_scanner.execute_with_retry(
                directory_fuzzer.fuzz, aggressive=scan_request.enable_fuzzing
            )
            if endpoints and fuzzed_endpoints:
                endpoints.extend(fuzzed_endpoints)
            logger.info(f"✅ Fuzzing discovered {len(fuzzed_endpoints or [])} additional endpoints")

            scan_result.discovered_endpoints = endpoints or []
            endpoint_urls = [ep.url for ep in (endpoints or [])]
            logger.info(f"📍 Total endpoints discovered: {len(endpoint_urls)}")

            # 🧠 INTELLIGENT ANALYSIS: Endpoints
            logger.info(f"\n🧠 [BRAIN] Analyzing discovered endpoints...")
            endpoint_intelligence = brain.analyze_endpoints(endpoints or [])

            for reasoning in endpoint_intelligence.get('reasoning', []):
                logger.info(f"💡 {reasoning}")

            # 🧠 ADAPTIVE STRATEGY
            strategy = brain.get_adaptive_strategy()
            logger.info(f"\n🧠 [BRAIN] Generated adaptive testing strategy:")
            for reasoning in strategy.get('reasoning', []):
                logger.info(f"💡 {reasoning}")

            await self._auto_save(scan_id)

            # ===== PHASE 2: OWASP TOP 10 - ADAPTIVE TESTING =====
            logger.info(f"\n{'='*70}")
            logger.info(f"🔥 [PHASE 2] OWASP TOP 10 VULNERABILITY SCANNING (ADAPTIVE)")
            logger.info(f"{'='*70}")
            scan_result.status = "owasp_scanning"

            if scan_request.enable_active_tests:
                # Prioritize based on intelligence
                priority_targets = endpoint_intelligence.get('priority_targets', [])

                if priority_targets:
                    logger.info(f"🎯 Testing {len(priority_targets)} high-priority targets first...")

                # SQL Injection
                logger.info(f"🗃️  Testing for SQL Injection...")
                sql_scanner = SQLInjectionScanner(client)
                sql_vulns = await self.robust_scanner.execute_batch_safe(
                    endpoint_urls,
                    lambda urls: sql_scanner.scan(urls),
                    max_concurrent=5
                )
                vulnerabilities.extend([v for v in sql_vulns if v])
                logger.info(f"✅ SQL Injection: Found {len([v for v in sql_vulns if v])} vulnerabilities")

                # XSS
                logger.info(f"🎨 Testing for Cross-Site Scripting (XSS)...")
                xss_scanner = XSSScanner(client)
                xss_vulns = await self.robust_scanner.execute_batch_safe(
                    endpoint_urls,
                    lambda urls: xss_scanner.scan(urls),
                    max_concurrent=5
                )
                vulnerabilities.extend([v for v in xss_vulns if v])
                logger.info(f"✅ XSS: Found {len([v for v in xss_vulns if v])} vulnerabilities")

                # Command Injection
                logger.info(f"💻 Testing for Command Injection...")
                cmd_scanner = CommandInjectionScanner(client)
                cmd_vulns = await self.robust_scanner.execute_batch_safe(
                    endpoint_urls,
                    lambda urls: cmd_scanner.scan(urls),
                    max_concurrent=3
                )
                vulnerabilities.extend([v for v in cmd_vulns if v])
                logger.info(f"✅ Command Injection: Found {len([v for v in cmd_vulns if v])} vulnerabilities")

            # SSRF
            logger.info(f"🌐 Testing for SSRF...")
            ssrf_scanner = SSRFScanner(client)
            ssrf_vulns = await self.robust_scanner.execute_with_retry(
                ssrf_scanner.scan, endpoint_urls
            )
            vulnerabilities.extend(ssrf_vulns or [])
            logger.info(f"✅ SSRF: Found {len(ssrf_vulns or [])} vulnerabilities")

            # 🧠 INTELLIGENT ANALYSIS: Vulnerabilities Found
            logger.info(f"\n🧠 [BRAIN] Analyzing found vulnerabilities...")
            vuln_intelligence = brain.analyze_vulnerabilities(vulnerabilities)

            for reasoning in vuln_intelligence.get('reasoning', []):
                logger.info(f"💡 {reasoning}")

            exploitation_chains = vuln_intelligence.get('exploitation_chain', [])
            if exploitation_chains:
                logger.info(f"\n🚨 EXPLOITATION CHAINS IDENTIFIED:")
                for chain in exploitation_chains:
                    logger.info(f"  Step {chain['step']}: {chain['action']} - {chain['reason']}")

            await self._auto_save(scan_id)

            # ===== PHASE 3: ACCESS CONTROL =====
            logger.info(f"\n{'='*70}")
            logger.info(f"🔒 [PHASE 3] ACCESS CONTROL TESTING")
            logger.info(f"{'='*70}")
            scan_result.status = "access_control_testing"

            # IDOR
            logger.info(f"🔑 Testing for IDOR...")
            idor_scanner = IDORScanner(client)
            idor_vulns = await self.robust_scanner.execute_with_retry(
                idor_scanner.scan, endpoint_urls, authenticated=bool(scan_request.auth_token)
            )
            vulnerabilities.extend(idor_vulns or [])
            logger.info(f"✅ IDOR: Found {len(idor_vulns or [])} vulnerabilities")

            # Privilege Escalation (Grey Box)
            if scan_request.mode == ScanMode.GREY_BOX and scan_request.auth_token:
                logger.info(f"⬆️  Testing for Privilege Escalation...")
                priv_scanner = PrivilegeEscalationScanner(client)
                priv_vulns = await self.robust_scanner.execute_with_retry(
                    priv_scanner.scan, endpoint_urls, test_users=scan_request.test_users
                )
                vulnerabilities.extend(priv_vulns or [])
                logger.info(f"✅ Privilege Escalation: Found {len(priv_vulns or [])} vulnerabilities")

            await self._auto_save(scan_id)

            # ===== PHASE 4: SECURITY MISCONFIGURATION =====
            logger.info(f"\n{'='*70}")
            logger.info(f"🔧 [PHASE 4] SECURITY MISCONFIGURATION")
            logger.info(f"{'='*70}")
            scan_result.status = "misconfiguration_scanning"

            # Security Headers
            logger.info(f"🛡️  Checking security headers...")
            headers_scanner = SecurityHeadersScanner(client)
            header_issues = await self.robust_scanner.execute_with_retry(
                headers_scanner.scan
            )
            misconfigurations.extend(header_issues or [])
            logger.info(f"✅ Security Headers: Found {len(header_issues or [])} issues")

            # CORS
            logger.info(f"🌍 Testing CORS configuration...")
            cors_scanner = CORSScanner(client)
            cors_issues = await self.robust_scanner.execute_with_retry(
                cors_scanner.scan, endpoint_urls
            )
            misconfigurations.extend(cors_issues or [])
            logger.info(f"✅ CORS: Found {len(cors_issues or [])} issues")

            # ===== FINALIZATION =====
            scan_result.vulnerabilities = vulnerabilities
            scan_result.misconfigurations = misconfigurations
            scan_result.end_time = datetime.utcnow()
            scan_result.status = "completed"
            scan_result.total_requests = client.request_count

            if scan_result.start_time and scan_result.end_time:
                duration = (scan_result.end_time - scan_result.start_time).total_seconds()
                scan_result.scan_duration = duration

            scan_result.vulnerabilities_by_severity = self._count_by_severity(vulnerabilities)

            # Final save
            self.storage.save_scan(scan_result)

            logger.info(f"\n{'='*70}")
            logger.info(f"✅ SCAN COMPLETED!")
            logger.info(f"{'='*70}")
            logger.info(f"📊 Duration: {scan_result.scan_duration:.2f}s")
            logger.info(f"🎯 Vulnerabilities: {len(vulnerabilities)}")
            logger.info(f"⚠️  Misconfigurations: {len(misconfigurations)}")
            logger.info(f"📡 Total Requests: {client.request_count}")
            logger.info(f"{'='*70}")

        except Exception as e:
            logger.error(f"❌ [SCAN {scan_id}] FAILED: {e}", exc_info=True)
            scan_result.status = "failed"
            scan_result.error_message = str(e)
            scan_result.end_time = datetime.utcnow()
            self.storage.save_scan(scan_result)

    # Helper methods
    async def _auto_save(self, scan_id: str):
        """Auto-save scan periodically"""
        now = datetime.utcnow()
        last_save = self.last_save_time.get(scan_id)

        if not last_save or (now - last_save).total_seconds() >= settings.AUTO_SAVE_INTERVAL:
            scan_result = self.active_scans.get(scan_id)
            if scan_result:
                self.storage.auto_save_scan(scan_result)
                self.last_save_time[scan_id] = now

    async def _safe_port_scan(self, target_url: str):
        """Safe port scan wrapper"""
        port_scanner = PortScanner(target_url)
        return await port_scanner.scan()

    async def _safe_ssl_scan(self, target_url: str):
        """Safe SSL scan wrapper"""
        ssl_scanner = SSLScanner(target_url)
        return await ssl_scanner.scan()

    async def _safe_subdomain_scan(self, target_url: str):
        """Safe subdomain scan wrapper"""
        subdomain_scanner = SubdomainScanner(target_url)
        return await subdomain_scanner.scan()

    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Get scan result (from memory or disk)"""
        # Try memory first
        result = self.active_scans.get(scan_id)
        if result:
            return result

        # Try loading from disk
        return self.storage.load_scan(scan_id)

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
            severity_key = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
            if severity_key in counts:
                counts[severity_key] += 1

        return counts
