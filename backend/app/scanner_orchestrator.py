"""
Intelligent Scanner Orchestrator V2 - With Brain, Robustness, and Adaptive Strategy
"""
import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from app.models import (
    ScanRequest,
    ScanResult,
    ScanMode,
    Vulnerability,
    Misconfiguration,
    EndpointInfo,
    TechnologyInfo,
    SeverityLevel,
    TimelineEvent,
    AttackChainStep,
    ScanArtifact,
    PlaybookRequest,
    PlaybookRun,
    StabilitySnapshot,
)
from app.utils import PentestHTTPClient
from app.utils.target_validator import TargetValidator
from app.utils.robust_scanner import RobustScanner
from app.intelligence import ScanBrain
from app.persistence import ScanStorage
from app.config import settings
from app.utils.auth import AdvancedAuthManager
from app.utils.hooks import ExternalToolHookRunner
from app.utils.stability_monitor import StabilityMonitor
from app.intelligence.exploitation_assistant import ExploitationAssistant
from app.scanners.reconnaissance import (
    BrowserCrawler,
    APISchemaCollector,
    LocalOSINTEnricher,
)
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
from app.scanners.api_security import (
    JWTSecurityScanner,
    GraphQLSecurityScanner,
    NoSQLInjectionScanner,
    FileUploadScanner
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
        self.stop_flags: Dict[str, bool] = {}  # Track scans that should be stopped
        self.robust_scanner = RobustScanner(
            max_retries=settings.MAX_RETRIES,
            base_timeout=settings.BASE_TIMEOUT,
            max_timeout=settings.MAX_TIMEOUT,
            backoff_factor=settings.BACKOFF_FACTOR
        )
        self.storage = ScanStorage(settings.SCAN_STORAGE_DIR)
        self.last_save_time: Dict[str, datetime] = {}
        self.hook_runner = ExternalToolHookRunner(settings.EXTERNAL_TOOL_HOOKS)
        self.stability_monitor = StabilityMonitor()
        self.exploitation_assistant = ExploitationAssistant()
        self.playbooks: Dict[str, PlaybookRun] = {}

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

    def _record_event(
        self,
        scan_result: ScanResult,
        phase: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TimelineEvent:
        event = TimelineEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            phase=phase,
            message=message,
            metadata=metadata or {},
        )
        scan_result.timeline.append(event)
        return event

    def _snapshot_stability(self, scan_result: ScanResult, label: str) -> Optional[StabilitySnapshot]:
        metrics = self.stability_monitor.snapshot(label)
        if not metrics:
            return None
        snapshot = StabilitySnapshot(
            label=label,
            timestamp=metrics["timestamp"],
            load_average=metrics["load_average"],
            memory=metrics["memory"],
        )
        scan_result.stability_metrics.append(snapshot)
        return snapshot

    def _prioritize_endpoints(
        self,
        endpoints: List[EndpointInfo],
        scan_depth: str,
        priority_targets: List[str] = None
    ) -> List[str]:
        """
        Prioritize and limit endpoints based on scan depth

        Returns limited list of endpoint URLs optimized for scanning
        """
        from app.models import ScanDepth

        # Score endpoints by priority
        scored_endpoints = []
        for ep in endpoints:
            score = 0
            url_lower = ep.url.lower()

            # High priority patterns
            if any(pattern in url_lower for pattern in ['/admin', '/api', '/upload', '/login', '/auth']):
                score += 10
            if any(pattern in url_lower for pattern in ['/user', '/account', '/profile', '/settings']):
                score += 7
            if any(pattern in url_lower for pattern in ['/delete', '/update', '/create', '/edit']):
                score += 5
            if '?' in url_lower:  # Has parameters
                score += 3
            if ep.url in (priority_targets or []):
                score += 15  # Brain-identified priority targets

            scored_endpoints.append((score, ep))

        # Sort by score (highest first)
        scored_endpoints.sort(key=lambda x: x[0], reverse=True)

        # Apply limits based on scan depth
        depth_limits = {
            ScanDepth.QUICK: 10,      # ~5-15 min
            ScanDepth.BALANCED: 50,   # ~30-60 min (DEFAULT)
            ScanDepth.DEEP: 999999    # All endpoints (2-10h)
        }

        limit = depth_limits.get(scan_depth, 50)
        selected_endpoints = [ep.url for score, ep in scored_endpoints[:limit]]

        logger.info(f"📊 Endpoint prioritization: {len(endpoints)} total → {len(selected_endpoints)} selected for {scan_depth} scan")
        logger.info(f"⏱️  Estimated scan time: {self._estimate_scan_time(len(selected_endpoints))}")

        return selected_endpoints

    def _estimate_scan_time(self, endpoint_count: int) -> str:
        """Estimate scan time based on endpoint count"""
        # Rough estimate: ~20-30 seconds per endpoint for OWASP tests
        minutes = (endpoint_count * 25) / 60  # 25 seconds average

        if minutes < 15:
            return f"{int(minutes)} minutes"
        elif minutes < 120:
            return f"{int(minutes)} minutes ({minutes/60:.1f} hours)"
        else:
            return f"{minutes/60:.1f} hours"

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
            osint_findings = []
            dynamic_endpoints: List[EndpointInfo] = []

            if scan_request.auth_sequence:
                auth_manager = AdvancedAuthManager(client)
                auth_results = await auth_manager.execute_sequence(
                    scan_request.auth_sequence,
                    totp_secret=scan_request.mfa_totp_secret,
                )
                self._record_event(
                    scan_result,
                    "authentication",
                    "Completed advanced authentication sequence",
                    {
                        "steps": [
                            {
                                "index": step.index,
                                "method": step.method,
                                "path": step.path,
                                "status_code": step.status_code,
                                "notes": step.notes,
                            }
                            for step in auth_results
                        ]
                    }
                )

            # ===== PHASE 0: INFRASTRUCTURE RECONNAISSANCE =====
            logger.info(f"\n{'='*70}")
            logger.info(f"🔍 [PHASE 0] INFRASTRUCTURE RECONNAISSANCE")
            logger.info(f"{'='*70}")
            scan_result.status = "infrastructure_recon"
            self._record_event(scan_result, "phase_0", "Infrastructure reconnaissance started")
            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_0_start")
            await self._auto_save(scan_id)

            # Port Scanning
            logger.info(f"🔌 Scanning ports and services...")
            open_ports, port_vulns, port_misconfigs = await self.robust_scanner.execute_with_retry(
                self._safe_port_scan, target_url
            )
            vulnerabilities.extend(port_vulns or [])
            misconfigurations.extend(port_misconfigs or [])
            logger.info(f"✅ Found {len(open_ports or [])} open ports, {len(port_vulns or [])} vulnerabilities")
            self._record_event(
                scan_result,
                "phase_0",
                "Port scan completed",
                {"open_ports": open_ports}
            )

            # SSL/TLS Analysis
            if target_url.startswith('https://'):
                logger.info(f"🔐 Analyzing SSL/TLS configuration...")
                ssl_vulns, ssl_misconfigs = await self.robust_scanner.execute_with_retry(
                    self._safe_ssl_scan, target_url
                )
                vulnerabilities.extend(ssl_vulns or [])
                misconfigurations.extend(ssl_misconfigs or [])
                logger.info(f"✅ SSL/TLS: Found {len(ssl_vulns or [])} vulnerabilities")
                self._record_event(
                    scan_result,
                    "phase_0",
                    "SSL/TLS analysis completed",
                    {"vulnerabilities": len(ssl_vulns or [])}
                )

            # Subdomain Enumeration
            logger.info(f"🌐 Enumerating subdomains...")
            subdomains = await self.robust_scanner.execute_with_retry(
                self._safe_subdomain_scan, target_url
            )
            logger.info(f"✅ Found {len(subdomains or [])} subdomains")
            self._record_event(
                scan_result,
                "phase_0",
                "Subdomain enumeration finished",
                {"count": len(subdomains or [])}
            )

            if scan_request.enrich_osint and settings.ENABLE_OSINT_ENRICHMENT:
                logger.info("🔎 Collecting OSINT enrichment data...")
                osint_enricher = LocalOSINTEnricher(target_url, client)
                osint_findings = await self.robust_scanner.execute_with_retry(osint_enricher.collect)
                scan_result.osint_findings = osint_findings or []
                brain.register_osint(scan_result.osint_findings)
                self._record_event(
                    scan_result,
                    "phase_0",
                    "OSINT enrichment completed",
                    {"findings": scan_result.osint_findings}
                )

            # 🧠 INTELLIGENT ANALYSIS: Infrastructure
            logger.info(f"\n🧠 [BRAIN] Analyzing infrastructure results...")
            infra_intelligence = brain.analyze_infrastructure(open_ports or [], subdomains or [])

            for reasoning in infra_intelligence.get('reasoning', []):
                logger.info(f"💡 {reasoning}")

            await self._auto_save(scan_id)
            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_0_end")
            await self.hook_runner.run_phase_hooks(
                "infrastructure",
                {"scan_id": scan_id, "target": target_url, "open_ports": open_ports}
            )

            # ===== PHASE 1: APPLICATION RECONNAISSANCE =====
            logger.info(f"\n{'='*70}")
            logger.info(f"🔍 [PHASE 1] APPLICATION RECONNAISSANCE")
            logger.info(f"{'='*70}")
            scan_result.status = "reconnaissance"
            self._record_event(scan_result, "phase_1", "Application reconnaissance started")
            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_1_start")

            # Technology Detection
            logger.info(f"🔬 Detecting technologies...")
            tech_detector = TechnologyDetector()
            technologies = await self.robust_scanner.execute_with_retry(
                tech_detector.detect, client
            )
            scan_result.detected_technologies = technologies or []
            logger.info(f"✅ Detected {len(technologies or [])} technologies")
            self._record_event(
                scan_result,
                "phase_1",
                "Technology detection finished",
                {"count": len(technologies or [])}
            )

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
            self._record_event(
                scan_result,
                "phase_1",
                "Primary crawler completed",
                {"count": len(endpoints or [])}
            )

            if scan_request.browser_crawling and settings.ENABLE_BROWSER_CRAWLER:
                logger.info("🧭 Launching browser-based crawler for dynamic routes...")
                browser_crawler = BrowserCrawler(target_url)
                dynamic_endpoints = await self.robust_scanner.execute_with_retry(browser_crawler.crawl)
                scan_result.dynamic_endpoints = dynamic_endpoints or []
                scan_result.browser_crawl_summary = (
                    f"Browser crawler captured {len(dynamic_endpoints or [])} additional endpoints"
                )
                self._record_event(
                    scan_result,
                    "phase_1",
                    "Browser crawler finished",
                    {"count": len(dynamic_endpoints or [])}
                )

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

            if scan_request.collect_api_schemas and settings.ENABLE_API_SCHEMA_COLLECTION:
                logger.info("📘 Collecting API schemas for deeper testing...")
                collector = APISchemaCollector(client)
                candidate_paths = list({
                    urlparse(url).path or '/' for url in endpoint_urls + [
                        ep.url for ep in (dynamic_endpoints or [])
                    ]
                })
                api_schemas = await collector.collect(candidate_paths)
                scan_result.api_schemas = api_schemas
                self._record_event(
                    scan_result,
                    "phase_1",
                    "API schema collection finished",
                    {"count": len(api_schemas)}
                )

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

            # 🎯 SMART ENDPOINT SELECTION - Adapt based on scan depth
            priority_targets = endpoint_intelligence.get('priority_targets', [])
            endpoint_urls_to_test = self._prioritize_endpoints(
                endpoints or [],
                scan_request.scan_depth,
                priority_targets
            )

            await self._auto_save(scan_id)
            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_1_end")
            await self.hook_runner.run_phase_hooks(
                "reconnaissance",
                {
                    "scan_id": scan_id,
                    "target": target_url,
                    "endpoint_count": len(endpoint_urls),
                }
            )

            # Check if stop requested
            if self._should_stop(scan_id):
                logger.info(f"🛑 Scan {scan_id} stopped by user after Phase 1")
                scan_result.status = "stopped"
                self._record_event(scan_result, "scan_control", "Scan stopped by user after reconnaissance phase")
                await self._finalize_scan(scan_id, scan_result, target_url, vulnerabilities, misconfigurations, scan_time)
                return

            # ===== PHASE 2: OWASP TOP 10 - ADAPTIVE TESTING =====
            logger.info(f"\n{'='*70}")
            logger.info(f"🔥 [PHASE 2] OWASP TOP 10 VULNERABILITY SCANNING (ADAPTIVE)")
            logger.info(f"📊 Testing {len(endpoint_urls_to_test)} priority endpoints (Mode: {scan_request.scan_depth})")
            if scan_request.scan_depth == "quick":
                logger.info(f"⚡ QUICK MODE: Testing ~3 payloads/endpoint, skipping time-based tests")
            elif scan_request.scan_depth == "balanced":
                logger.info(f"⚖️  BALANCED MODE: Testing ~10 payloads/endpoint, standard depth")
            else:
                logger.info(f"🔥 DEEP MODE: Testing all payloads, maximum coverage")
            logger.info(f"{'='*70}")
            scan_result.status = "owasp_scanning"
            self._record_event(scan_result, "phase_2", "OWASP Top 10 scanning started")
            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_2_start")

            # Create progress callback to send live updates
            async def progress_callback(message: str):
                logger.info(message)
                self._record_event(scan_result, "phase_2", message)

            if scan_request.enable_active_tests:
                # SQL Injection
                logger.info(f"🗃️  Testing for SQL Injection on {len(endpoint_urls_to_test)} endpoints...")
                sql_scanner = SQLInjectionScanner(client, scan_depth=scan_request.scan_depth, progress_callback=progress_callback)
                sql_vulns = await self.robust_scanner.execute_batch_safe(
                    endpoint_urls_to_test,
                    lambda urls: sql_scanner.scan(urls),
                    max_concurrent=5
                )
                vulnerabilities.extend([v for v in sql_vulns if v])
                logger.info(f"✅ SQL Injection: Found {len([v for v in sql_vulns if v])} vulnerabilities")

                # XSS
                logger.info(f"🎨 Testing for Cross-Site Scripting (XSS) on {len(endpoint_urls_to_test)} endpoints...")
                xss_scanner = XSSScanner(client, scan_depth=scan_request.scan_depth, progress_callback=progress_callback)
                xss_vulns = await self.robust_scanner.execute_batch_safe(
                    endpoint_urls_to_test,
                    lambda urls: xss_scanner.scan(urls),
                    max_concurrent=5
                )
                vulnerabilities.extend([v for v in xss_vulns if v])
                logger.info(f"✅ XSS: Found {len([v for v in xss_vulns if v])} vulnerabilities")

                # Command Injection
                logger.info(f"💻 Testing for Command Injection on {len(endpoint_urls_to_test)} endpoints...")
                cmd_scanner = CommandInjectionScanner(client, scan_depth=scan_request.scan_depth, progress_callback=progress_callback)
                cmd_vulns = await self.robust_scanner.execute_batch_safe(
                    endpoint_urls_to_test,
                    lambda urls: cmd_scanner.scan(urls),
                    max_concurrent=3
                )
                vulnerabilities.extend([v for v in cmd_vulns if v])
                logger.info(f"✅ Command Injection: Found {len([v for v in cmd_vulns if v])} vulnerabilities")

            # SSRF
            logger.info(f"🌐 Testing for SSRF on {len(endpoint_urls_to_test)} endpoints...")
            ssrf_scanner = SSRFScanner(client, scan_depth=scan_request.scan_depth, progress_callback=progress_callback)
            ssrf_vulns = await self.robust_scanner.execute_with_retry(
                ssrf_scanner.scan, endpoint_urls_to_test
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
            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_2_end")
            self._record_event(
                scan_result,
                "phase_2",
                "OWASP Top 10 scanning finished",
                {"vulnerability_count": len(vulnerabilities)}
            )
            await self.hook_runner.run_phase_hooks(
                "owasp",
                {
                    "scan_id": scan_id,
                    "target": target_url,
                    "vulnerability_count": len(vulnerabilities),
                }
            )

            # Check if stop requested
            if self._should_stop(scan_id):
                logger.info(f"🛑 Scan {scan_id} stopped by user after Phase 2")
                scan_result.status = "stopped"
                self._record_event(scan_result, "scan_control", "Scan stopped by user after OWASP phase")
                await self._finalize_scan(scan_id, scan_result, target_url, vulnerabilities, misconfigurations, scan_time)
                return

            # ===== PHASE 2.5: API SECURITY TESTING =====
            logger.info(f"\n{'='*70}")
            logger.info(f"🔐 [PHASE 2.5] API SECURITY TESTING (JWT, GraphQL, NoSQL)")
            logger.info(f"{'='*70}")
            scan_result.status = "api_security_testing"
            self._record_event(scan_result, "phase_2.5", "API security testing started")
            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_2.5_start")

            # JWT Security Testing
            logger.info(f"🔐 Testing JWT Security on {len(endpoint_urls_to_test)} endpoints...")
            jwt_scanner = JWTSecurityScanner(client, scan_depth=scan_request.scan_depth, progress_callback=progress_callback)
            jwt_vulns = await self.robust_scanner.execute_with_retry(
                jwt_scanner.scan, endpoint_urls_to_test
            )
            vulnerabilities.extend(jwt_vulns or [])
            logger.info(f"✅ JWT Security: Found {len(jwt_vulns or [])} vulnerabilities")

            # GraphQL Security Testing
            logger.info(f"🎨 Testing GraphQL Security on {len(endpoint_urls_to_test)} endpoints...")
            graphql_scanner = GraphQLSecurityScanner(client, scan_depth=scan_request.scan_depth, progress_callback=progress_callback)
            graphql_vulns = await self.robust_scanner.execute_with_retry(
                graphql_scanner.scan, endpoint_urls_to_test
            )
            vulnerabilities.extend(graphql_vulns or [])
            logger.info(f"✅ GraphQL Security: Found {len(graphql_vulns or [])} vulnerabilities")

            # NoSQL Injection Testing
            logger.info(f"🗄️  Testing NoSQL Injection on {len(endpoint_urls_to_test)} endpoints...")
            nosql_scanner = NoSQLInjectionScanner(client, scan_depth=scan_request.scan_depth, progress_callback=progress_callback)
            nosql_vulns = await self.robust_scanner.execute_with_retry(
                nosql_scanner.scan, endpoint_urls_to_test
            )
            vulnerabilities.extend(nosql_vulns or [])
            logger.info(f"✅ NoSQL Injection: Found {len(nosql_vulns or [])} vulnerabilities")

            # File Upload Security Testing
            logger.info(f"📤 Testing File Upload Security on {len(endpoint_urls_to_test)} endpoints...")
            upload_scanner = FileUploadScanner(client, scan_depth=scan_request.scan_depth, progress_callback=progress_callback)
            upload_vulns = await self.robust_scanner.execute_with_retry(
                upload_scanner.scan, endpoint_urls_to_test
            )
            vulnerabilities.extend(upload_vulns or [])
            logger.info(f"✅ File Upload Security: Found {len(upload_vulns or [])} vulnerabilities")

            await self._auto_save(scan_id)
            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_2.5_end")
            self._record_event(
                scan_result,
                "phase_2.5",
                "API security testing finished",
                {"api_vulnerability_count": len(jwt_vulns or []) + len(graphql_vulns or []) + len(nosql_vulns or []) + len(upload_vulns or [])}
            )
            await self.hook_runner.run_phase_hooks(
                "api_security",
                {
                    "scan_id": scan_id,
                    "target": target_url,
                    "jwt_vulns": len(jwt_vulns or []),
                    "graphql_vulns": len(graphql_vulns or []),
                    "nosql_vulns": len(nosql_vulns or []),
                    "upload_vulns": len(upload_vulns or []),
                }
            )

            # ===== PHASE 3: ACCESS CONTROL =====
            logger.info(f"\n{'='*70}")
            logger.info(f"🔒 [PHASE 3] ACCESS CONTROL TESTING")
            logger.info(f"{'='*70}")
            scan_result.status = "access_control_testing"
            self._record_event(scan_result, "phase_3", "Access control testing started")
            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_3_start")

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
            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_3_end")
            self._record_event(
                scan_result,
                "phase_3",
                "Access control testing finished",
                {"idor": len(idor_vulns or []), "privilege": len(priv_vulns or []) if 'priv_vulns' in locals() else 0}
            )
            await self.hook_runner.run_phase_hooks(
                "access_control",
                {
                    "scan_id": scan_id,
                    "target": target_url,
                    "idor": len(idor_vulns or []),
                }
            )

            # ===== PHASE 4: SECURITY MISCONFIGURATION =====
            logger.info(f"\n{'='*70}")
            logger.info(f"🔧 [PHASE 4] SECURITY MISCONFIGURATION")
            logger.info(f"{'='*70}")
            scan_result.status = "misconfiguration_scanning"
            self._record_event(scan_result, "phase_4", "Security misconfiguration review started")
            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_4_start")

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

            if scan_request.track_stability and settings.ENABLE_STABILITY_MONITORING:
                self._snapshot_stability(scan_result, "phase_4_end")
            self._record_event(
                scan_result,
                "phase_4",
                "Security misconfiguration review finished",
                {"misconfigurations": len(misconfigurations)}
            )
            await self.hook_runner.run_phase_hooks(
                "misconfiguration",
                {
                    "scan_id": scan_id,
                    "target": target_url,
                    "misconfigurations": len(misconfigurations),
                }
            )

            # ===== FINALIZATION =====
            scan_result.attack_chains = brain.plan_attack_chains(
                vulnerabilities,
                osint_findings=osint_findings,
                dynamic_endpoints=dynamic_endpoints,
            )
            artifacts = self.exploitation_assistant.build_artifacts(vulnerabilities)
            if artifacts:
                scan_result.artifacts.extend(artifacts)
                self._record_event(
                    scan_result,
                    "finalization",
                    "Generated exploitation artifacts",
                    {"count": len(artifacts)}
                )

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
            self._record_event(
                scan_result,
                "finalization",
                "Scan completed",
                {
                    "duration": scan_result.scan_duration,
                    "vulnerabilities": len(vulnerabilities),
                    "misconfigurations": len(misconfigurations),
                }
            )

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
            self._record_event(
                scan_result,
                "finalization",
                "Scan failed",
                {"error": str(e)}
            )
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

    def stop_scan(self, scan_id: str) -> bool:
        """Request to stop a running scan"""
        if scan_id in self.active_scans:
            self.stop_flags[scan_id] = True
            logger.info(f"🛑 Stop requested for scan {scan_id}")
            return True
        return False

    def _should_stop(self, scan_id: str) -> bool:
        """Check if scan should stop"""
        return self.stop_flags.get(scan_id, False)

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

    async def start_playbook(self, playbook_request: PlaybookRequest) -> PlaybookRun:
        playbook_id = str(uuid.uuid4())
        run = PlaybookRun(
            playbook_id=playbook_id,
            name=playbook_request.name,
            started_at=datetime.utcnow(),
            targets=playbook_request.targets,
            sequential=playbook_request.sequential,
        )
        self.playbooks[playbook_id] = run

        for target in playbook_request.targets:
            scan_request = ScanRequest(
                target_url=target.target_url,
                mode=target.mode,
                auth_token=target.auth_token,
                custom_headers=target.custom_headers,
                cookies=target.cookies,
            )
            scan_id = await self.start_scan(scan_request)
            run.scan_ids.append(scan_id)
            active_scan = self.active_scans.get(scan_id)
            if active_scan:
                active_scan.playbook_runs.append(run)

        return run

    def get_playbook(self, playbook_id: str) -> Optional[PlaybookRun]:
        run = self.playbooks.get(playbook_id)
        if not run:
            return None

        status_overview = []
        all_completed = True

        for scan_id in run.scan_ids:
            result = self.get_scan_result(scan_id)
            status = result.status if result else "unknown"
            status_overview.append({
                "scan_id": scan_id,
                "status": status,
                "target": result.target_url if result else None,
            })
            if status != "completed":
                all_completed = False

        run.completed = all_completed
        run.status_overview = status_overview
        return run

    def generate_report(self, scan_id: str) -> Dict[str, Any]:
        result = self.get_scan_result(scan_id)
        if not result:
            raise ValueError("Scan not found")
        return self.storage.generate_markdown_report(result)

    def compare_scans(self, scan_a_id: str, scan_b_id: str) -> Dict[str, Any]:
        scan_a = self.get_scan_result(scan_a_id)
        scan_b = self.get_scan_result(scan_b_id)

        if not scan_a or not scan_b:
            raise ValueError("Both scans must exist to compare")

        return self.storage.compare_scans(scan_a, scan_b)
