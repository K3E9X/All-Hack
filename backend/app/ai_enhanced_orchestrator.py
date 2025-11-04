"""
AI-Enhanced Scanner Orchestrator
Integrates Enhanced Autonomous AI Agent with the scan orchestrator

Features:
- Real-time AI decision making during scans
- Memory system integration
- Intelligent payload generation
- Exploitation chain discovery
- Professional report generation
- Autonomous adaptation
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

from app.scanner_orchestrator import ScanOrchestrator
from app.models import ScanRequest, ScanResult
from app.config import settings

# Import Enhanced AI Agent
from app.ai_agent.enhanced_autonomous_agent import EnhancedAutonomousPentestAgent

logger = logging.getLogger(__name__)


class AIEnhancedScanOrchestrator(ScanOrchestrator):
    """
    Scanner Orchestrator with Enhanced AI Agent Integration

    Extends base ScanOrchestrator with:
    - Real-time AI decision making
    - Memory-based learning
    - Intelligent payload generation
    - Exploitation chain discovery
    - Professional report generation
    """

    def __init__(self):
        super().__init__()

        # Initialize Enhanced AI Agent
        self.ai_agent: Optional[EnhancedAutonomousPentestAgent] = None

        if getattr(settings, 'ENABLE_AI_AGENT', False):
            try:
                self.ai_agent = EnhancedAutonomousPentestAgent(
                    claude_api_key=getattr(settings, 'ANTHROPIC_API_KEY', None),
                    storage_path=getattr(settings, 'AI_AGENT_STORAGE_PATH', './data/agent_memory')
                )

                if self.ai_agent.enabled:
                    logger.info("🤖 AI-Enhanced Scanner Orchestrator initialized with AI Agent!")
                    logger.info("   ├─ 🧠 Memory System: ACTIVE")
                    logger.info("   ├─ 🎯 Payload Generator: ACTIVE")
                    logger.info("   ├─ 🔗 Exploitation Chain Builder: ACTIVE")
                    logger.info("   └─ 📄 Report Generator: ACTIVE")
                else:
                    logger.warning("⚠️  AI Agent initialized but disabled (missing API key)")
                    self.ai_agent = None

            except Exception as e:
                logger.error(f"❌ Failed to initialize AI Agent: {e}")
                self.ai_agent = None
        else:
            logger.info("ℹ️  AI Agent disabled in settings")

    async def start_scan(self, scan_request: ScanRequest) -> str:
        """Start AI-enhanced scan"""
        scan_id = await super().start_scan(scan_request)

        # Start AI memory session if enabled
        if self.ai_agent and self.ai_agent.enabled:
            scan_result = self.active_scans.get(scan_id)
            if scan_result:
                logger.info(f"🧠 Starting AI memory session for scan {scan_id}")
                self.ai_agent.memory.start_session(
                    session_id=scan_id,
                    target=scan_result.target_url
                )

                # Check for similar targets
                similar_insights = self.ai_agent.memory.get_similar_target_insights(
                    scan_result.target_url
                )

                if similar_insights["found_similar"]:
                    logger.info(f"🎓 Found {similar_insights['similar_count']} similar targets in memory")
                    logger.info("💡 AI Agent will use historical patterns for intelligent testing")

                    # Record in timeline
                    self._record_event(
                        scan_result,
                        "ai_agent",
                        f"AI Agent activated - found {similar_insights['similar_count']} similar targets",
                        {"recommendations": similar_insights.get("recommendations", [])}
                    )

        return scan_id

    async def _ai_analyze_after_phase(
        self,
        scan_id: str,
        phase_name: str,
        phase_results: Dict[str, Any]
    ):
        """AI analysis and decision making after each scan phase"""
        if not self.ai_agent or not self.ai_agent.enabled:
            return

        scan_result = self.active_scans.get(scan_id)
        if not scan_result:
            return

        try:
            logger.info(f"\n{'='*70}")
            logger.info(f"🤖 AI AGENT - Analyzing {phase_name} Results")
            logger.info(f"{'='*70}")

            # AI analyzes current state
            decision = await self.ai_agent.analyze_and_decide(scan_result)

            # Remember this decision
            context = self.ai_agent._build_analysis_context(scan_result)
            self.ai_agent.memory.remember_decision(decision, context)

            # Log AI's strategic thinking
            if decision.get('reasoning'):
                logger.info(f"🧠 AI Agent Analysis:")
                logger.info(f"   {decision.get('reasoning')}")
                logger.info(f"   Confidence: {decision.get('confidence', 0):.0%}")

            # Check if AI recommends additional tests
            if decision.get('next_actions'):
                logger.info(f"\n🎯 AI Agent recommends {len(decision['next_actions'])} additional tests:")

                for idx, action in enumerate(decision['next_actions'][:3], 1):  # Limit to 3 for performance
                    logger.info(f"\n   {idx}. {action['test']}")
                    logger.info(f"      Priority: {action['priority']}")
                    logger.info(f"      Reason: {action['reason']}")

                    # Execute AI-recommended test if time permits
                    # (Implementation depends on specific scanner availability)
                    await self._execute_ai_recommended_test(scan_id, action)

            # Record AI analysis in timeline
            self._record_event(
                scan_result,
                "ai_agent",
                f"AI analysis after {phase_name}",
                {
                    "reasoning": decision.get('reasoning'),
                    "confidence": decision.get('confidence'),
                    "actions_recommended": len(decision.get('next_actions', []))
                }
            )

        except Exception as e:
            logger.error(f"❌ AI analysis failed: {e}")

    async def _execute_ai_recommended_test(
        self,
        scan_id: str,
        action: Dict[str, Any]
    ):
        """Execute test recommended by AI Agent"""
        scan_result = self.active_scans.get(scan_id)
        if not scan_result:
            return

        test_type = action['test']
        target = action['target']

        logger.info(f"   🔧 Executing AI-recommended test: {test_type}")

        try:
            # Track attempt
            start_time = datetime.utcnow()

            # Execute based on test type (extend as needed)
            new_vulns = []

            # Map test types to scanner methods
            test_mapping = {
                'jwt_deep_analysis': self._execute_jwt_deep_test,
                'graphql_advanced': self._execute_graphql_advanced_test,
                'nosql_advanced': self._execute_nosql_advanced_test,
                'file_upload_advanced': self._execute_file_upload_advanced_test,
            }

            executor = test_mapping.get(test_type)
            if executor:
                new_vulns = await executor(scan_result, target)

            # Remember result
            success = len(new_vulns) > 0
            self.ai_agent.memory.remember_exploit_attempt(
                test_type=test_type,
                target=target,
                payload=action.get('payload', 'N/A'),
                success=success,
                result={
                    "vulnerabilities_found": len(new_vulns),
                    "execution_time": (datetime.utcnow() - start_time).total_seconds()
                }
            )

            if new_vulns:
                logger.info(f"   ✅ AI-recommended test found {len(new_vulns)} vulnerabilities!")
                scan_result.vulnerabilities.extend(new_vulns)

                # Remember findings
                for vuln in new_vulns:
                    self.ai_agent.memory.remember_finding(
                        self.ai_agent._vuln_to_dict(vuln)
                    )
            else:
                logger.info(f"   ℹ️  AI-recommended test completed, no new vulnerabilities")

        except Exception as e:
            logger.error(f"   ❌ AI-recommended test failed: {e}")
            self.ai_agent.memory.remember_exploit_attempt(
                test_type=test_type,
                target=target,
                payload='N/A',
                success=False,
                result={"error": str(e)}
            )

    async def _execute_jwt_deep_test(self, scan_result: ScanResult, target: str):
        """Execute deep JWT analysis"""
        from app.scanners.api_security import JWTSecurityScanner
        from app.utils import PentestHTTPClient

        client = PentestHTTPClient(base_url=scan_result.target_url)
        scanner = JWTSecurityScanner(client, scan_depth="deep")

        endpoints = [target] if target != "all" else [ep.url for ep in scan_result.discovered_endpoints[:10]]
        return await scanner.scan(endpoints)

    async def _execute_graphql_advanced_test(self, scan_result: ScanResult, target: str):
        """Execute advanced GraphQL testing"""
        from app.scanners.api_security import GraphQLSecurityScanner
        from app.utils import PentestHTTPClient

        client = PentestHTTPClient(base_url=scan_result.target_url)
        scanner = GraphQLSecurityScanner(client, scan_depth="deep")

        endpoints = [target] if target != "all" else [ep.url for ep in scan_result.discovered_endpoints[:10]]
        return await scanner.scan(endpoints)

    async def _execute_nosql_advanced_test(self, scan_result: ScanResult, target: str):
        """Execute advanced NoSQL injection testing"""
        from app.scanners.api_security import NoSQLInjectionScanner
        from app.utils import PentestHTTPClient

        client = PentestHTTPClient(base_url=scan_result.target_url)
        scanner = NoSQLInjectionScanner(client, scan_depth="deep")

        endpoints = [target] if target != "all" else [ep.url for ep in scan_result.discovered_endpoints[:10]]
        return await scanner.scan(endpoints)

    async def _execute_file_upload_advanced_test(self, scan_result: ScanResult, target: str):
        """Execute advanced file upload testing"""
        from app.scanners.api_security import FileUploadScanner
        from app.utils import PentestHTTPClient

        client = PentestHTTPClient(base_url=scan_result.target_url)
        scanner = FileUploadScanner(client, scan_depth="deep")

        endpoints = [target] if target != "all" else [ep.url for ep in scan_result.discovered_endpoints[:10]]
        return await scanner.scan(endpoints)

    async def _generate_ai_reports(self, scan_id: str) -> Dict[str, str]:
        """Generate professional reports using AI"""
        if not self.ai_agent or not self.ai_agent.enabled:
            return {}

        scan_result = self.active_scans.get(scan_id)
        if not scan_result:
            return {}

        try:
            logger.info(f"\n{'='*70}")
            logger.info(f"📄 AI AGENT - Generating Professional Reports")
            logger.info(f"{'='*70}")

            scan_result_dict = self.ai_agent._scan_result_to_dict(scan_result)
            memory_data = self.ai_agent.memory.export_session_report()

            # Generate all report types
            reports = {}

            # Executive Summary
            logger.info("📊 Generating executive summary (for management)...")
            reports['executive_summary'] = await self.ai_agent.report_generator.generate_executive_summary(
                scan_result_dict,
                memory_data
            )

            # Technical Report
            logger.info("🔬 Generating technical report (for security team)...")
            reports['technical_report'] = await self.ai_agent.report_generator.generate_technical_report(
                scan_result_dict,
                include_payloads=False
            )

            # Remediation Plan
            logger.info("🛠️  Generating remediation plan (30-day phases)...")
            reports['remediation_plan'] = await self.ai_agent.report_generator.generate_remediation_plan(
                [self.ai_agent._vuln_to_dict(v) for v in scan_result.vulnerabilities],
                timeline="30_days"
            )

            # Risk Assessment
            logger.info("⚖️  Generating risk assessment (business impact)...")
            reports['risk_assessment'] = await self.ai_agent.report_generator.generate_risk_assessment(
                scan_result_dict
            )

            # Exploitation Chains
            logger.info("🔗 Finding exploitation chains...")
            chains = await self.ai_agent.chain_builder.find_exploitation_chains(
                [self.ai_agent._vuln_to_dict(v) for v in scan_result.vulnerabilities]
            )

            if chains:
                logger.info(f"   ✅ Found {len(chains)} exploitation chains")
                reports['exploitation_chains'] = self.ai_agent.chain_builder.generate_chain_report(chains)
            else:
                logger.info("   ℹ️  No exploitation chains identified")
                reports['exploitation_chains'] = "No exploitation chains identified."

            logger.info("✅ All AI reports generated successfully")

            # Record in timeline
            self._record_event(
                scan_result,
                "ai_agent",
                "Professional reports generated",
                {
                    "report_types": list(reports.keys()),
                    "exploitation_chains_found": len(chains) if chains else 0
                }
            )

            return reports

        except Exception as e:
            logger.error(f"❌ AI report generation failed: {e}")
            return {}

    async def _finalize_scan_with_ai(self, scan_id: str):
        """Finalize scan with AI analysis and reporting"""
        if not self.ai_agent or not self.ai_agent.enabled:
            return

        scan_result = self.active_scans.get(scan_id)
        if not scan_result:
            return

        try:
            logger.info(f"\n{'='*70}")
            logger.info(f"🤖 AI AGENT - Finalizing Scan")
            logger.info(f"{'='*70}")

            # Generate professional reports
            reports = await self._generate_ai_reports(scan_id)

            # Save reports to scan result (if ScanResult model supports it)
            if hasattr(scan_result, 'ai_reports'):
                scan_result.ai_reports = reports

            # End memory session
            self.ai_agent.memory.end_session()

            # Get learning insights
            insights = self.ai_agent.memory.get_learning_insights()

            logger.info(f"\n🎓 AI Learning Insights:")
            logger.info(f"   Total sessions: {insights['total_sessions']}")
            logger.info(f"   Total vulnerabilities found: {insights['total_vulnerabilities']}")
            logger.info(f"   Patterns learned: {insights['patterns_learned']}")
            logger.info(f"   Targets scanned: {insights['targets_scanned']}")

            # Most common vulnerabilities
            if insights['most_common_vulnerabilities']:
                logger.info(f"\n📊 Most Common Vulnerabilities (historical):")
                for vuln_type, count in insights['most_common_vulnerabilities'][:5]:
                    logger.info(f"   - {vuln_type}: {count} occurrences")

            # Record final AI summary
            self._record_event(
                scan_result,
                "ai_agent",
                "AI Agent scan finalization complete",
                {
                    "reports_generated": list(reports.keys()),
                    "learning_insights": insights,
                    "session_saved": True
                }
            )

            logger.info(f"\n✅ AI Agent finalization complete")
            logger.info(f"💾 Session saved to long-term memory for future learning")

        except Exception as e:
            logger.error(f"❌ AI finalization failed: {e}")

    def get_ai_insights(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get AI insights for a completed scan"""
        if not self.ai_agent or not self.ai_agent.enabled:
            return None

        scan_result = self.active_scans.get(scan_id)
        if not scan_result:
            return None

        try:
            # Get exploitation chains
            chains = []
            if scan_result.vulnerabilities:
                import asyncio
                chains = asyncio.run(
                    self.ai_agent.chain_builder.find_exploitation_chains(
                        [self.ai_agent._vuln_to_dict(v) for v in scan_result.vulnerabilities]
                    )
                )

            return {
                "ai_enabled": True,
                "memory_insights": self.ai_agent.memory.get_learning_insights(),
                "exploitation_chains": chains,
                "session_data": self.ai_agent.memory.export_session_report()
            }

        except Exception as e:
            logger.error(f"Failed to get AI insights: {e}")
            return None
