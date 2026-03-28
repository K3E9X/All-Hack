"""
ENHANCED Autonomous Penetration Testing Agent
Integrates all AI components: Memory, Payloads, Chains, Reports

Complete AI-powered pentesting with:
- Persistent memory and learning
- Intelligent payload generation
- Exploitation chain building
- Professional report generation
- Real-time decision making
"""

import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio

try:
    from anthropic import AsyncAnthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logging.warning("Anthropic library not installed. AI Agent features will be disabled.")

from app.models.scan import ScanResult, Vulnerability, SeverityLevel
from app.config import settings

# Import our new AI modules
from app.ai_agent.memory_system import AgentMemory
from app.ai_agent.payload_generator import AIPayloadGenerator
from app.ai_agent.exploitation_chains import ExploitationChainBuilder, ExploitationGoal
from app.ai_agent.report_generator import AIPoweredReportGenerator

logger = logging.getLogger(__name__)


class EnhancedAutonomousPentestAgent:
    """
    COMPLETE AI-Powered Autonomous Pentesting Agent

    Features:
    - Learns from past scans (memory system)
    - Generates intelligent payloads (AI-powered)
    - Builds exploitation chains
    - Creates professional reports
    - Makes autonomous decisions
    - Works while you sleep 😴
    """

    def __init__(self, claude_api_key: Optional[str] = None, storage_path: Optional[str] = None):
        """
        Initialize the enhanced autonomous agent with all AI components

        Args:
            claude_api_key: Anthropic API key (if None, uses settings.ANTHROPIC_API_KEY)
            storage_path: Path for memory storage (default: ./data/agent_memory)
        """
        self.api_key = claude_api_key or getattr(settings, 'ANTHROPIC_API_KEY', None)

        if not ANTHROPIC_AVAILABLE:
            logger.warning("⚠️  Anthropic library not installed. Install with: pip install anthropic")
            self.enabled = False
            return

        if not self.api_key:
            logger.warning("⚠️  No Claude API key provided. AI Agent features will be disabled.")
            self.enabled = False
            return

        # Initialize Claude client
        self.client = AsyncAnthropic(api_key=self.api_key)
        self.enabled = True
        self.max_iterations = getattr(settings, 'AI_AGENT_MAX_ITERATIONS', 10)

        # Initialize AI components
        self.memory = AgentMemory(storage_path=storage_path)
        self.payload_generator = AIPayloadGenerator(api_key=self.api_key, memory_system=self.memory)
        self.chain_builder = ExploitationChainBuilder(ai_client=self.client)
        self.report_generator = AIPoweredReportGenerator(api_key=self.api_key)

        logger.info("🤖 Enhanced Autonomous AI Agent initialized!")
        logger.info("   ├─ 🧠 Memory System: ACTIVE")
        logger.info("   ├─ 🎯 Payload Generator: ACTIVE")
        logger.info("   ├─ 🔗 Exploitation Chain Builder: ACTIVE")
        logger.info("   └─ 📄 Report Generator: ACTIVE")

    async def start_autonomous_scan(
        self,
        scan_result: ScanResult,
        executor_callback,
        generate_report: bool = True
    ) -> Dict[str, Any]:
        """
        Run complete autonomous scan with all AI features

        Args:
            scan_result: Initial scan result
            executor_callback: Async function to execute tests
            generate_report: Generate professional report at end

        Returns:
            Complete results with report
        """
        if not self.enabled:
            logger.warning("🤖 AI Agent disabled")
            return {"scan_result": scan_result, "report": None}

        # Start memory session
        self.memory.start_session(
            session_id=scan_result.scan_id,
            target=scan_result.target_url
        )

        logger.info("\n" + "="*80)
        logger.info("🤖 ENHANCED AUTONOMOUS AI AGENT - STARTING")
        logger.info("="*80)
        logger.info(f"📍 Target: {scan_result.target_url}")
        logger.info(f"🆔 Session: {scan_result.scan_id}")
        logger.info(f"🔄 Max iterations: {self.max_iterations}")
        logger.info("💤 You can go to sleep - AI agent will work autonomously!")
        logger.info("="*80 + "\n")

        # Phase 1: Check for similar targets in memory
        similar_insights = self.memory.get_similar_target_insights(scan_result.target_url)
        if similar_insights["found_similar"]:
            logger.info(f"🎓 Found {similar_insights['similar_count']} similar targets in memory")
            logger.info(f"💡 Recommendations based on history:")
            for rec in similar_insights["recommendations"]:
                logger.info(f"   - {rec}")

        # Phase 2: Autonomous iteration loop
        iteration = 0
        while iteration < self.max_iterations:
            iteration += 1

            logger.info(f"\n{'='*80}")
            logger.info(f"🤖 AI AGENT - ITERATION {iteration}/{self.max_iterations}")
            logger.info(f"{'='*80}")

            # Analyze current state and decide next actions
            decision = await self.analyze_and_decide(scan_result)

            # Remember this decision
            context = self._build_analysis_context(scan_result)
            self.memory.remember_decision(decision, context)

            # Check if AI recommends stopping
            if not decision.get('next_actions'):
                logger.info("🎯 AI Agent: No more recommended actions. Optimization complete!")
                logger.info(f"💡 Reasoning: {decision.get('reasoning')}")
                break

            # Log AI's strategy
            logger.info(f"\n🧠 AI Agent Strategy:")
            logger.info(f"   Reasoning: {decision.get('reasoning')}")
            logger.info(f"   Confidence: {decision.get('confidence', 0):.0%}")
            logger.info(f"   Estimated time: {decision.get('estimated_time_minutes', 0)} minutes")
            logger.info(f"   Strategy: {decision.get('exploitation_strategy', 'N/A')}")

            # Execute each recommended action
            for idx, action in enumerate(decision['next_actions'], 1):
                logger.info(f"\n🎯 Executing action {idx}/{len(decision['next_actions'])}: {action['test']}")
                logger.info(f"   Target: {action['target']}")
                logger.info(f"   Priority: {action['priority']}")
                logger.info(f"   Reason: {action['reason']}")

                try:
                    # Execute via callback
                    new_findings = await executor_callback(action)

                    # Remember exploit attempt
                    self.memory.remember_exploit_attempt(
                        test_type=action['test'],
                        target=action['target'],
                        payload=action.get('payload', 'N/A'),
                        success=len(new_findings) > 0 if new_findings else False,
                        result={"findings_count": len(new_findings)} if new_findings else None
                    )

                    # Update scan result
                    if new_findings:
                        scan_result.vulnerabilities.extend(new_findings)

                        # Remember findings
                        for finding in new_findings:
                            self.memory.remember_finding(self._vuln_to_dict(finding))

                        logger.info(f"✅ Found {len(new_findings)} new vulnerabilities")
                    else:
                        logger.info(f"ℹ️  No new vulnerabilities found")

                except Exception as e:
                    logger.error(f"❌ Failed to execute action {action['test']}: {e}")
                    self.memory.remember_exploit_attempt(
                        test_type=action['test'],
                        target=action['target'],
                        payload='N/A',
                        success=False,
                        result={"error": str(e)}
                    )

            # Small delay between iterations
            await asyncio.sleep(2)

        # Phase 3: Exploitation chain analysis
        logger.info(f"\n{'='*80}")
        logger.info("🔗 EXPLOITATION CHAIN ANALYSIS")
        logger.info(f"{'='*80}")

        chains = await self.chain_builder.find_exploitation_chains(
            vulnerabilities=[self._vuln_to_dict(v) for v in scan_result.vulnerabilities]
        )

        if chains:
            logger.info(f"✅ Found {len(chains)} exploitation chains:")
            for idx, chain in enumerate(chains[:5], 1):
                logger.info(f"\n   {idx}. {chain['name']}")
                logger.info(f"      Goal: {chain['goal']}")
                logger.info(f"      Complexity: {chain['complexity']}")
                logger.info(f"      Success Probability: {chain['success_probability']:.0%}")
                logger.info(f"      Impact: {chain['impact']}")

            # Generate chain report
            chain_report = self.chain_builder.generate_chain_report(chains)
        else:
            logger.info("ℹ️  No exploitation chains identified")
            chain_report = None

        # Phase 4: End session and save memory
        self.memory.end_session()

        # Get learning insights
        insights = self.memory.get_learning_insights()
        logger.info(f"\n🎓 Learning Insights:")
        logger.info(f"   Total sessions: {insights['total_sessions']}")
        logger.info(f"   Total vulnerabilities found: {insights['total_vulnerabilities']}")
        logger.info(f"   Patterns learned: {insights['patterns_learned']}")
        logger.info(f"   Targets scanned: {insights['targets_scanned']}")

        # Phase 5: Generate professional reports
        final_report = None
        if generate_report:
            logger.info(f"\n{'='*80}")
            logger.info("📄 GENERATING PROFESSIONAL REPORTS")
            logger.info(f"{'='*80}")

            scan_result_dict = self._scan_result_to_dict(scan_result)

            # Executive summary
            logger.info("📊 Generating executive summary...")
            exec_summary = await self.report_generator.generate_executive_summary(
                scan_result_dict,
                self.memory.export_session_report()
            )

            # Technical report
            logger.info("🔬 Generating technical report...")
            technical_report = await self.report_generator.generate_technical_report(
                scan_result_dict,
                include_payloads=False  # Set to True if needed
            )

            # Remediation plan
            logger.info("🛠️  Generating remediation plan...")
            remediation_plan = await self.report_generator.generate_remediation_plan(
                [self._vuln_to_dict(v) for v in scan_result.vulnerabilities],
                timeline="30_days"
            )

            # Risk assessment
            logger.info("⚖️  Generating risk assessment...")
            risk_assessment = await self.report_generator.generate_risk_assessment(
                scan_result_dict
            )

            final_report = {
                "executive_summary": exec_summary,
                "technical_report": technical_report,
                "remediation_plan": remediation_plan,
                "risk_assessment": risk_assessment,
                "exploitation_chains": chain_report,
            }

            logger.info("✅ All reports generated successfully")

        # Final summary
        logger.info(f"\n{'='*80}")
        logger.info("🎉 AUTONOMOUS SCAN COMPLETE!")
        logger.info(f"{'='*80}")
        logger.info(f"📊 Final Statistics:")
        logger.info(f"   Total vulnerabilities: {len(scan_result.vulnerabilities)}")
        logger.info(f"   AI iterations: {iteration}")
        logger.info(f"   Exploitation chains found: {len(chains) if chains else 0}")
        logger.info(f"   Session success rate: {self.memory._calculate_success_rate():.1%}")
        logger.info(f"{'='*80}\n")

        return {
            "scan_result": scan_result,
            "report": final_report,
            "exploitation_chains": chains,
            "memory_insights": insights,
            "session_summary": self.memory.export_session_report(),
        }

    async def analyze_and_decide(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Analyze current scan results and decide next actions

        Args:
            scan_result: Current scan results

        Returns:
            Decision dict with next_actions, reasoning, and priority
        """
        if not self.enabled:
            return {"next_actions": [], "reasoning": "AI Agent disabled", "confidence": 0.0}

        try:
            # Build context
            context = self._build_analysis_context(scan_result)

            # Ask Claude to analyze
            prompt = self._create_decision_prompt(context)

            logger.debug("🧠 AI Agent analyzing scan results...")

            response = await self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=3000,
                temperature=0.7,
                messages=[{"role": "user", "content": prompt}]
            )

            # Parse decision
            decision_text = response.content[0].text
            decision = self._parse_decision(decision_text)

            logger.debug(f"🎯 AI Agent decision: {len(decision.get('next_actions', []))} actions recommended")

            return decision

        except Exception as e:
            logger.error(f"❌ AI Agent analysis failed: {e}")
            return {"next_actions": [], "reasoning": f"Error: {str(e)}", "confidence": 0.0}

    def _build_analysis_context(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Build context from current scan results"""
        # Categorize vulnerabilities by severity
        critical_vulns = [v for v in scan_result.vulnerabilities if v.severity == SeverityLevel.CRITICAL]
        high_vulns = [v for v in scan_result.vulnerabilities if v.severity == SeverityLevel.HIGH]
        medium_vulns = [v for v in scan_result.vulnerabilities if v.severity == SeverityLevel.MEDIUM]

        # Categorize by type
        vuln_by_category = {}
        for vuln in scan_result.vulnerabilities:
            category = vuln.category.value
            if category not in vuln_by_category:
                vuln_by_category[category] = []
            vuln_by_category[category].append({
                "title": vuln.title,
                "severity": vuln.severity.value,
                "url": vuln.affected_url,
                "parameter": vuln.affected_parameter
            })

        context = {
            "target_url": scan_result.target_url,
            "scan_id": scan_result.scan_id,
            "mode": scan_result.mode.value,
            "status": scan_result.status,
            "statistics": {
                "total_vulnerabilities": len(scan_result.vulnerabilities),
                "critical": len(critical_vulns),
                "high": len(high_vulns),
                "medium": len(medium_vulns),
                "endpoints_discovered": len(scan_result.discovered_endpoints),
                "technologies": [t.name for t in scan_result.detected_technologies]
            },
            "vulnerabilities_by_category": vuln_by_category,
            "detected_technologies": [
                {
                    "name": tech.name,
                    "version": tech.version,
                    "categories": tech.categories
                }
                for tech in scan_result.detected_technologies
            ],
            "critical_vulnerabilities_details": [
                {
                    "title": v.title,
                    "category": v.category.value,
                    "url": v.affected_url,
                    "description": v.description[:200]
                }
                for v in critical_vulns[:5]
            ]
        }

        return context

    def _create_decision_prompt(self, context: Dict[str, Any]) -> str:
        """Create prompt for Claude to make decisions"""
        prompt = f"""You are an expert autonomous penetration testing AI agent. Analyze scan results and decide which tests to perform next.

# Current Scan Context
**Target:** {context['target_url']}
**Scan Mode:** {context['mode']}
**Status:** {context['status']}

## Statistics
- Total Vulnerabilities: {context['statistics']['total_vulnerabilities']}
  - Critical: {context['statistics']['critical']}
  - High: {context['statistics']['high']}
  - Medium: {context['statistics']['medium']}
- Endpoints: {context['statistics']['endpoints_discovered']}
- Technologies: {', '.join(context['statistics']['technologies'][:10])}

## Vulnerabilities by Category
{json.dumps(context['vulnerabilities_by_category'], indent=2)}

## Critical Vulnerabilities
{json.dumps(context['critical_vulnerabilities_details'], indent=2)}

## Technologies
{json.dumps(context['detected_technologies'][:5], indent=2)}

---

# Your Task
Decide what additional tests should be performed to maximize vulnerability discovery.

**Available Tests:**
- jwt_deep_analysis, graphql_advanced, nosql_advanced, file_upload_advanced
- session_management, rate_limiting, business_logic
- authentication_bypass, authorization_escalation, api_fuzzing

Respond with JSON:
{{
    "next_actions": [
        {{
            "test": "test_name",
            "target": "specific_endpoint_or_all",
            "priority": "critical|high|medium|low",
            "reason": "Why this test"
        }}
    ],
    "reasoning": "Strategic thinking",
    "confidence": 0.0-1.0,
    "estimated_time_minutes": 10,
    "exploitation_strategy": "Overall strategy"
}}

**Rules:**
- Suggest 2-5 high-impact tests
- Prioritize tests likely to find NEW vulnerabilities
- Consider technology-specific vulns
- Be strategic, not exhaustive"""

        return prompt

    def _parse_decision(self, decision_text: str) -> Dict[str, Any]:
        """Parse Claude's decision"""
        try:
            import re
            json_match = re.search(r'\{.*\}', decision_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return json.loads(decision_text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI decision: {e}")
            return {"next_actions": [], "reasoning": "Parse failed", "confidence": 0.0}

    def _vuln_to_dict(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Convert Vulnerability to dict"""
        return {
            "id": vuln.id,
            "title": vuln.title,
            "severity": vuln.severity.value,
            "category": vuln.category.value,
            "url": vuln.affected_url,
            "affected_url": vuln.affected_url,
            "parameter": vuln.affected_parameter,
            "affected_parameter": vuln.affected_parameter,
            "description": vuln.description,
            "poc": vuln.proof_of_concept,
            "cwe": vuln.cwe_id,
            "owasp": vuln.owasp_category,
        }

    def _scan_result_to_dict(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult to dict"""
        return {
            "scan_id": scan_result.scan_id,
            "target_url": scan_result.target_url,
            "mode": scan_result.mode.value,
            "status": scan_result.status,
            "start_time": scan_result.start_time.isoformat() if scan_result.start_time else None,
            "end_time": scan_result.end_time.isoformat() if scan_result.end_time else None,
            "duration": str(scan_result.end_time - scan_result.start_time) if scan_result.end_time and scan_result.start_time else "N/A",
            "vulnerabilities": [self._vuln_to_dict(v) for v in scan_result.vulnerabilities],
            "discovered_endpoints": scan_result.discovered_endpoints,
            "detected_technologies": [
                {"name": t.name, "version": t.version, "categories": t.categories}
                for t in scan_result.detected_technologies
            ],
        }
