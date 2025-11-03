"""
Autonomous Penetration Testing Agent
Uses Claude API to analyze results and make intelligent testing decisions
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

logger = logging.getLogger(__name__)


class AutonomousPentestAgent:
    """
    AI-powered autonomous pentesting agent that:
    - Analyzes scan results in real-time
    - Decides which tests to run next
    - Adapts strategy based on findings
    - Works autonomously while you sleep 😴
    """

    def __init__(self, claude_api_key: Optional[str] = None):
        """
        Initialize the autonomous agent

        Args:
            claude_api_key: Anthropic API key (if None, uses settings.ANTHROPIC_API_KEY)
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

        self.client = AsyncAnthropic(api_key=self.api_key)
        self.enabled = True
        self.memory: List[Dict[str, Any]] = []  # Agent's memory of decisions and findings
        self.max_iterations = 10  # Safety limit

        logger.info("🤖 Autonomous AI Agent initialized and ready!")

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
            # Build context from scan results
            context = self._build_analysis_context(scan_result)

            # Ask Claude to analyze and decide
            prompt = self._create_decision_prompt(context)

            logger.info("🧠 AI Agent analyzing scan results...")

            response = await self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=3000,
                temperature=0.7,
                messages=[{"role": "user", "content": prompt}]
            )

            # Parse Claude's decision
            decision_text = response.content[0].text
            decision = self._parse_decision(decision_text)

            # Store in memory
            self.memory.append({
                "timestamp": datetime.utcnow().isoformat(),
                "context": context,
                "decision": decision
            })

            logger.info(f"🎯 AI Agent decision: {len(decision.get('next_actions', []))} actions recommended")

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

        # Extract key findings from timeline
        recent_events = scan_result.timeline[-20:] if len(scan_result.timeline) > 20 else scan_result.timeline

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
            "recent_findings": [
                {
                    "phase": event.phase,
                    "message": event.message,
                    "timestamp": event.timestamp.isoformat()
                }
                for event in recent_events
            ],
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
                    "description": v.description[:200]  # Truncate
                }
                for v in critical_vulns[:5]  # Top 5 critical
            ]
        }

        return context

    def _create_decision_prompt(self, context: Dict[str, Any]) -> str:
        """Create the prompt for Claude to make decisions"""

        prompt = f"""You are an expert autonomous penetration testing AI agent. You analyze scan results in real-time and decide which tests to perform next to maximize vulnerability discovery.

# Current Scan Context

**Target:** {context['target_url']}
**Scan Mode:** {context['mode']}
**Current Status:** {context['status']}

## Statistics
- Total Vulnerabilities: {context['statistics']['total_vulnerabilities']}
  - Critical: {context['statistics']['critical']}
  - High: {context['statistics']['high']}
  - Medium: {context['statistics']['medium']}
- Endpoints Discovered: {context['statistics']['endpoints_discovered']}
- Technologies: {', '.join(context['statistics']['technologies'][:10])}

## Vulnerabilities Found by Category
{json.dumps(context['vulnerabilities_by_category'], indent=2)}

## Critical Vulnerabilities (Top 5)
{json.dumps(context['critical_vulnerabilities_details'], indent=2)}

## Recent Scan Events (Last 20)
{json.dumps(context['recent_findings'][-10:], indent=2)}

## Detected Technologies
{json.dumps(context['detected_technologies'][:5], indent=2)}

---

# Your Task

Based on the scan results above, decide what additional security tests should be performed to:
1. Maximize vulnerability discovery
2. Exploit discovered vulnerabilities deeper
3. Find related vulnerabilities based on patterns
4. Test technology-specific vulnerabilities

**Available Test Types:**
- jwt_deep_analysis: Deep JWT token analysis (algorithm confusion, weak secrets, claims manipulation)
- graphql_advanced: Advanced GraphQL testing (batching, nested queries, introspection)
- nosql_advanced: Advanced NoSQL injection (MongoDB operators, authentication bypass)
- api_fuzzing: Fuzzing API endpoints with malformed data
- session_management: Session fixation, timeout, concurrent sessions
- rate_limiting: Test rate limits and account enumeration
- business_logic: Test business logic flaws (race conditions, price manipulation)
- file_upload_advanced: Advanced file upload tests (path traversal, webshell upload)
- authentication_bypass: Try authentication bypass techniques
- authorization_escalation: Test for privilege escalation and IDOR patterns

Respond ONLY with valid JSON in this exact format:
{{
    "next_actions": [
        {{
            "test": "test_name",
            "target": "specific_endpoint_or_all",
            "priority": "critical|high|medium|low",
            "reason": "Why this test is important based on findings"
        }}
    ],
    "reasoning": "Your strategic thinking: why these tests, what patterns you noticed, what you're trying to discover",
    "confidence": 0.0-1.0,
    "estimated_time_minutes": 10,
    "exploitation_strategy": "Brief description of your overall strategy"
}}

**Important:**
- Prioritize tests that are likely to find NEW vulnerabilities
- If you found SQL injection, don't suggest more SQL tests unless you have a specific reason
- If you found JWT vulnerabilities, suggest deeper JWT exploitation
- If GraphQL was discovered, prioritize GraphQL-specific tests
- Consider technology-specific vulnerabilities (e.g., if Node.js detected, test for prototype pollution)
- Be strategic: suggest 2-5 high-impact tests, not everything
- If scan is already comprehensive with many findings, suggest focused exploitation rather than broad scanning

Think like a senior penetration tester making tactical decisions."""

        return prompt

    def _parse_decision(self, decision_text: str) -> Dict[str, Any]:
        """Parse Claude's decision from text response"""
        try:
            # Extract JSON from response (Claude might add explanation around it)
            import re

            # Try to find JSON block
            json_match = re.search(r'\{.*\}', decision_text, re.DOTALL)

            if json_match:
                decision_json = json.loads(json_match.group())
                return decision_json

            # Fallback: try to parse entire response
            return json.loads(decision_text)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI decision: {e}")
            logger.debug(f"Raw response: {decision_text}")

            # Return safe fallback
            return {
                "next_actions": [],
                "reasoning": "Failed to parse AI decision",
                "confidence": 0.0
            }

    async def autonomous_scan_loop(self, scan_result: ScanResult, executor_callback) -> ScanResult:
        """
        Run autonomous scan loop where AI decides and executes tests iteratively

        Args:
            scan_result: Initial scan result
            executor_callback: Async function to execute tests, signature: async def(action) -> new_findings

        Returns:
            Updated scan result with all findings
        """
        if not self.enabled:
            logger.warning("🤖 AI Agent disabled, skipping autonomous scan loop")
            return scan_result

        logger.info("🤖 Starting autonomous scan loop...")
        logger.info("💤 You can go to sleep now - the AI agent will work autonomously!")

        iteration = 0

        while iteration < self.max_iterations:
            iteration += 1
            logger.info(f"\n{'='*70}")
            logger.info(f"🤖 AI AGENT ITERATION {iteration}/{self.max_iterations}")
            logger.info(f"{'='*70}")

            # AI analyzes and decides
            decision = await self.analyze_and_decide(scan_result)

            # Check if AI recommends stopping
            if not decision.get('next_actions'):
                logger.info("🎯 AI Agent: No more recommended actions. Scan optimization complete!")
                logger.info(f"💡 Reasoning: {decision.get('reasoning')}")
                break

            # Log AI's reasoning
            logger.info(f"\n🧠 AI Agent Strategy:")
            logger.info(f"   {decision.get('reasoning')}")
            logger.info(f"   Confidence: {decision.get('confidence', 0):.0%}")
            logger.info(f"   Estimated time: {decision.get('estimated_time_minutes', 0)} minutes")

            # Execute each recommended action
            for idx, action in enumerate(decision['next_actions'], 1):
                logger.info(f"\n🎯 Executing action {idx}/{len(decision['next_actions'])}: {action['test']}")
                logger.info(f"   Target: {action['target']}")
                logger.info(f"   Priority: {action['priority']}")
                logger.info(f"   Reason: {action['reason']}")

                try:
                    # Execute the test via callback
                    new_findings = await executor_callback(action)

                    # Update scan result with new findings
                    if new_findings:
                        scan_result.vulnerabilities.extend(new_findings)
                        logger.info(f"✅ Found {len(new_findings)} new vulnerabilities")
                    else:
                        logger.info(f"ℹ️  No new vulnerabilities found")

                except Exception as e:
                    logger.error(f"❌ Failed to execute action {action['test']}: {e}")

            # Small delay between iterations
            await asyncio.sleep(2)

        logger.info(f"\n{'='*70}")
        logger.info(f"🎉 AUTONOMOUS SCAN COMPLETE!")
        logger.info(f"{'='*70}")
        logger.info(f"📊 Total vulnerabilities found: {len(scan_result.vulnerabilities)}")
        logger.info(f"🔄 AI iterations performed: {iteration}")

        return scan_result

    def get_scan_summary(self, scan_result: ScanResult) -> str:
        """
        Generate a human-readable summary of scan results for notifications

        Args:
            scan_result: Completed scan result

        Returns:
            Formatted summary string
        """
        critical = len([v for v in scan_result.vulnerabilities if v.severity == SeverityLevel.CRITICAL])
        high = len([v for v in scan_result.vulnerabilities if v.severity == SeverityLevel.HIGH])
        medium = len([v for v in scan_result.vulnerabilities if v.severity == SeverityLevel.MEDIUM])
        low = len([v for v in scan_result.vulnerabilities if v.severity == SeverityLevel.LOW])

        summary = f"""
🎯 Penetration Test Complete!

Target: {scan_result.target_url}
Scan ID: {scan_result.scan_id}
Duration: {scan_result.end_time - scan_result.start_time if scan_result.end_time else 'In progress'}

📊 Vulnerabilities Found:
   🔴 Critical: {critical}
   🟠 High: {high}
   🟡 Medium: {medium}
   🔵 Low: {low}

   Total: {len(scan_result.vulnerabilities)}

🔍 Endpoints Discovered: {len(scan_result.discovered_endpoints)}
🛠️  Technologies Detected: {len(scan_result.detected_technologies)}

"""

        # Add top 3 critical vulnerabilities
        critical_vulns = [v for v in scan_result.vulnerabilities if v.severity == SeverityLevel.CRITICAL]
        if critical_vulns:
            summary += "⚠️  Top Critical Vulnerabilities:\n"
            for idx, vuln in enumerate(critical_vulns[:3], 1):
                summary += f"   {idx}. {vuln.title}\n"
                summary += f"      URL: {vuln.affected_url}\n"

        return summary.strip()
