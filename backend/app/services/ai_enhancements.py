"""
AI Enhancement Service - Intelligent Security Testing

Integrates orphaned AI modules to enhance scanning capabilities:
- DecisionEngine: Smart test routing
- ExploitationChainBuilder: Multi-vuln chain attacks
- AIPayloadGenerator: Context-aware payload generation
- AIPoweredReportGenerator: Professional reports
- AgentMemory: Learning from successful patterns

All enhancements are OPTIONAL - gracefully degrades if unavailable.
"""

import logging
import os
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AIEnhancementResult:
    """Result from AI enhancement"""
    success: bool
    data: Any
    source: str  # Which AI module produced this
    fallback_used: bool = False
    error: Optional[str] = None


class AIEnhancementService:
    """
    Unified AI Enhancement Layer.

    Wraps all AI agent modules and provides graceful degradation.
    Works with or without API keys - uses fallbacks when AI unavailable.
    """

    def __init__(self):
        self._initialized = False
        self._decision_engine = None
        self._chain_builder = None
        self._payload_generator = None
        self._report_generator = None
        self._memory = None
        self._available_modules = []

    async def initialize(self):
        """Initialize all available AI modules"""
        if self._initialized:
            return

        # Try to initialize each module
        await self._init_decision_engine()
        await self._init_memory()
        await self._init_chain_builder()
        await self._init_payload_generator()
        await self._init_report_generator()

        self._initialized = True
        logger.info(f"AI Enhancements initialized: {self._available_modules}")

    async def _init_decision_engine(self):
        """Initialize DecisionEngine"""
        try:
            from app.ai_agent.decision_engine import DecisionEngine
            self._decision_engine = DecisionEngine()
            self._available_modules.append("decision_engine")
        except Exception as e:
            logger.debug(f"DecisionEngine not available: {e}")

    async def _init_memory(self):
        """Initialize AgentMemory"""
        try:
            from app.ai_agent.memory_system import AgentMemory
            self._memory = AgentMemory()
            self._available_modules.append("memory")
        except Exception as e:
            logger.debug(f"AgentMemory not available: {e}")

    async def _init_chain_builder(self):
        """Initialize ExploitationChainBuilder"""
        try:
            from app.ai_agent.exploitation_chains import ExploitationChainBuilder
            self._chain_builder = ExploitationChainBuilder()
            self._available_modules.append("chain_builder")
        except Exception as e:
            logger.debug(f"ExploitationChainBuilder not available: {e}")

    async def _init_payload_generator(self):
        """Initialize AIPayloadGenerator if API key available"""
        try:
            api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("GROQ_API_KEY")
            if api_key:
                from app.ai_agent.payload_generator import AIPayloadGenerator
                self._payload_generator = AIPayloadGenerator(api_key, self._memory)
                self._available_modules.append("payload_generator")
        except Exception as e:
            logger.debug(f"AIPayloadGenerator not available: {e}")

    async def _init_report_generator(self):
        """Initialize AIPoweredReportGenerator if API key available"""
        try:
            api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("GROQ_API_KEY")
            if api_key:
                from app.ai_agent.report_generator import AIPoweredReportGenerator
                self._report_generator = AIPoweredReportGenerator(api_key)
                self._available_modules.append("report_generator")
        except Exception as e:
            logger.debug(f"AIPoweredReportGenerator not available: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get AI enhancement status"""
        return {
            "initialized": self._initialized,
            "available_modules": self._available_modules,
            "decision_engine": self._decision_engine is not None,
            "memory": self._memory is not None,
            "chain_builder": self._chain_builder is not None,
            "payload_generator": self._payload_generator is not None,
            "report_generator": self._report_generator is not None
        }

    # ==================== DECISION ENGINE ====================

    def get_available_tests(self) -> List[Dict[str, str]]:
        """Get all available test types from DecisionEngine"""
        if self._decision_engine:
            return self._decision_engine.get_available_tests()
        # Fallback: return basic test list
        return [
            {"name": "sql_injection", "description": "SQL Injection testing"},
            {"name": "xss", "description": "Cross-Site Scripting"},
            {"name": "lfi", "description": "Local File Inclusion"},
            {"name": "ssrf", "description": "Server-Side Request Forgery"},
            {"name": "rce", "description": "Remote Code Execution"},
        ]

    def parse_action(self, action_dict: Dict, endpoints: List[str]) -> AIEnhancementResult:
        """Parse AI-recommended action into executable test"""
        if self._decision_engine:
            try:
                action = self._decision_engine.parse_action(action_dict, endpoints)
                return AIEnhancementResult(
                    success=True,
                    data=action,
                    source="decision_engine"
                )
            except Exception as e:
                logger.warning(f"DecisionEngine error: {e}")

        return AIEnhancementResult(
            success=False,
            data=None,
            source="decision_engine",
            fallback_used=True,
            error="DecisionEngine not available"
        )

    # ==================== MEMORY SYSTEM ====================

    def start_session(self, session_id: str, target: str):
        """Start memory session for learning"""
        if self._memory:
            try:
                self._memory.start_session(session_id, target)
            except Exception as e:
                logger.debug(f"Memory start_session error: {e}")

    def remember_finding(self, vulnerability: Dict[str, Any]):
        """Remember a finding for pattern learning"""
        if self._memory:
            try:
                self._memory.remember_finding(vulnerability)
            except Exception as e:
                logger.debug(f"Memory remember_finding error: {e}")

    def remember_exploit_attempt(self, test_type: str, target: str, payload: str,
                                  success: bool, result: Dict = None):
        """Remember exploit attempt for learning"""
        if self._memory:
            try:
                self._memory.remember_exploit_attempt(test_type, target, payload, success, result)
            except Exception as e:
                logger.debug(f"Memory remember_exploit error: {e}")

    def get_successful_patterns(self, test_type: str) -> List[Dict[str, Any]]:
        """Get previously successful patterns for a test type"""
        if self._memory:
            try:
                return self._memory.get_successful_patterns(test_type)
            except Exception as e:
                logger.debug(f"Memory get_patterns error: {e}")
        return []

    def get_learning_insights(self) -> Dict[str, Any]:
        """Get insights from learning system"""
        if self._memory:
            try:
                return self._memory.get_learning_insights()
            except Exception as e:
                logger.debug(f"Memory insights error: {e}")
        return {"patterns_learned": 0, "recommendations": []}

    def end_session(self) -> Optional[Dict[str, Any]]:
        """End session and get report"""
        if self._memory:
            try:
                self._memory.end_session()
                return self._memory.export_session_report()
            except Exception as e:
                logger.debug(f"Memory end_session error: {e}")
        return None

    # ==================== EXPLOITATION CHAINS ====================

    async def find_exploitation_chains(self, vulnerabilities: List[Dict],
                                        goal: str = None) -> AIEnhancementResult:
        """Find multi-vulnerability exploitation chains"""
        if self._chain_builder and vulnerabilities:
            try:
                chains = await self._chain_builder.find_exploitation_chains(
                    vulnerabilities,
                    goal=goal
                )
                return AIEnhancementResult(
                    success=True,
                    data=chains,
                    source="chain_builder"
                )
            except Exception as e:
                logger.warning(f"ChainBuilder error: {e}")

        # Fallback: basic chain detection
        chains = self._fallback_chain_detection(vulnerabilities)
        return AIEnhancementResult(
            success=len(chains) > 0,
            data=chains,
            source="chain_builder",
            fallback_used=True
        )

    def _fallback_chain_detection(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Rule-based fallback for chain detection"""
        chains = []
        vuln_types = {v.get('vuln_type', '').lower() for v in vulnerabilities}

        # Known chain patterns
        chain_patterns = [
            {
                "requires": ["ssrf", "rce"],
                "name": "SSRF to RCE",
                "description": "Use SSRF to access internal services leading to RCE"
            },
            {
                "requires": ["lfi", "rce"],
                "name": "LFI to RCE",
                "description": "LFI log poisoning to achieve RCE"
            },
            {
                "requires": ["sql", "lfi"],
                "name": "SQLi to File Read",
                "description": "SQL injection to read files via LOAD_FILE"
            },
            {
                "requires": ["xxe", "ssrf"],
                "name": "XXE to SSRF",
                "description": "XXE to access internal services"
            },
            {
                "requires": ["xss", "csrf"],
                "name": "XSS + CSRF",
                "description": "XSS to bypass CSRF protection"
            },
        ]

        for pattern in chain_patterns:
            if all(any(req in vt for vt in vuln_types) for req in pattern["requires"]):
                chains.append({
                    "name": pattern["name"],
                    "description": pattern["description"],
                    "vulnerabilities_used": pattern["requires"],
                    "complexity": "medium",
                    "fallback": True
                })

        return chains

    def build_execution_plan(self, chain: Dict) -> Dict[str, Any]:
        """Build detailed execution plan for a chain"""
        if self._chain_builder:
            try:
                return self._chain_builder.build_execution_plan(chain)
            except Exception as e:
                logger.debug(f"Execution plan error: {e}")

        # Fallback plan
        return {
            "chain": chain.get("name"),
            "steps": [
                {"step": 1, "action": "Identify entry point", "status": "pending"},
                {"step": 2, "action": "Exploit first vulnerability", "status": "pending"},
                {"step": 3, "action": "Chain to second vulnerability", "status": "pending"},
                {"step": 4, "action": "Achieve final goal", "status": "pending"},
            ],
            "fallback": True
        }

    # ==================== PAYLOAD GENERATION ====================

    async def generate_payloads(self, vuln_type: str, target_url: str,
                                 context: Dict = None, count: int = 5) -> AIEnhancementResult:
        """Generate intelligent payloads for a vulnerability type"""
        # Try AI generation
        if self._payload_generator:
            try:
                # Get successful patterns from memory
                patterns = self.get_successful_patterns(vuln_type)
                ctx = context or {}
                ctx["successful_patterns"] = patterns

                payloads = await self._payload_generator.generate_payloads(
                    vuln_type, target_url, ctx, count
                )
                return AIEnhancementResult(
                    success=True,
                    data=payloads,
                    source="payload_generator"
                )
            except Exception as e:
                logger.warning(f"PayloadGenerator error: {e}")

        # Fallback: return curated payloads
        payloads = self._get_fallback_payloads(vuln_type, count)
        return AIEnhancementResult(
            success=True,
            data=payloads,
            source="payload_generator",
            fallback_used=True
        )

    def _get_fallback_payloads(self, vuln_type: str, count: int) -> List[Dict]:
        """Get fallback payloads from curated lists"""
        payloads_db = {
            "sql": [
                {"payload": "' OR '1'='1", "type": "boolean", "bypass": "basic"},
                {"payload": "' UNION SELECT NULL--", "type": "union", "bypass": "basic"},
                {"payload": "1' AND SLEEP(5)--", "type": "time-based", "bypass": "basic"},
                {"payload": "admin'/*", "type": "comment", "bypass": "waf"},
                {"payload": "1'||'1'='1", "type": "boolean", "bypass": "oracle"},
            ],
            "xss": [
                {"payload": "<script>alert(1)</script>", "type": "basic", "context": "html"},
                {"payload": "<img src=x onerror=alert(1)>", "type": "event", "context": "html"},
                {"payload": "javascript:alert(1)", "type": "uri", "context": "href"},
                {"payload": "'-alert(1)-'", "type": "template", "context": "js"},
                {"payload": "<svg/onload=alert(1)>", "type": "svg", "bypass": "filter"},
            ],
            "lfi": [
                {"payload": "../../../etc/passwd", "type": "basic", "os": "linux"},
                {"payload": "....//....//etc/passwd", "type": "bypass", "os": "linux"},
                {"payload": "php://filter/convert.base64-encode/resource=index", "type": "wrapper", "os": "any"},
                {"payload": "/proc/self/environ", "type": "proc", "os": "linux"},
                {"payload": "..%252f..%252fetc/passwd", "type": "double-encode", "bypass": "waf"},
            ],
            "ssrf": [
                {"payload": "http://127.0.0.1", "type": "localhost", "target": "internal"},
                {"payload": "http://169.254.169.254/latest/meta-data/", "type": "cloud", "target": "aws"},
                {"payload": "gopher://127.0.0.1:6379/_", "type": "gopher", "target": "redis"},
                {"payload": "file:///etc/passwd", "type": "file", "target": "local"},
                {"payload": "http://[::1]", "type": "ipv6", "bypass": "filter"},
            ],
            "rce": [
                {"payload": ";id", "type": "command", "os": "linux"},
                {"payload": "|whoami", "type": "pipe", "os": "any"},
                {"payload": "`id`", "type": "backtick", "os": "linux"},
                {"payload": "$(id)", "type": "subshell", "os": "linux"},
                {"payload": "&dir", "type": "command", "os": "windows"},
            ],
        }

        vuln_lower = vuln_type.lower()
        for key, payloads in payloads_db.items():
            if key in vuln_lower:
                return payloads[:count]

        return [{"payload": "test", "type": "generic", "note": "No specific payloads"}]

    async def generate_evasion_variants(self, payload: str,
                                         evasion_types: List[str] = None) -> AIEnhancementResult:
        """Generate WAF evasion variants of a payload"""
        if self._payload_generator:
            try:
                variants = await self._payload_generator.generate_evasion_variants(
                    payload, evasion_types or ["encoding", "case", "comments"]
                )
                return AIEnhancementResult(success=True, data=variants, source="payload_generator")
            except Exception as e:
                logger.debug(f"Evasion generation error: {e}")

        # Fallback evasion
        variants = self._generate_basic_evasions(payload)
        return AIEnhancementResult(
            success=True,
            data=variants,
            source="payload_generator",
            fallback_used=True
        )

    def _generate_basic_evasions(self, payload: str) -> List[Dict]:
        """Generate basic evasion variants"""
        import urllib.parse
        variants = [
            {"payload": payload, "technique": "original"},
            {"payload": urllib.parse.quote(payload), "technique": "url_encode"},
            {"payload": urllib.parse.quote(urllib.parse.quote(payload)), "technique": "double_encode"},
            {"payload": payload.replace(" ", "/**/"), "technique": "comment_space"},
            {"payload": payload.upper(), "technique": "uppercase"},
            {"payload": payload.replace("'", "''"), "technique": "quote_escape"},
        ]
        return variants

    # ==================== REPORT GENERATION ====================

    async def generate_executive_summary(self, scan_result: Dict) -> AIEnhancementResult:
        """Generate executive summary of scan results"""
        if self._report_generator:
            try:
                memory_data = self._memory.export_session_report() if self._memory else None
                summary = await self._report_generator.generate_executive_summary(
                    scan_result, memory_data
                )
                return AIEnhancementResult(success=True, data=summary, source="report_generator")
            except Exception as e:
                logger.debug(f"Executive summary error: {e}")

        # Fallback summary
        summary = self._generate_fallback_summary(scan_result)
        return AIEnhancementResult(
            success=True,
            data=summary,
            source="report_generator",
            fallback_used=True
        )

    def _generate_fallback_summary(self, scan_result: Dict) -> str:
        """Generate fallback executive summary"""
        findings = scan_result.get("findings", [])
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")

        target = scan_result.get("target_url", "target")
        total = len(findings)

        if critical > 0:
            risk = "CRITICAL"
            action = "Immediate remediation required."
        elif high > 0:
            risk = "HIGH"
            action = "Urgent remediation recommended."
        elif medium > 0:
            risk = "MEDIUM"
            action = "Remediation should be planned."
        else:
            risk = "LOW"
            action = "Continue monitoring."

        return f"""## Executive Summary

**Target:** {target}
**Risk Level:** {risk}
**Total Findings:** {total}

### Severity Distribution
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low/Info: {total - critical - high - medium}

### Recommendation
{action}

### Key Findings
{self._format_key_findings(findings[:5])}
"""

    def _format_key_findings(self, findings: List[Dict]) -> str:
        """Format key findings for report"""
        if not findings:
            return "No significant findings."

        lines = []
        for f in findings:
            lines.append(f"- **{f.get('vuln_type', 'Unknown')}** ({f.get('severity', 'unknown')}): {f.get('url', 'N/A')[:50]}")
        return "\n".join(lines)

    async def generate_remediation_plan(self, vulnerabilities: List[Dict],
                                         timeline: str = "30_days") -> AIEnhancementResult:
        """Generate remediation plan"""
        if self._report_generator:
            try:
                plan = await self._report_generator.generate_remediation_plan(
                    vulnerabilities, timeline
                )
                return AIEnhancementResult(success=True, data=plan, source="report_generator")
            except Exception as e:
                logger.debug(f"Remediation plan error: {e}")

        # Fallback plan
        plan = self._generate_fallback_remediation(vulnerabilities)
        return AIEnhancementResult(
            success=True,
            data=plan,
            source="report_generator",
            fallback_used=True
        )

    def _generate_fallback_remediation(self, vulnerabilities: List[Dict]) -> str:
        """Generate fallback remediation plan"""
        remediation_db = {
            "sql": "Use parameterized queries/prepared statements",
            "xss": "Encode output, implement CSP headers",
            "lfi": "Whitelist allowed files, disable allow_url_include",
            "rce": "Never pass user input to system commands",
            "ssrf": "Whitelist allowed URLs, use allowlists",
            "xxe": "Disable external entities in XML parser",
            "ssti": "Use sandboxed template engines",
            "csrf": "Implement CSRF tokens on all forms",
        }

        lines = ["## Remediation Plan\n"]
        seen_types = set()

        for v in vulnerabilities:
            vtype = v.get("vuln_type", "").lower()
            for key, fix in remediation_db.items():
                if key in vtype and key not in seen_types:
                    lines.append(f"### {vtype.upper()}")
                    lines.append(f"**Fix:** {fix}\n")
                    seen_types.add(key)
                    break

        return "\n".join(lines)


# Global instance
_ai_service: Optional[AIEnhancementService] = None


def get_ai_enhancements() -> AIEnhancementService:
    """Get or create AI enhancement service"""
    global _ai_service
    if _ai_service is None:
        _ai_service = AIEnhancementService()
    return _ai_service


async def init_ai_enhancements() -> AIEnhancementService:
    """Initialize and return AI enhancement service"""
    service = get_ai_enhancements()
    await service.initialize()
    return service
