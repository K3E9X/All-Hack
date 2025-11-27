"""
LLM-Powered Vulnerability Analyst

Uses local LLM (Ollama) to provide intelligent analysis of security findings.
"""
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
import json

from app.models import Vulnerability, ScanResult
from app.intelligence.ollama_client import get_ollama_client, OllamaClient
from app.intelligence.prompts.vulnerability_analysis import (
    SYSTEM_PROMPT,
    format_vulnerability_for_analysis,
    format_vulnerabilities_for_summary,
    format_exploitation_guidance,
    format_code_remediation,
    ATTACK_CHAIN_PLANNING_PROMPT
)

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityAnalysis:
    """AI-generated vulnerability analysis"""
    vulnerability_id: str
    root_cause: str
    exploitation_complexity: str
    business_impact: str
    remediation_code: str
    next_steps: List[str]
    full_analysis: str  # Complete markdown analysis

@dataclass
class ScanSummary:
    """AI-generated scan summary"""
    critical_attack_chains: List[Dict[str, Any]]
    priority_ranking: List[Dict[str, str]]
    common_patterns: List[str]
    quick_wins: List[str]
    executive_summary: str
    full_summary: str  # Complete markdown summary

class LLMVulnerabilityAnalyst:
    """
    AI-powered vulnerability analyst using Ollama

    Features:
    - Deep vulnerability analysis
    - Exploitation guidance
    - Framework-specific remediation
    - Attack chain identification
    - Strategic scan summaries

    Cost: $0 (runs locally with Ollama)
    Privacy: 100% (no data leaves your machine)
    """

    def __init__(self, ollama_client: Optional[OllamaClient] = None):
        self.ollama = ollama_client or get_ollama_client()
        self.available = False

    async def initialize(self) -> bool:
        """
        Check if Ollama is available

        Returns:
            True if ready to use, False otherwise
        """
        self.available = await self.ollama.check_available()
        if self.available:
            logger.info("✅ LLM Analyst initialized with Ollama")
        else:
            logger.warning("⚠️  LLM Analyst unavailable - Ollama not running")
            logger.info("Start Ollama: ollama serve")
            logger.info("Pull model: ollama pull llama3.2")
        return self.available

    async def analyze_vulnerability(
        self,
        vulnerability: Vulnerability,
        tech_stack: Optional[List[Dict]] = None
    ) -> Optional[VulnerabilityAnalysis]:
        """
        Analyze a single vulnerability with AI

        Args:
            vulnerability: Vulnerability to analyze
            tech_stack: Detected technology stack

        Returns:
            VulnerabilityAnalysis with AI insights
        """
        if not self.available:
            logger.warning("LLM Analyst not available, skipping analysis")
            return None

        try:
            logger.info(f"🧠 Analyzing vulnerability: {vulnerability.title}")

            # Convert vulnerability to dict
            vuln_dict = vulnerability.dict() if hasattr(vulnerability, 'dict') else asdict(vulnerability)

            # Format prompt
            prompt = format_vulnerability_for_analysis(vuln_dict, tech_stack)

            # Get AI analysis
            analysis_text = await self.ollama.generate(
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT
            )

            logger.info(f"✅ Analysis complete for: {vulnerability.title}")

            # Parse analysis (basic extraction)
            analysis = self._parse_analysis(vulnerability.id, analysis_text)
            return analysis

        except Exception as e:
            logger.error(f"❌ Failed to analyze vulnerability {vulnerability.id}: {e}")
            return None

    def _parse_analysis(self, vuln_id: str, analysis_text: str) -> VulnerabilityAnalysis:
        """
        Parse LLM output into structured analysis

        Note: This is a simple parser. For production, consider using
        structured output or JSON mode.
        """
        # Extract sections (simple heuristic)
        root_cause = self._extract_section(analysis_text, "Root Cause")
        exploitation = self._extract_section(analysis_text, "Exploitation Complexity")
        impact = self._extract_section(analysis_text, "Business Impact")
        remediation = self._extract_section(analysis_text, "Remediation")
        next_steps = self._extract_list_section(analysis_text, "Next Steps")

        return VulnerabilityAnalysis(
            vulnerability_id=vuln_id,
            root_cause=root_cause or "Analysis not available",
            exploitation_complexity=exploitation or "Unknown",
            business_impact=impact or "Not assessed",
            remediation_code=remediation or "See general remediation guidance",
            next_steps=next_steps or ["Manual review recommended"],
            full_analysis=analysis_text
        )

    def _extract_section(self, text: str, section_name: str) -> Optional[str]:
        """Extract a section from markdown text"""
        import re

        # Try to find section header
        patterns = [
            f"##? {section_name}[:\n](.+?)(?=##|$)",  # Markdown header
            f"\*\*{section_name}\*\*[:\n](.+?)(?=\*\*|$)",  # Bold header
            f"{section_name}[:\n](.+?)(?=\n\n|$)",  # Plain header
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()

        return None

    def _extract_list_section(self, text: str, section_name: str) -> List[str]:
        """Extract a bulleted list from text"""
        import re

        section = self._extract_section(text, section_name)
        if not section:
            return []

        # Find bullet points
        items = re.findall(r'[-*•]\s*(.+)', section)
        # Also try numbered lists
        if not items:
            items = re.findall(r'\d+\.\s*(.+)', section)

        return [item.strip() for item in items]

    async def summarize_scan(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> Optional[ScanSummary]:
        """
        Generate strategic summary of all findings

        Args:
            vulnerabilities: All vulnerabilities found

        Returns:
            ScanSummary with strategic insights
        """
        if not self.available:
            return None

        if not vulnerabilities:
            logger.info("No vulnerabilities to summarize")
            return None

        try:
            logger.info(f"🧠 Generating strategic summary for {len(vulnerabilities)} vulnerabilities")

            # Convert to dicts
            vuln_dicts = [
                v.dict() if hasattr(v, 'dict') else asdict(v)
                for v in vulnerabilities
            ]

            # Format prompt
            prompt = format_vulnerabilities_for_summary(vuln_dicts)

            # Get AI summary
            summary_text = await self.ollama.generate(
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT
            )

            logger.info("✅ Strategic summary generated")

            # Parse summary
            summary = self._parse_summary(summary_text)
            return summary

        except Exception as e:
            logger.error(f"❌ Failed to generate summary: {e}")
            return None

    def _parse_summary(self, summary_text: str) -> ScanSummary:
        """Parse scan summary from LLM output"""

        attack_chains = self._extract_list_section(summary_text, "Critical Attack Chains")
        priority = self._extract_list_section(summary_text, "Priority Ranking")
        patterns = self._extract_list_section(summary_text, "Common Patterns")
        quick_wins = self._extract_list_section(summary_text, "Quick Wins")
        executive = self._extract_section(summary_text, "Executive Summary")

        return ScanSummary(
            critical_attack_chains=[{"description": chain} for chain in attack_chains],
            priority_ranking=[{"item": p} for p in priority],
            common_patterns=patterns,
            quick_wins=quick_wins,
            executive_summary=executive or "No executive summary available",
            full_summary=summary_text
        )

    async def generate_exploitation_guide(
        self,
        vulnerability: Vulnerability,
        user_question: str
    ) -> Optional[str]:
        """
        Generate exploitation guidance for a vulnerability

        Args:
            vulnerability: Vulnerability to exploit
            user_question: User's specific question

        Returns:
            Exploitation guide (markdown)
        """
        if not self.available:
            return None

        try:
            vuln_dict = vulnerability.dict() if hasattr(vulnerability, 'dict') else asdict(vulnerability)
            prompt = format_exploitation_guidance(vuln_dict, user_question)

            guide = await self.ollama.generate(
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT
            )

            return guide

        except Exception as e:
            logger.error(f"❌ Failed to generate exploitation guide: {e}")
            return None

    async def generate_remediation_code(
        self,
        vulnerability: Vulnerability,
        tech_stack: Optional[List[Dict]] = None
    ) -> Optional[str]:
        """
        Generate framework-specific remediation code

        Args:
            vulnerability: Vulnerability to fix
            tech_stack: Detected technology stack

        Returns:
            Code fix with git diff format
        """
        if not self.available:
            return None

        try:
            vuln_dict = vulnerability.dict() if hasattr(vulnerability, 'dict') else asdict(vulnerability)
            prompt = format_code_remediation(vuln_dict, tech_stack)

            code_fix = await self.ollama.generate(
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT
            )

            return code_fix

        except Exception as e:
            logger.error(f"❌ Failed to generate remediation code: {e}")
            return None

    async def identify_attack_chains(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Identify potential attack chains from vulnerabilities

        Args:
            vulnerabilities: All vulnerabilities

        Returns:
            List of attack chains with steps
        """
        if not self.available or not vulnerabilities:
            return None

        try:
            logger.info("🧠 Identifying attack chains...")

            # Convert to JSON
            vuln_dicts = [
                v.dict() if hasattr(v, 'dict') else asdict(v)
                for v in vulnerabilities
            ]
            vulns_json = json.dumps(vuln_dicts, indent=2)

            prompt = ATTACK_CHAIN_PLANNING_PROMPT.format(
                vulnerabilities_json=vulns_json
            )

            chains_text = await self.ollama.generate(
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT
            )

            logger.info("✅ Attack chains identified")

            # Parse chains (simple extraction)
            # For production, use structured output
            return [{"description": chains_text}]

        except Exception as e:
            logger.error(f"❌ Failed to identify attack chains: {e}")
            return None


# Singleton instance
_llm_analyst: Optional[LLMVulnerabilityAnalyst] = None

async def get_llm_analyst() -> LLMVulnerabilityAnalyst:
    """Get or create LLM analyst singleton"""
    global _llm_analyst
    if _llm_analyst is None:
        _llm_analyst = LLMVulnerabilityAnalyst()
        await _llm_analyst.initialize()
    return _llm_analyst
