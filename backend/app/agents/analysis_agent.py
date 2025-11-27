"""
Analysis Agent

Vulnerability correlation and impact analysis.
"""
import logging
from typing import Dict, Any, List, Optional

from app.agents.base_agent import BaseAgent, AgentCapability, AgentMessage
from app.intelligence import get_llm_analyst

logger = logging.getLogger(__name__)

class AnalysisAgent(BaseAgent):
    """
    Analysis Agent - Deep Analysis & Correlation

    Responsibilities:
    - Correlate vulnerabilities across different endpoints
    - Identify attack chains and escalation paths
    - Assess business impact
    - Prioritize remediation
    - Generate risk scores
    """

    def __init__(self):
        super().__init__(
            agent_id="analysis",
            capabilities=[AgentCapability.ANALYSIS]
        )

    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute analysis task"""
        task_type = task.get("type")

        if task_type == "correlate_vulnerabilities":
            return await self._correlate_vulnerabilities(task)
        elif task_type == "identify_attack_chains":
            return await self._identify_attack_chains(task)
        elif task_type == "assess_impact":
            return await self._assess_impact(task)
        elif task_type == "prioritize_remediation":
            return await self._prioritize_remediation(task)
        else:
            return {"error": f"Unknown task type: {task_type}"}

    async def _correlate_vulnerabilities(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate vulnerabilities to find patterns

        Looks for:
        - Same vulnerability type across endpoints
        - Related vulnerabilities (SQLi + file read = RCE potential)
        - Common root causes
        - Framework-specific patterns
        """
        vulnerabilities = task.get("vulnerabilities", [])

        self.log_action(f"Correlating {len(vulnerabilities)} vulnerabilities")

        # Use LLM analyst for correlation
        analyst = await get_llm_analyst()
        if analyst.available:
            correlations = await analyst.identify_attack_chains(vulnerabilities)

            return {
                "total_vulnerabilities": len(vulnerabilities),
                "correlations": correlations,
                "ai_analysis": True
            }

        return {"error": "LLM analyst not available"}

    async def _identify_attack_chains(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Identify multi-step attack paths"""
        vulnerabilities = task.get("vulnerabilities", [])

        self.log_action(f"Identifying attack chains")

        analyst = await get_llm_analyst()
        if analyst.available:
            chains = await analyst.identify_attack_chains(vulnerabilities)

            return {
                "attack_chains": chains,
                "potential_impact": "high" if chains else "medium"
            }

        return {"error": "LLM not available"}

    async def _assess_impact(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess business impact of findings

        Considers:
        - Data sensitivity
        - User impact
        - Compliance requirements
        - Reputation risk
        - Financial impact
        """
        vulnerabilities = task.get("vulnerabilities", [])

        self.log_action(f"Assessing business impact")

        analyst = await get_llm_analyst()
        impact_scores = []

        for vuln in vulnerabilities:
            if analyst.available:
                analysis = await analyst.analyze_vulnerability(vuln)
                if analysis:
                    impact_scores.append({
                        "vulnerability": vuln.title,
                        "business_impact": analysis.business_impact,
                        "severity": vuln.severity
                    })

        return {
            "total_analyzed": len(impact_scores),
            "impact_assessments": impact_scores
        }

    async def _prioritize_remediation(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prioritize remediation efforts

        Factors:
        - Severity
        - Exploitability
        - Business impact
        - Attack chain potential
        - Fix complexity
        """
        vulnerabilities = task.get("vulnerabilities", [])

        self.log_action(f"Prioritizing remediation")

        # TODO: Implement smart prioritization algorithm
        prioritized = sorted(
            vulnerabilities,
            key=lambda v: (v.get("severity", "low"), v.get("exploitability", 0)),
            reverse=True
        )

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "remediation_priority": prioritized[:10],  # Top 10
            "quick_wins": [v for v in prioritized if v.get("fix_complexity") == "low"]
        }

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process messages from orchestrator"""
        message_type = message.message_type

        if message_type == "start_analysis":
            scan_id = message.content.get("scan_id")
            findings = message.content.get("previous_findings", [])

            self.log_action(f"Starting analysis for scan {scan_id}")

            # Analyze findings
            await self._correlate_vulnerabilities({"vulnerabilities": findings})
            await self._identify_attack_chains({"vulnerabilities": findings})

            return self.send_message(
                receiver="orchestrator",
                message_type="phase_complete",
                content={
                    "scan_id": scan_id,
                    "phase": "analysis",
                    "findings_analyzed": len(findings)
                },
                priority=4
            )

        return None
