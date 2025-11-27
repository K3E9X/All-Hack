"""
Reporting Agent

Executive summary and report generation.
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.agents.base_agent import BaseAgent, AgentCapability, AgentMessage
from app.intelligence import get_llm_analyst

logger = logging.getLogger(__name__)

class ReportingAgent(BaseAgent):
    """
    Reporting Agent - Report Generation

    Responsibilities:
    - Generate executive summaries
    - Create technical reports
    - Produce compliance reports (PCI-DSS, OWASP, etc.)
    - Generate remediation roadmaps
    - Export in multiple formats (PDF, HTML, JSON, Markdown)
    """

    def __init__(self):
        super().__init__(
            agent_id="reporting",
            capabilities=[AgentCapability.REPORTING]
        )

    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute reporting task"""
        task_type = task.get("type")

        if task_type == "generate_executive_summary":
            return await self._generate_executive_summary(task)
        elif task_type == "generate_technical_report":
            return await self._generate_technical_report(task)
        elif task_type == "generate_compliance_report":
            return await self._generate_compliance_report(task)
        elif task_type == "generate_remediation_roadmap":
            return await self._generate_remediation_roadmap(task)
        else:
            return {"error": f"Unknown task type: {task_type}"}

    async def _generate_executive_summary(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate executive summary for C-level

        Includes:
        - Overall risk score
        - Critical findings count
        - Business impact summary
        - Recommended actions
        - Timeline for remediation
        """
        scan_result = task.get("scan_result")
        vulnerabilities = scan_result.get("vulnerabilities", [])

        self.log_action("Generating executive summary")

        analyst = await get_llm_analyst()
        if analyst.available:
            summary = await analyst.summarize_scan(vulnerabilities)

            executive_summary = {
                "generated_at": datetime.now().isoformat(),
                "scan_id": scan_result.get("scan_id"),
                "target": scan_result.get("target_url"),
                "overall_risk": summary.overall_risk_level if summary else "Unknown",
                "critical_findings": summary.critical_count if summary else 0,
                "high_findings": summary.high_count if summary else 0,
                "business_impact": summary.summary if summary else "Analysis unavailable",
                "recommended_actions": summary.key_recommendations if summary else [],
                "remediation_timeline": "30-60 days"
            }

            return {
                "report_type": "executive_summary",
                "summary": executive_summary,
                "format": "json"
            }

        return {"error": "LLM not available for summary generation"}

    async def _generate_technical_report(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate detailed technical report

        Includes:
        - Full vulnerability details
        - PoC evidence
        - Remediation code
        - CVSS scores
        - Attack scenarios
        """
        scan_result = task.get("scan_result")
        vulnerabilities = scan_result.get("vulnerabilities", [])

        self.log_action("Generating technical report")

        technical_report = {
            "generated_at": datetime.now().isoformat(),
            "scan_id": scan_result.get("scan_id"),
            "target": scan_result.get("target_url"),
            "scan_duration": scan_result.get("scan_duration"),
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities_by_severity": {
                "critical": len([v for v in vulnerabilities if v.get("severity") == "critical"]),
                "high": len([v for v in vulnerabilities if v.get("severity") == "high"]),
                "medium": len([v for v in vulnerabilities if v.get("severity") == "medium"]),
                "low": len([v for v in vulnerabilities if v.get("severity") == "low"])
            },
            "detailed_findings": []
        }

        # Add detailed findings with AI analysis
        analyst = await get_llm_analyst()
        for vuln in vulnerabilities[:20]:  # Limit to top 20
            finding = {
                "title": vuln.get("title"),
                "severity": vuln.get("severity"),
                "category": vuln.get("category"),
                "affected_url": vuln.get("affected_url"),
                "proof_of_concept": vuln.get("proof_of_concept"),
                "remediation": vuln.get("remediation")
            }

            # Add AI analysis if available
            if analyst.available:
                analysis = await analyst.analyze_vulnerability(vuln)
                if analysis:
                    finding["ai_analysis"] = {
                        "root_cause": analysis.root_cause,
                        "exploitation_complexity": analysis.exploitation_complexity,
                        "business_impact": analysis.business_impact,
                        "remediation_code": analysis.remediation_code
                    }

            technical_report["detailed_findings"].append(finding)

        return {
            "report_type": "technical",
            "report": technical_report,
            "format": "json"
        }

    async def _generate_compliance_report(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate compliance report

        Standards:
        - OWASP Top 10
        - PCI-DSS
        - HIPAA
        - GDPR
        - ISO 27001
        """
        scan_result = task.get("scan_result")
        standard = task.get("standard", "OWASP")
        vulnerabilities = scan_result.get("vulnerabilities", [])

        self.log_action(f"Generating {standard} compliance report")

        # Map vulnerabilities to compliance requirements
        compliance_mapping = {
            "OWASP": self._map_to_owasp(vulnerabilities),
            "PCI-DSS": self._map_to_pci_dss(vulnerabilities),
        }

        compliance_report = {
            "standard": standard,
            "generated_at": datetime.now().isoformat(),
            "scan_id": scan_result.get("scan_id"),
            "compliance_status": compliance_mapping.get(standard, {}),
            "non_compliant_items": [],
            "recommendations": []
        }

        return {
            "report_type": "compliance",
            "report": compliance_report,
            "format": "json"
        }

    def _map_to_owasp(self, vulnerabilities: List) -> Dict[str, Any]:
        """Map findings to OWASP Top 10"""
        owasp_categories = {
            "A01:2021-Broken Access Control": [],
            "A02:2021-Cryptographic Failures": [],
            "A03:2021-Injection": [],
            "A04:2021-Insecure Design": [],
            "A05:2021-Security Misconfiguration": [],
            "A06:2021-Vulnerable Components": [],
            "A07:2021-Auth Failures": [],
            "A08:2021-Software Integrity": [],
            "A09:2021-Logging Failures": [],
            "A10:2021-SSRF": []
        }

        # TODO: Map vulnerabilities to OWASP categories
        return owasp_categories

    def _map_to_pci_dss(self, vulnerabilities: List) -> Dict[str, Any]:
        """Map findings to PCI-DSS requirements"""
        # TODO: Implement PCI-DSS mapping
        return {}

    async def _generate_remediation_roadmap(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate remediation roadmap with timeline

        Phases:
        - Quick wins (0-7 days)
        - Short term (1-4 weeks)
        - Medium term (1-3 months)
        - Long term (3-6 months)
        """
        vulnerabilities = task.get("vulnerabilities", [])

        self.log_action("Generating remediation roadmap")

        roadmap = {
            "quick_wins": [],       # 0-7 days
            "short_term": [],       # 1-4 weeks
            "medium_term": [],      # 1-3 months
            "long_term": []         # 3-6 months
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low")
            fix_complexity = vuln.get("fix_complexity", "medium")

            # Categorize by priority
            if severity in ["critical", "high"] and fix_complexity == "low":
                roadmap["quick_wins"].append(vuln)
            elif severity == "high":
                roadmap["short_term"].append(vuln)
            elif severity == "medium":
                roadmap["medium_term"].append(vuln)
            else:
                roadmap["long_term"].append(vuln)

        return {
            "roadmap": roadmap,
            "total_items": len(vulnerabilities),
            "estimated_completion": "6 months"
        }

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process messages from orchestrator"""
        message_type = message.message_type

        if message_type == "start_reporting":
            scan_id = message.content.get("scan_id")
            scan_result = message.content.get("scan_result")

            self.log_action(f"Starting reporting for scan {scan_id}")

            # Generate all reports
            await self._generate_executive_summary({"scan_result": scan_result})
            await self._generate_technical_report({"scan_result": scan_result})

            return self.send_message(
                receiver="orchestrator",
                message_type="phase_complete",
                content={
                    "scan_id": scan_id,
                    "phase": "reporting",
                    "reports_generated": 2
                },
                priority=4
            )

        return None
