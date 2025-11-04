"""
AI-Powered Professional Report Generator
Uses Claude to generate comprehensive, executive-ready security reports

Features:
- Executive summary generation
- Technical deep-dive reports
- Risk assessment and prioritization
- Remediation roadmap
- Multiple formats (markdown, HTML, PDF-ready)
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from anthropic import AsyncAnthropic

logger = logging.getLogger(__name__)


class AIPoweredReportGenerator:
    """
    Generate professional penetration testing reports using Claude AI

    Creates:
    - Executive summaries (non-technical)
    - Technical reports (detailed)
    - Remediation plans
    - Risk assessments
    """

    def __init__(self, api_key: str):
        """
        Initialize report generator

        Args:
            api_key: Anthropic API key
        """
        self.client = AsyncAnthropic(api_key=api_key)
        logger.info("📄 AI Report Generator initialized")

    async def generate_executive_summary(
        self,
        scan_result: Dict[str, Any],
        memory_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate executive summary (for management/non-technical audience)

        Args:
            scan_result: Scan results data
            memory_data: Agent memory data (optional)

        Returns:
            Executive summary in markdown format
        """
        try:
            logger.info("📊 Generating executive summary...")

            prompt = self._build_executive_summary_prompt(scan_result, memory_data)

            response = await self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=4000,
                temperature=0.5,  # Lower temperature for factual reporting
                messages=[{"role": "user", "content": prompt}]
            )

            summary = response.content[0].text

            logger.info("✅ Executive summary generated")

            return summary

        except Exception as e:
            logger.error(f"Failed to generate executive summary: {e}")
            return self._fallback_executive_summary(scan_result)

    async def generate_technical_report(
        self,
        scan_result: Dict[str, Any],
        include_payloads: bool = False
    ) -> str:
        """
        Generate detailed technical report (for security teams)

        Args:
            scan_result: Scan results data
            include_payloads: Include actual payloads in report

        Returns:
            Technical report in markdown format
        """
        try:
            logger.info("🔬 Generating technical report...")

            prompt = self._build_technical_report_prompt(scan_result, include_payloads)

            response = await self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=8000,
                temperature=0.4,
                messages=[{"role": "user", "content": prompt}]
            )

            report = response.content[0].text

            logger.info("✅ Technical report generated")

            return report

        except Exception as e:
            logger.error(f"Failed to generate technical report: {e}")
            return self._fallback_technical_report(scan_result)

    async def generate_remediation_plan(
        self,
        vulnerabilities: List[Dict[str, Any]],
        timeline: str = "30_days"
    ) -> str:
        """
        Generate prioritized remediation plan

        Args:
            vulnerabilities: List of vulnerabilities
            timeline: Remediation timeline ("30_days", "60_days", "90_days")

        Returns:
            Remediation plan in markdown format
        """
        try:
            logger.info("🛠️  Generating remediation plan...")

            prompt = self._build_remediation_plan_prompt(vulnerabilities, timeline)

            response = await self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=5000,
                temperature=0.5,
                messages=[{"role": "user", "content": prompt}]
            )

            plan = response.content[0].text

            logger.info("✅ Remediation plan generated")

            return plan

        except Exception as e:
            logger.error(f"Failed to generate remediation plan: {e}")
            return self._fallback_remediation_plan(vulnerabilities)

    async def generate_risk_assessment(
        self,
        scan_result: Dict[str, Any],
        business_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate risk assessment with business impact analysis

        Args:
            scan_result: Scan results data
            business_context: Business context (industry, compliance requirements, etc.)

        Returns:
            Risk assessment in markdown format
        """
        try:
            logger.info("⚖️  Generating risk assessment...")

            prompt = self._build_risk_assessment_prompt(scan_result, business_context)

            response = await self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=4000,
                temperature=0.5,
                messages=[{"role": "user", "content": prompt}]
            )

            assessment = response.content[0].text

            logger.info("✅ Risk assessment generated")

            return assessment

        except Exception as e:
            logger.error(f"Failed to generate risk assessment: {e}")
            return self._fallback_risk_assessment(scan_result)

    def _build_executive_summary_prompt(
        self,
        scan_result: Dict[str, Any],
        memory_data: Optional[Dict[str, Any]]
    ) -> str:
        """Build prompt for executive summary"""
        import json

        prompt = f"""You are a senior security consultant writing an executive summary for company leadership. Create a clear, non-technical summary that executives can understand.

# Scan Information
- **Target:** {scan_result.get('target_url', 'N/A')}
- **Scan Date:** {scan_result.get('start_time', datetime.utcnow().isoformat())}
- **Scan Duration:** {scan_result.get('duration', 'N/A')}
- **Scan Mode:** {scan_result.get('mode', 'N/A')}

# Vulnerability Statistics
- **Total Vulnerabilities:** {len(scan_result.get('vulnerabilities', []))}
- **Critical:** {len([v for v in scan_result.get('vulnerabilities', []) if v.get('severity') == 'critical'])}
- **High:** {len([v for v in scan_result.get('vulnerabilities', []) if v.get('severity') == 'high'])}
- **Medium:** {len([v for v in scan_result.get('vulnerabilities', []) if v.get('severity') == 'medium'])}
- **Low:** {len([v for v in scan_result.get('vulnerabilities', []) if v.get('severity') == 'low'])}

# Top 5 Critical/High Vulnerabilities
{json.dumps([
    {'title': v.get('title'), 'severity': v.get('severity'), 'category': v.get('category')}
    for v in sorted(scan_result.get('vulnerabilities', []), key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x.get('severity', 'low'), 4))[:5]
], indent=2)}

# Technologies Detected
{json.dumps([t.get('name', '') for t in scan_result.get('detected_technologies', [])][:10], indent=2)}

---

# Your Task

Create an executive summary with:

1. **Overall Security Posture** (1-2 paragraphs)
   - Is this application secure or at risk?
   - What's the overall risk level?

2. **Key Findings** (3-5 bullet points)
   - Most critical issues in business terms
   - Potential business impact (data breach, financial loss, reputation)

3. **Immediate Actions Required** (Top 3 priorities)
   - What must be fixed right now?
   - Why it matters to the business

4. **Risk Score** (1-10 scale with explanation)
   - Overall risk score
   - Justification

**Writing Style:**
- NO technical jargon (avoid terms like "XSS", "SQLi", "CSRF")
- Use business language (data breach, unauthorized access, financial loss)
- Be clear and direct
- Focus on business impact, not technical details
- Maximum 1 page (aim for 400-500 words)

**Format:** Use markdown with clear sections."""

        return prompt

    def _build_technical_report_prompt(
        self,
        scan_result: Dict[str, Any],
        include_payloads: bool
    ) -> str:
        """Build prompt for technical report"""
        import json

        prompt = f"""You are a penetration tester writing a detailed technical report for the security team. Be thorough and technical.

# Scan Information
- **Target:** {scan_result.get('target_url', 'N/A')}
- **Scan ID:** {scan_result.get('scan_id', 'N/A')}
- **Scan Date:** {scan_result.get('start_time', datetime.utcnow().isoformat())}
- **Scan Mode:** {scan_result.get('mode', 'N/A')}
- **Total Endpoints:** {len(scan_result.get('discovered_endpoints', []))}

# Vulnerabilities Found
{json.dumps([
    {
        'id': v.get('id'),
        'title': v.get('title'),
        'severity': v.get('severity'),
        'category': v.get('category'),
        'url': v.get('affected_url', '')[:80],
        'parameter': v.get('affected_parameter', ''),
        'cwe': v.get('cwe_id', ''),
        'owasp': v.get('owasp_category', '')
    }
    for v in scan_result.get('vulnerabilities', [])
], indent=2)}

# Technologies Detected
{json.dumps([
    {'name': t.get('name'), 'version': t.get('version'), 'categories': t.get('categories', [])}
    for t in scan_result.get('detected_technologies', [])
], indent=2)}

---

# Your Task

Create a comprehensive technical report with:

## 1. Executive Summary (1 paragraph technical overview)

## 2. Methodology
- What testing techniques were used
- Scan depth and coverage

## 3. Findings (For each vulnerability):
- **Vulnerability Name**
- **Severity & Risk Rating**
- **Affected Component** (URL, parameter)
- **Technical Description** (what is it, how it works)
- **Exploitation Details** {"with actual payloads" if include_payloads else "without payloads"}
- **Proof of Concept** (step-by-step)
- **Impact Analysis** (what attacker can do)
- **CWE/OWASP Classification**
- **Remediation** (how to fix)

## 4. Technology Stack Analysis
- Technologies identified
- Version-specific vulnerabilities
- Configuration issues

## 5. Attack Surface Summary
- Number of endpoints
- Input vectors tested
- Authentication mechanisms

**Format:** Use markdown with clear sections, code blocks for technical details, and tables where appropriate.

**Style:** Technical and detailed, for security engineers."""

        return prompt

    def _build_remediation_plan_prompt(
        self,
        vulnerabilities: List[Dict[str, Any]],
        timeline: str
    ) -> str:
        """Build prompt for remediation plan"""
        import json

        timeline_days = {"30_days": 30, "60_days": 60, "90_days": 90}.get(timeline, 30)

        prompt = f"""You are a security consultant creating a remediation plan. Organize fixes into phases based on priority and complexity.

# Timeline
{timeline_days} days

# Vulnerabilities to Remediate
{json.dumps([
    {
        'title': v.get('title'),
        'severity': v.get('severity'),
        'category': v.get('category'),
        'url': v.get('affected_url', '')[:60],
        'remediation': v.get('remediation', '')[:200]
    }
    for v in vulnerabilities
], indent=2)}

---

# Your Task

Create a phased remediation plan:

## Phase 1: Critical (Days 1-7)
- List CRITICAL severity issues
- Quick wins that reduce risk immediately
- Estimated effort for each

## Phase 2: High Priority (Days 8-21)
- List HIGH severity issues
- Group by system/component for efficiency
- Estimated effort for each

## Phase 3: Medium Priority (Days 22-{timeline_days})
- List MEDIUM severity issues
- Can be batched together
- Estimated effort for each

For each vulnerability:
1. **Issue:** Brief description
2. **Location:** Where to fix
3. **Fix:** Specific remediation steps
4. **Effort:** Hours/days estimate
5. **Validation:** How to verify the fix

**Also include:**
- Total estimated effort (hours)
- Required skills/roles
- Dependencies between fixes
- Quick wins vs long-term fixes
- Testing requirements

**Format:** Markdown with clear phases, tables, and checklists."""

        return prompt

    def _build_risk_assessment_prompt(
        self,
        scan_result: Dict[str, Any],
        business_context: Optional[Dict[str, Any]]
    ) -> str:
        """Build prompt for risk assessment"""
        import json

        context_str = ""
        if business_context:
            context_str = f"""
# Business Context
- **Industry:** {business_context.get('industry', 'Not specified')}
- **Compliance Requirements:** {', '.join(business_context.get('compliance', ['None specified']))}
- **Data Sensitivity:** {business_context.get('data_sensitivity', 'Not specified')}
- **Public Facing:** {business_context.get('public_facing', 'Not specified')}
"""

        prompt = f"""You are a security risk analyst assessing business risk from security vulnerabilities.

{context_str}

# Vulnerability Summary
- **Total:** {len(scan_result.get('vulnerabilities', []))}
- **Critical:** {len([v for v in scan_result.get('vulnerabilities', []) if v.get('severity') == 'critical'])}
- **High:** {len([v for v in scan_result.get('vulnerabilities', []) if v.get('severity') == 'high'])}

# Critical Vulnerabilities
{json.dumps([
    {'title': v.get('title'), 'category': v.get('category'), 'impact': v.get('description', '')[:150]}
    for v in scan_result.get('vulnerabilities', [])
    if v.get('severity') == 'critical'
][:5], indent=2)}

---

# Your Task

Create a risk assessment with:

## 1. Overall Risk Rating (1-10 scale)
- Risk score with justification
- Likelihood vs Impact matrix

## 2. Business Impact Analysis
For each risk level:
- **Data Breach Risk:** What data could be compromised?
- **Financial Impact:** Potential losses (direct, regulatory fines, reputation)
- **Operational Impact:** Service disruption, downtime
- **Compliance Impact:** Violations, legal consequences
- **Reputation Impact:** Brand damage, customer trust

## 3. Attack Scenarios
3-5 realistic attack scenarios:
- What could an attacker do?
- Step-by-step attack path
- Business consequences

## 4. Prioritization
- Which risks to address first?
- Cost vs benefit analysis
- Quick wins

## 5. Recommendations
- Strategic recommendations
- Resource allocation
- Timeline

**Style:** Business-focused but technically accurate. Use risk matrices, scenarios, and clear recommendations."""

        return prompt

    def _fallback_executive_summary(self, scan_result: Dict[str, Any]) -> str:
        """Fallback executive summary if AI fails"""
        vulns = scan_result.get('vulnerabilities', [])
        critical = len([v for v in vulns if v.get('severity') == 'critical'])
        high = len([v for v in vulns if v.get('severity') == 'high'])

        risk_level = "HIGH" if critical > 0 or high > 3 else "MEDIUM" if high > 0 else "LOW"

        return f"""# Executive Summary

## Overall Risk Level: {risk_level}

The security assessment of {scan_result.get('target_url', 'the application')} identified **{len(vulns)} security issues**, including **{critical} critical** and **{high} high-severity** vulnerabilities.

### Key Findings:
- {critical} critical security issues requiring immediate attention
- {high} high-severity vulnerabilities that pose significant risk
- Multiple security weaknesses that could lead to data breach

### Immediate Actions Required:
1. Address all critical vulnerabilities within 7 days
2. Implement security patches for high-severity issues
3. Review and strengthen authentication mechanisms

**Risk Score: {8 if critical > 0 else 5 if high > 0 else 3}/10**

*This is an automated fallback summary. For a comprehensive analysis, please review the detailed technical report.*
"""

    def _fallback_technical_report(self, scan_result: Dict[str, Any]) -> str:
        """Fallback technical report if AI fails"""
        return f"""# Technical Security Assessment Report

## Scan Information
- Target: {scan_result.get('target_url', 'N/A')}
- Scan Date: {scan_result.get('start_time', 'N/A')}
- Total Vulnerabilities: {len(scan_result.get('vulnerabilities', []))}

## Findings Summary
{self._format_vulnerabilities_list(scan_result.get('vulnerabilities', []))}

*This is an automated fallback report. For AI-generated comprehensive analysis, please check API configuration.*
"""

    def _fallback_remediation_plan(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Fallback remediation plan if AI fails"""
        critical = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high = [v for v in vulnerabilities if v.get('severity') == 'high']

        plan = "# Remediation Plan\n\n"
        plan += "## Phase 1: Critical (Days 1-7)\n"
        for v in critical:
            plan += f"- {v.get('title')}\n"

        plan += "\n## Phase 2: High Priority (Days 8-21)\n"
        for v in high:
            plan += f"- {v.get('title')}\n"

        return plan

    def _fallback_risk_assessment(self, scan_result: Dict[str, Any]) -> str:
        """Fallback risk assessment if AI fails"""
        vulns = scan_result.get('vulnerabilities', [])
        critical = len([v for v in vulns if v.get('severity') == 'critical'])

        return f"""# Risk Assessment

## Overall Risk Score: {8 if critical > 0 else 5}/10

### Business Impact:
- Data Breach Risk: {"High" if critical > 0 else "Medium"}
- Financial Impact: Potential regulatory fines and breach costs
- Operational Impact: Possible service disruption

### Recommendations:
1. Address critical vulnerabilities immediately
2. Implement security monitoring
3. Review incident response procedures
"""

    def _format_vulnerabilities_list(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format vulnerabilities as markdown list"""
        output = ""
        for v in vulnerabilities:
            output += f"### {v.get('title')}\n"
            output += f"- **Severity:** {v.get('severity', 'unknown').upper()}\n"
            output += f"- **Category:** {v.get('category', 'unknown')}\n"
            output += f"- **Location:** {v.get('affected_url', 'N/A')}\n\n"
        return output
