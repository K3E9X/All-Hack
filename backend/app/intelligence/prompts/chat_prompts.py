"""
Chat prompts for conversational pentesting assistant
"""

CHAT_SYSTEM_PROMPT = """You are an expert penetration testing assistant integrated into All-Hack, a professional security scanner.

You have access to the complete scan results including:
- All discovered vulnerabilities
- Security misconfigurations
- Discovered endpoints
- Detected technologies
- Scan timeline and phases

Your role:
- Answer questions about the scan results
- Explain vulnerabilities in simple or technical terms
- Provide exploitation guidance (for authorized testing only)
- Generate reports and summaries
- Suggest next testing steps
- Help prioritize remediation

Be concise, technical, and actionable. Use markdown for formatting.
Always remind users this is for authorized testing only."""

CHAT_CONTEXT_TEMPLATE = """
# Current Scan Context

**Scan ID**: {scan_id}
**Target**: {target_url}
**Status**: {status}
**Mode**: {mode}

## Summary
- **Vulnerabilities Found**: {vuln_count}
  - Critical: {critical_count}
  - High: {high_count}
  - Medium: {medium_count}
  - Low: {low_count}
- **Misconfigurations**: {misconfig_count}
- **Endpoints Discovered**: {endpoint_count}
- **Technologies Detected**: {tech_count}

## Technologies
{technologies}

## Top Vulnerabilities
{top_vulnerabilities}

---

User Question: {user_message}

Provide a helpful, concise answer based on the scan context above.
"""

def format_chat_context(scan_result, user_message: str) -> str:
    """Format scan context for chat"""

    # Count by severity
    vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln in scan_result.vulnerabilities:
        severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
        if severity in vuln_counts:
            vuln_counts[severity] += 1

    # Format technologies
    tech_list = []
    for tech in scan_result.detected_technologies[:10]:  # Top 10
        name = tech.name if hasattr(tech, 'name') else tech.get('name', 'Unknown')
        version = tech.version if hasattr(tech, 'version') else tech.get('version', '')
        tech_list.append(f"- {name} {version}".strip())
    technologies = "\n".join(tech_list) if tech_list else "None detected"

    # Format top vulnerabilities
    top_vulns = []
    for vuln in scan_result.vulnerabilities[:5]:  # Top 5
        title = vuln.title if hasattr(vuln, 'title') else vuln.get('title', 'Unknown')
        severity = vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity)
        url = vuln.affected_url if hasattr(vuln, 'affected_url') else vuln.get('affected_url', '')
        top_vulns.append(f"- [{severity.upper()}] {title}\n  URL: {url}")
    top_vulnerabilities = "\n".join(top_vulns) if top_vulns else "None found"

    return CHAT_CONTEXT_TEMPLATE.format(
        scan_id=scan_result.scan_id,
        target_url=scan_result.target_url,
        status=scan_result.status,
        mode=scan_result.mode,
        vuln_count=len(scan_result.vulnerabilities),
        critical_count=vuln_counts['critical'],
        high_count=vuln_counts['high'],
        medium_count=vuln_counts['medium'],
        low_count=vuln_counts['low'],
        misconfig_count=len(scan_result.misconfigurations),
        endpoint_count=len(scan_result.discovered_endpoints),
        tech_count=len(scan_result.detected_technologies),
        technologies=technologies,
        top_vulnerabilities=top_vulnerabilities,
        user_message=user_message
    )
