"""
Intelligent Scan Brain - Analyzes results and adapts scanning strategy
"""
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from app.models import Vulnerability, Misconfiguration, TechnologyInfo, SeverityLevel

logger = logging.getLogger(__name__)

@dataclass
class ScanIntelligence:
    """Intelligence gathered during scan"""
    # Technology stack
    detected_frameworks: List[str] = field(default_factory=list)
    detected_languages: List[str] = field(default_factory=list)
    detected_servers: List[str] = field(default_factory=list)
    detected_databases: List[str] = field(default_factory=list)

    # Security posture
    has_waf: bool = False
    waf_type: Optional[str] = None
    has_authentication: bool = False
    auth_type: Optional[str] = None

    # Attack surface
    open_ports: List[int] = field(default_factory=list)
    exposed_services: List[str] = field(default_factory=list)
    admin_endpoints: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)

    # Vulnerabilities found
    sql_vulnerable_params: List[str] = field(default_factory=list)
    xss_vulnerable_params: List[str] = field(default_factory=list)
    command_vulnerable_params: List[str] = field(default_factory=list)

    # Attack vectors identified
    promising_attack_vectors: List[Dict[str, Any]] = field(default_factory=list)

    # Recommendations for next phases
    recommended_tests: List[str] = field(default_factory=list)
    skip_tests: List[str] = field(default_factory=list)


class ScanBrain:
    """
    Intelligent brain that analyzes scan results and adapts strategy
    """

    def __init__(self):
        self.intelligence = ScanIntelligence()

    def analyze_infrastructure(
        self,
        open_ports: List[Dict[str, Any]],
        subdomains: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze infrastructure results and provide intelligence

        Returns:
            Dict with recommendations and strategy adjustments
        """
        logger.info("🧠 [BRAIN] Analyzing infrastructure results...")

        recommendations = {
            'focus_areas': [],
            'attack_vectors': [],
            'next_phase_adjustments': {},
            'reasoning': []
        }

        # Analyze open ports
        for port_info in open_ports:
            port = port_info.get('port')
            service = port_info.get('service', 'unknown')

            self.intelligence.open_ports.append(port)
            self.intelligence.exposed_services.append(service)

            # Database exposed - HIGH PRIORITY
            if port in [3306, 5432, 27017, 6379, 9200, 11211]:
                recommendations['focus_areas'].append('database_exploitation')
                recommendations['attack_vectors'].append({
                    'type': 'database_direct_access',
                    'target': f'{service} on port {port}',
                    'priority': 'CRITICAL',
                    'reason': f'{service} database is directly accessible, attempt authentication bypass'
                })
                recommendations['reasoning'].append(
                    f"🎯 Found {service} on port {port} - This is a CRITICAL finding. "
                    f"Will prioritize database-related attacks."
                )

            # SSH exposed - Brute force potential
            if port == 22:
                recommendations['attack_vectors'].append({
                    'type': 'ssh_bruteforce',
                    'target': f'SSH on port 22',
                    'priority': 'HIGH',
                    'reason': 'SSH exposed, potential for credential attacks'
                })

            # Admin services exposed
            if port in [3389, 5900]:  # RDP, VNC
                recommendations['focus_areas'].append('admin_access')
                recommendations['reasoning'].append(
                    f"🎯 Remote admin service ({service}) exposed - Will test for weak credentials"
                )

        # Analyze subdomains
        interesting_subdomains = ['dev', 'staging', 'test', 'admin', 'api', 'backup', 'old']
        for subdomain_info in subdomains:
            subdomain = subdomain_info.get('subdomain', '')

            for keyword in interesting_subdomains:
                if keyword in subdomain.lower():
                    recommendations['attack_vectors'].append({
                        'type': 'subdomain_exploitation',
                        'target': subdomain,
                        'priority': 'HIGH',
                        'reason': f'Development/admin subdomain found - likely has weaker security'
                    })
                    recommendations['reasoning'].append(
                        f"🎯 Interesting subdomain: {subdomain} - Development environments "
                        f"often have debug features and weaker security. Will scan thoroughly."
                    )

        # Strategic recommendations
        if len(open_ports) > 10:
            recommendations['next_phase_adjustments']['increase_depth'] = True
            recommendations['reasoning'].append(
                f"🔍 Large attack surface detected ({len(open_ports)} ports) - "
                f"Will perform deeper reconnaissance"
            )

        logger.info(f"🧠 [BRAIN] Infrastructure analysis complete. "
                   f"Found {len(recommendations['attack_vectors'])} attack vectors")

        return recommendations

    def analyze_technologies(self, technologies: List[TechnologyInfo]) -> Dict[str, Any]:
        """
        Analyze detected technologies and adapt testing strategy
        """
        logger.info("🧠 [BRAIN] Analyzing technology stack...")

        recommendations = {
            'targeted_tests': [],
            'known_vulnerabilities': [],
            'reasoning': []
        }

        for tech in technologies:
            name = tech.name.lower()
            version = tech.version

            # Framework detection
            if 'react' in name or 'vue' in name or 'angular' in name:
                self.intelligence.detected_frameworks.append(tech.name)
                recommendations['targeted_tests'].append('client_side_attacks')
                recommendations['reasoning'].append(
                    f"🎯 JavaScript framework ({tech.name}) detected - Will focus on "
                    f"DOM-based XSS and client-side vulnerabilities"
                )

            # Backend frameworks
            if any(fw in name for fw in ['django', 'flask', 'laravel', 'spring', 'express']):
                self.intelligence.detected_frameworks.append(tech.name)
                recommendations['reasoning'].append(
                    f"🎯 Backend framework: {tech.name} - Will test framework-specific "
                    f"vulnerabilities (mass assignment, template injection, etc.)"
                )

            # WordPress detected - known attack vectors
            if 'wordpress' in name:
                recommendations['targeted_tests'].extend([
                    'wordpress_xmlrpc',
                    'wordpress_plugin_vulns',
                    'wordpress_user_enum'
                ])
                recommendations['reasoning'].append(
                    f"🎯 WordPress detected - Will test XML-RPC, plugin vulnerabilities, "
                    f"and user enumeration"
                )

            # Vulnerable versions
            if version:
                # Check for known vulnerable versions (simplified)
                vulnerable_versions = {
                    'Apache': ['2.4.49', '2.4.50'],
                    'nginx': ['1.20.0'],
                }

                for vuln_name, vuln_versions in vulnerable_versions.items():
                    if vuln_name.lower() in name and version in vuln_versions:
                        recommendations['known_vulnerabilities'].append({
                            'software': tech.name,
                            'version': version,
                            'priority': 'CRITICAL',
                            'exploit': f'Known CVE for {tech.name} {version}'
                        })
                        recommendations['reasoning'].append(
                            f"🚨 CRITICAL: {tech.name} {version} has KNOWN vulnerabilities! "
                            f"Will prioritize exploitation attempts."
                        )

        logger.info(f"🧠 [BRAIN] Technology analysis complete. "
                   f"Frameworks: {len(self.intelligence.detected_frameworks)}, "
                   f"Known vulns: {len(recommendations['known_vulnerabilities'])}")

        return recommendations

    def analyze_endpoints(self, endpoints: List[Any]) -> Dict[str, Any]:
        """
        Analyze discovered endpoints and identify promising targets
        """
        logger.info(f"🧠 [BRAIN] Analyzing {len(endpoints)} discovered endpoints...")

        recommendations = {
            'priority_targets': [],
            'reasoning': []
        }

        for endpoint in endpoints:
            url = endpoint.url if hasattr(endpoint, 'url') else str(endpoint)

            # Admin endpoints - HIGH PRIORITY
            if any(keyword in url.lower() for keyword in ['admin', 'dashboard', 'panel', 'manage']):
                self.intelligence.admin_endpoints.append(url)
                recommendations['priority_targets'].append({
                    'url': url,
                    'type': 'admin',
                    'tests': ['authentication_bypass', 'privilege_escalation', 'idor'],
                    'priority': 'HIGH'
                })
                recommendations['reasoning'].append(
                    f"🎯 Admin endpoint found: {url} - Will test for authentication bypass "
                    f"and privilege escalation"
                )

            # API endpoints - TEST THOROUGHLY
            if any(keyword in url.lower() for keyword in ['/api/', '/rest/', '/graphql']):
                self.intelligence.api_endpoints.append(url)
                recommendations['priority_targets'].append({
                    'url': url,
                    'type': 'api',
                    'tests': ['mass_assignment', 'idor', 'rate_limiting', 'injection'],
                    'priority': 'HIGH'
                })

            # File upload endpoints - DANGEROUS
            if any(keyword in url.lower() for keyword in ['upload', 'file', 'media']):
                recommendations['priority_targets'].append({
                    'url': url,
                    'type': 'upload',
                    'tests': ['file_upload_bypass', 'path_traversal', 'rce'],
                    'priority': 'CRITICAL'
                })
                recommendations['reasoning'].append(
                    f"🚨 CRITICAL: File upload endpoint: {url} - This is a HIGH-RISK area. "
                    f"Will test for upload restrictions bypass and RCE."
                )

        logger.info(f"🧠 [BRAIN] Endpoint analysis complete. "
                   f"Priority targets: {len(recommendations['priority_targets'])}")

        return recommendations

    def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> Dict[str, Any]:
        """
        Analyze found vulnerabilities and suggest next steps
        """
        logger.info(f"🧠 [BRAIN] Analyzing {len(vulnerabilities)} vulnerabilities...")

        recommendations = {
            'exploitation_chain': [],
            'next_steps': [],
            'reasoning': []
        }

        # Group by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.category.value if hasattr(vuln.category, 'value') else str(vuln.category)
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)

        # SQL Injection found - PRIORITIZE
        if 'injection' in vuln_types or any('sql' in str(v.title).lower() for v in vulnerabilities):
            recommendations['exploitation_chain'].append({
                'step': 1,
                'action': 'sql_injection_exploitation',
                'reason': 'SQL injection found - can lead to full database compromise',
                'priority': 'CRITICAL'
            })
            recommendations['reasoning'].append(
                "🚨 SQL Injection detected! This is CRITICAL. Can extract entire database, "
                "bypass authentication, and potentially achieve RCE via xp_cmdshell or INTO OUTFILE."
            )

            # Track vulnerable parameters
            for vuln in vulnerabilities:
                if 'sql' in str(vuln.title).lower() and vuln.affected_parameter:
                    self.intelligence.sql_vulnerable_params.append(vuln.affected_parameter)

        # XSS + CSRF = Session hijacking
        xss_found = any('xss' in str(v.title).lower() for v in vulnerabilities)
        csrf_found = any('csrf' in str(v.title).lower() for v in vulnerabilities)

        if xss_found:
            recommendations['next_steps'].append({
                'test': 'session_hijacking',
                'reason': 'XSS can be used to steal session tokens',
                'priority': 'HIGH'
            })
            recommendations['reasoning'].append(
                "🎯 XSS found - Can be chained with CSRF to hijack admin sessions. "
                "Will attempt to craft session-stealing payloads."
            )

        # IDOR + Authentication issues = Full account takeover
        idor_found = any('idor' in str(v.title).lower() for v in vulnerabilities)
        auth_issues = any('auth' in str(v.title).lower() for v in vulnerabilities)

        if idor_found and auth_issues:
            recommendations['exploitation_chain'].append({
                'step': 2,
                'action': 'account_takeover_chain',
                'reason': 'IDOR + weak auth = Full account takeover possible',
                'priority': 'CRITICAL'
            })
            recommendations['reasoning'].append(
                "🚨 IDOR + Authentication issues detected! This combination allows "
                "full account takeover. Will test account enumeration → IDOR → takeover chain."
            )

        # Command injection = RCE
        if any('command' in str(v.title).lower() for v in vulnerabilities):
            recommendations['exploitation_chain'].append({
                'step': 1,
                'action': 'remote_code_execution',
                'reason': 'Command injection = Direct RCE',
                'priority': 'CRITICAL'
            })
            recommendations['reasoning'].append(
                "🚨 COMMAND INJECTION = GAME OVER! Can execute arbitrary commands on server. "
                "Will attempt reverse shell and privilege escalation."
            )

        # Correlation analysis
        critical_count = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.HIGH)

        if critical_count >= 3:
            recommendations['reasoning'].append(
                f"⚠️ WARNING: {critical_count} CRITICAL vulnerabilities found. "
                f"This application has SEVERE security issues. Full compromise is likely possible."
            )

        logger.info(f"🧠 [BRAIN] Vulnerability analysis complete. "
                   f"Exploitation chains: {len(recommendations['exploitation_chain'])}")

        return recommendations

    def get_adaptive_strategy(self) -> Dict[str, Any]:
        """
        Generate adaptive testing strategy based on all intelligence gathered
        """
        logger.info("🧠 [BRAIN] Generating adaptive testing strategy...")

        strategy = {
            'recommended_order': [],
            'focus_areas': [],
            'skip_areas': [],
            'estimated_time': 0,
            'reasoning': []
        }

        # If databases are exposed, prioritize database attacks
        if any(port in self.intelligence.open_ports for port in [3306, 5432, 27017, 6379]):
            strategy['recommended_order'].insert(0, 'database_exploitation')
            strategy['focus_areas'].append('database_attacks')
            strategy['reasoning'].append(
                "🎯 STRATEGY: Databases exposed - Prioritizing direct database attacks"
            )

        # If admin endpoints found, test authentication
        if self.intelligence.admin_endpoints:
            strategy['recommended_order'].insert(0, 'authentication_testing')
            strategy['focus_areas'].append('admin_access')
            strategy['reasoning'].append(
                f"🎯 STRATEGY: {len(self.intelligence.admin_endpoints)} admin endpoints found - "
                f"Focusing on authentication bypass"
            )

        # If API endpoints found, test API-specific vulns
        if self.intelligence.api_endpoints:
            strategy['recommended_order'].append('api_security_testing')
            strategy['focus_areas'].append('api_abuse')
            strategy['reasoning'].append(
                f"🎯 STRATEGY: {len(self.intelligence.api_endpoints)} API endpoints - "
                f"Testing for mass assignment, rate limiting, IDOR"
            )

        # If SQL vulns already found, skip basic SQLi and go deeper
        if self.intelligence.sql_vulnerable_params:
            strategy['skip_areas'].append('basic_sql_injection')
            strategy['recommended_order'].insert(0, 'advanced_sql_exploitation')
            strategy['reasoning'].append(
                "🎯 STRATEGY: SQL injection already confirmed - Skipping basic tests, "
                "going directly to exploitation (data extraction, RCE attempts)"
            )

        return strategy
