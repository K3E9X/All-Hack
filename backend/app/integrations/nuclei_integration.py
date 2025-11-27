"""
Nuclei Integration

Integrates Nuclei for template-based vulnerability scanning.
"""
import asyncio
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable
from app.models import Vulnerability, Misconfiguration, SeverityLevel, VulnerabilityCategory

logger = logging.getLogger(__name__)

class NucleiIntegration:
    """
    Nuclei integration for template-based vulnerability scanning

    Features:
    - Automatic Nuclei installation check
    - Template-based scanning
    - JSON output parsing
    - Custom templates support
    - Severity mapping
    """

    # Map Nuclei severity to our severity levels
    SEVERITY_MAP = {
        'info': SeverityLevel.INFO,
        'low': SeverityLevel.LOW,
        'medium': SeverityLevel.MEDIUM,
        'high': SeverityLevel.HIGH,
        'critical': SeverityLevel.CRITICAL,
    }

    # Map Nuclei tags to our categories
    CATEGORY_MAP = {
        'xss': VulnerabilityCategory.XSS,
        'sqli': VulnerabilityCategory.SQL_INJECTION,
        'rce': VulnerabilityCategory.COMMAND_INJECTION,
        'ssrf': VulnerabilityCategory.SSRF,
        'lfi': VulnerabilityCategory.PATH_TRAVERSAL,
        'xxe': VulnerabilityCategory.XXE,
        'idor': VulnerabilityCategory.IDOR,
    }

    def __init__(
        self,
        nuclei_path: Optional[str] = None,
        templates_dir: Optional[str] = None,
        progress_callback: Optional[Callable] = None
    ):
        """
        Initialize Nuclei integration

        Args:
            nuclei_path: Path to nuclei executable (auto-detected if None)
            templates_dir: Path to nuclei templates directory
            progress_callback: Optional callback for progress updates
        """
        self.nuclei_path = nuclei_path or self._find_nuclei()
        self.templates_dir = templates_dir or self._find_templates_dir()
        self.progress_callback = progress_callback
        self.temp_dir = tempfile.mkdtemp(prefix="allhack_nuclei_")

    def _find_nuclei(self) -> Optional[str]:
        """
        Find Nuclei installation

        Checks common locations:
        - nuclei in PATH
        - /usr/local/bin/nuclei
        - ~/go/bin/nuclei
        """
        # Check if nuclei is in PATH
        nuclei_bin = shutil.which('nuclei')
        if nuclei_bin:
            logger.info(f"✅ Found Nuclei in PATH: {nuclei_bin}")
            return nuclei_bin

        # Check common installation paths
        common_paths = [
            '/usr/local/bin/nuclei',
            '/usr/bin/nuclei',
            os.path.expanduser('~/go/bin/nuclei'),
            os.path.expanduser('~/.local/bin/nuclei'),
        ]

        for path in common_paths:
            if os.path.exists(path):
                logger.info(f"✅ Found Nuclei at: {path}")
                return path

        logger.warning("⚠️  Nuclei not found. Install with: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
        return None

    def _find_templates_dir(self) -> Optional[str]:
        """Find Nuclei templates directory"""
        common_paths = [
            os.path.expanduser('~/nuclei-templates'),
            os.path.expanduser('~/.config/nuclei-templates'),
            '/opt/nuclei-templates',
        ]

        for path in common_paths:
            if os.path.exists(path):
                logger.info(f"✅ Found Nuclei templates at: {path}")
                return path

        logger.warning("⚠️  Nuclei templates not found. Run: nuclei -update-templates")
        return None

    def is_available(self) -> bool:
        """Check if Nuclei is available"""
        return self.nuclei_path is not None

    async def scan_target(
        self,
        target: str,
        scan_depth: str = "balanced",
        severity_filter: Optional[List[str]] = None,
        tags: Optional[List[str]] = None
    ) -> tuple[List[Vulnerability], List[Misconfiguration]]:
        """
        Scan target with Nuclei

        Args:
            target: Target URL or domain
            scan_depth: Scan depth (quick/balanced/deep)
            severity_filter: Filter by severity (critical, high, medium, low, info)
            tags: Filter by tags (e.g., ['cve', 'owasp', 'misconfig'])

        Returns:
            Tuple of (vulnerabilities, misconfigurations)
        """
        if not self.is_available():
            logger.error("❌ Nuclei not available. Skipping Nuclei scan.")
            return [], []

        logger.info(f"🔥 Nuclei: Starting template-based scan on {target}")

        if self.progress_callback:
            await self.progress_callback(f"Nuclei: Scanning {target} with templates")

        vulnerabilities = []
        misconfigurations = []

        # Output file for JSON results
        output_file = os.path.join(self.temp_dir, 'nuclei_output.json')

        # Build Nuclei command
        cmd = [
            self.nuclei_path,
            '-u', target,
            '-json',
            '-o', output_file,
            '-silent',  # Silent mode
        ]

        # Add scan depth options
        if scan_depth == 'quick':
            cmd.extend([
                '-severity', 'critical,high',
                '-tags', 'cve,owasp',
                '-rate-limit', '150',
            ])
        elif scan_depth == 'balanced':
            cmd.extend([
                '-severity', 'critical,high,medium',
                '-rate-limit', '100',
            ])
        else:  # deep
            cmd.extend([
                '-severity', 'critical,high,medium,low',
                '-rate-limit', '50',
            ])

        # Add custom severity filter
        if severity_filter:
            cmd.extend(['-severity', ','.join(severity_filter)])

        # Add custom tags
        if tags:
            cmd.extend(['-tags', ','.join(tags)])

        # Add templates directory if available
        if self.templates_dir:
            cmd.extend(['-t', self.templates_dir])

        try:
            logger.debug(f"Running Nuclei: {' '.join(cmd[:5])}...")

            # Run Nuclei
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Wait with timeout (max 5 minutes for Nuclei)
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300.0
                )
            except asyncio.TimeoutError:
                process.kill()
                logger.warning(f"⚠️  Nuclei timeout for {target}")
                return [], []

            # Parse JSON output
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            result = json.loads(line.strip())
                            item = self._parse_nuclei_result(result, target)
                            if item:
                                # Categorize as vulnerability or misconfiguration
                                if isinstance(item, Vulnerability):
                                    vulnerabilities.append(item)
                                else:
                                    misconfigurations.append(item)
                        except json.JSONDecodeError:
                            continue

            logger.info(f"✅ Nuclei: Found {len(vulnerabilities)} vulnerabilities, {len(misconfigurations)} misconfigurations")

        except Exception as e:
            logger.error(f"❌ Nuclei error for {target}: {e}")

        return vulnerabilities, misconfigurations

    def _parse_nuclei_result(
        self,
        result: Dict[str, Any],
        target: str
    ) -> Optional[Any]:
        """
        Parse Nuclei JSON result

        Args:
            result: Nuclei JSON result
            target: Target URL

        Returns:
            Vulnerability or Misconfiguration object
        """
        # Extract key fields
        template_id = result.get('template-id', 'unknown')
        template_name = result.get('info', {}).get('name', 'Unknown')
        severity_str = result.get('info', {}).get('severity', 'info').lower()
        description = result.get('info', {}).get('description', '')
        matched_at = result.get('matched-at', target)
        tags = result.get('info', {}).get('tags', [])

        if isinstance(tags, str):
            tags = [tags]

        # Extract matcher info
        matcher_name = result.get('matcher-name', '')
        extracted_results = result.get('extracted-results', [])

        # Map severity
        severity = self.SEVERITY_MAP.get(severity_str, SeverityLevel.INFO)

        # Determine category from tags
        category = VulnerabilityCategory.OTHER
        for tag in tags:
            if tag in self.CATEGORY_MAP:
                category = self.CATEGORY_MAP[tag]
                break

        # Determine if it's a misconfiguration
        is_misconfiguration = any(keyword in tags for keyword in [
            'misconfig', 'misconfiguration', 'config', 'exposure',
            'disclosure', 'default-login', 'panel'
        ])

        # Build proof of concept
        poc = f"Nuclei Template Detection:\\n\\n"
        poc += f"Template: {template_id}\\n"
        poc += f"Matched At: {matched_at}\\n"
        if matcher_name:
            poc += f"Matcher: {matcher_name}\\n"
        if extracted_results:
            poc += f"Extracted Data:\\n"
            for extracted in extracted_results[:5]:  # Limit to 5
                poc += f"  - {extracted}\\n"

        # Get references
        references = result.get('info', {}).get('reference', [])
        if isinstance(references, str):
            references = [references]

        # Build remediation
        remediation = self._build_remediation(template_id, template_name, tags)

        # Create appropriate object
        if is_misconfiguration:
            return Misconfiguration(
                id=f"nuclei_misconfig_{hash(template_id)}_{hash(matched_at)}",
                title=f"Configuration Issue: {template_name}",
                description=description or f"Nuclei template '{template_id}' detected a configuration issue.",
                severity=severity,
                affected_url=matched_at,
                proof_of_concept=poc,
                recommendation=remediation,
                references=references[:3] if references else [
                    f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{template_id}.yaml"
                ],
                tool_output=json.dumps(result, indent=2)[:500]
            )
        else:
            return Vulnerability(
                id=f"nuclei_vuln_{hash(template_id)}_{hash(matched_at)}",
                title=f"{template_name} - Detected by Nuclei",
                description=description or f"Nuclei template '{template_id}' detected a security vulnerability.",
                severity=severity,
                category=category,
                affected_url=matched_at,
                proof_of_concept=poc,
                payload=matcher_name,
                remediation=remediation,
                cwe_id=result.get('info', {}).get('cwe-id', 'CWE-noinfo'),
                owasp_category="Various",
                references=references[:3] if references else [
                    f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{template_id}.yaml"
                ],
                tool_output=json.dumps(result, indent=2)[:500]
            )

    def _build_remediation(
        self,
        template_id: str,
        template_name: str,
        tags: List[str]
    ) -> str:
        """Build remediation guidance based on template"""
        remediation = f"**Remediation for {template_name}**\\n\\n"

        # Generic remediation based on tags
        if 'cve' in tags:
            remediation += "1. **Update Software**\\n"
            remediation += "   - Apply the latest security patches\\n"
            remediation += "   - Update affected components to patched versions\\n\\n"

        if 'exposure' in tags or 'disclosure' in tags:
            remediation += "1. **Restrict Access**\\n"
            remediation += "   - Implement authentication and authorization\\n"
            remediation += "   - Use IP whitelisting if applicable\\n"
            remediation += "   - Remove sensitive information from public endpoints\\n\\n"

        if 'default-login' in tags:
            remediation += "1. **Change Default Credentials**\\n"
            remediation += "   - Immediately change all default usernames and passwords\\n"
            remediation += "   - Implement strong password policies\\n"
            remediation += "   - Enable multi-factor authentication\\n\\n"

        if 'misconfig' in tags:
            remediation += "1. **Review Configuration**\\n"
            remediation += "   - Follow security hardening guidelines\\n"
            remediation += "   - Disable unnecessary features\\n"
            remediation += "   - Apply principle of least privilege\\n\\n"

        remediation += "2. **Additional Steps**\\n"
        remediation += "   - Conduct security audit of the affected component\\n"
        remediation += "   - Review similar components for the same issue\\n"
        remediation += "   - Implement continuous security monitoring\\n\\n"

        remediation += f"3. **Reference**\\n"
        remediation += f"   - Review Nuclei template: {template_id}\\n"
        remediation += f"   - Check vendor security advisories\\n"

        return remediation

    def cleanup(self):
        """Clean up temporary files"""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.debug(f"🧹 Cleaned up Nuclei temp directory: {self.temp_dir}")
        except Exception as e:
            logger.warning(f"⚠️  Failed to cleanup Nuclei temp dir: {e}")

    def __del__(self):
        """Destructor to ensure cleanup"""
        self.cleanup()
