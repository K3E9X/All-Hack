"""
Server-Side Request Forgery (SSRF) detection scanner
"""
import asyncio
import logging
from typing import List, Optional
from app.models import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class SSRFScanner:
    """Detect SSRF vulnerabilities"""

    # SSRF payloads
    PAYLOADS = [
        # Internal network
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://[::1]",
        "http://127.1",
        "http://2130706433",  # Decimal IP for 127.0.0.1

        # AWS metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/",

        # Google Cloud metadata
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata/computeMetadata/v1/",

        # Azure metadata
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",

        # Private IP ranges
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.0.1",
        "http://192.168.1.1",

        # File protocol
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",

        # Other protocols
        "gopher://127.0.0.1:80/_GET",
        "dict://127.0.0.1:11211/stats",
    ]

    # Indicators of SSRF
    INDICATORS = [
        # Cloud metadata
        "ami-id",
        "instance-id",
        "local-hostname",
        "public-keys",
        "security-credentials",

        # Internal services
        "root:x:0:0",
        "[extensions]",  # win.ini
        "HTTP/1.",
        "Server:",

        # Connection errors that indicate internal network access
        "Connection refused",
        "No route to host",
        "Network is unreachable",
    ]

    def __init__(self, client: PentestHTTPClient):
        self.client = client

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Scan for SSRF vulnerabilities"""
        vulnerabilities = []

        tasks = []
        for endpoint in endpoints:
            tasks.append(self._test_endpoint(endpoint))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                vulnerabilities.extend(result)

        return vulnerabilities

    async def _test_endpoint(self, endpoint: str) -> List[Vulnerability]:
        """Test an endpoint for SSRF"""
        vulnerabilities = []

        # Test GET parameters
        if '?' in endpoint:
            vulns = await self._test_get_params(endpoint)
            vulnerabilities.extend(vulns)

        # Test POST parameters
        vulns = await self._test_post_params(endpoint)
        vulnerabilities.extend(vulns)

        return vulnerabilities

    async def _test_get_params(self, endpoint: str) -> List[Vulnerability]:
        """Test GET parameters for SSRF"""
        vulnerabilities = []

        if '?' not in endpoint:
            return vulnerabilities

        base_url, query_string = endpoint.split('?', 1)
        params = {}

        for param in query_string.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value

        # Test each parameter with URL-like values
        for param_name, original_value in params.items():
            # Skip if parameter doesn't look like it accepts URLs
            if not any(indicator in param_name.lower()
                      for indicator in ['url', 'uri', 'link', 'href', 'host', 'domain', 'callback', 'redirect', 'fetch']):
                continue

            for payload in self.PAYLOADS[:10]:
                test_params = params.copy()
                test_params[param_name] = payload

                vuln = await self._test_payload(
                    'GET',
                    base_url,
                    param_name,
                    payload,
                    params=test_params
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    break

        return vulnerabilities

    async def _test_post_params(self, endpoint: str) -> List[Vulnerability]:
        """Test POST parameters for SSRF"""
        vulnerabilities = []

        # Common parameters that might accept URLs
        test_params = {
            'url': 'http://example.com',
            'uri': 'http://example.com',
            'link': 'http://example.com',
            'href': 'http://example.com',
            'host': 'example.com',
            'callback': 'http://example.com/callback',
            'redirect': 'http://example.com',
            'fetch': 'http://example.com',
            'image_url': 'http://example.com/image.jpg',
            'file_url': 'http://example.com/file.txt',
        }

        for param_name, original_value in test_params.items():
            for payload in self.PAYLOADS[:10]:
                data = test_params.copy()
                data[param_name] = payload

                vuln = await self._test_payload(
                    'POST',
                    endpoint,
                    param_name,
                    payload,
                    data=data
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    break

        return vulnerabilities

    async def _test_payload(
        self,
        method: str,
        url: str,
        param_name: str,
        payload: str,
        **kwargs
    ) -> Optional[Vulnerability]:
        """Test a specific SSRF payload"""
        try:
            if method == 'GET':
                response = await self.client.get(url, **kwargs)
            else:
                response = await self.client.post(url, **kwargs)

            if not response:
                return None

            # Check for SSRF indicators in response
            response_text = response.text.lower()
            for indicator in self.INDICATORS:
                if indicator.lower() in response_text:
                    severity = SeverityLevel.CRITICAL
                    description = f"SSRF vulnerability in {method} parameter '{param_name}'"

                    # Special case for cloud metadata
                    if any(cloud in payload for cloud in ['169.254.169.254', 'metadata.google', 'metadata/instance']):
                        description += " - Cloud metadata access possible"
                        severity = SeverityLevel.CRITICAL

                    return Vulnerability(
                        id=f"ssrf_{method.lower()}_{param_name}_{hash(url)}",
                        title="Server-Side Request Forgery (SSRF)",
                        description=description,
                        severity=severity,
                        category=VulnerabilityCategory.SSRF,
                        affected_url=url,
                        affected_parameter=param_name,
                        proof_of_concept=f"The parameter '{param_name}' allows making requests to internal "
                                       f"or external resources. Indicator '{indicator}' found in response.",
                        payload=payload,
                        remediation="Validate and whitelist allowed URLs/domains. "
                                  "Disable unnecessary protocols (file://, gopher://, etc.). "
                                  "Block access to internal IP ranges and cloud metadata endpoints. "
                                  "Use separate infrastructure for external requests. "
                                  "Implement proper network segmentation.",
                        cwe_id="CWE-918",
                        owasp_category="A10:2021 – Server-Side Request Forgery",
                        references=[
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                        ]
                    )

        except Exception as e:
            logger.debug(f"Error testing SSRF: {e}")

        return None
