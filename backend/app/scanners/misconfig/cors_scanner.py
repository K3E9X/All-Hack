"""
CORS misconfiguration scanner
"""
import logging
from typing import List, Optional
from app.models import Misconfiguration, Vulnerability, SeverityLevel, VulnerabilityCategory
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class CORSScanner:
    """Scan for CORS misconfigurations"""

    ATTACK_ORIGINS = [
        "https://evil.com",
        "http://attacker.com",
        "https://malicious-site.net",
        "null",  # null origin
    ]

    def __init__(self, client: PentestHTTPClient):
        self.client = client

    async def scan(self, endpoints: List[str]) -> List[Misconfiguration]:
        """Scan for CORS misconfigurations"""
        misconfigurations = []

        # Test main domain
        vulns = await self._test_cors("/")
        misconfigurations.extend(vulns)

        # Test API endpoints
        api_endpoints = [ep for ep in endpoints if '/api' in ep.lower()]
        for endpoint in api_endpoints[:10]:  # Limit to avoid too many requests
            vulns = await self._test_cors(endpoint)
            misconfigurations.extend(vulns)
            if vulns:
                break  # If we found issues, no need to test all endpoints

        return misconfigurations

    async def _test_cors(self, endpoint: str) -> List[Misconfiguration]:
        """Test CORS configuration for a specific endpoint"""
        misconfigurations = []

        try:
            # Test 1: Wildcard origin (*)
            response = await self.client.get(endpoint)
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')

                # Wildcard with credentials is dangerous
                if acao == '*' and acac.lower() == 'true':
                    misconfigurations.append(Misconfiguration(
                        title="Critical CORS Misconfiguration: Wildcard with Credentials",
                        description="Access-Control-Allow-Origin is set to '*' with credentials enabled",
                        severity=SeverityLevel.CRITICAL,
                        affected_component=f"CORS Headers on {endpoint}",
                        current_value=f"Origin: {acao}, Credentials: {acac}",
                        recommended_value="Specify exact origins, avoid wildcard with credentials",
                        remediation="Never use Access-Control-Allow-Origin: * with "
                                  "Access-Control-Allow-Credentials: true. "
                                  "Whitelist specific trusted origins instead."
                    ))
                elif acao == '*':
                    misconfigurations.append(Misconfiguration(
                        title="CORS Misconfiguration: Wildcard Origin",
                        description="Access-Control-Allow-Origin is set to '*'",
                        severity=SeverityLevel.MEDIUM,
                        affected_component=f"CORS Headers on {endpoint}",
                        current_value=f"Access-Control-Allow-Origin: *",
                        recommended_value="Whitelist specific trusted origins",
                        remediation="Avoid using wildcard (*) for Access-Control-Allow-Origin. "
                                  "Implement a whitelist of trusted origins."
                    ))

            # Test 2: Origin reflection
            for test_origin in self.ATTACK_ORIGINS:
                response = await self.client.get(
                    endpoint,
                    headers={'Origin': test_origin}
                )

                if response:
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')

                    # Check if attacker origin is reflected
                    if acao == test_origin:
                        severity = SeverityLevel.CRITICAL if acac.lower() == 'true' else SeverityLevel.HIGH

                        misconfigurations.append(Misconfiguration(
                            title="CORS Misconfiguration: Reflected Origin",
                            description=f"Server reflects arbitrary origins in Access-Control-Allow-Origin",
                            severity=severity,
                            affected_component=f"CORS Headers on {endpoint}",
                            current_value=f"Reflected origin: {test_origin}",
                            recommended_value="Whitelist specific trusted origins, validate Origin header",
                            remediation="Do not blindly reflect the Origin header. "
                                      "Implement strict origin validation against a whitelist. "
                                      "Never reflect untrusted origins with credentials enabled."
                        ))
                        break  # Found the issue

            # Test 3: Null origin
            response = await self.client.get(
                endpoint,
                headers={'Origin': 'null'}
            )
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                if acao == 'null':
                    misconfigurations.append(Misconfiguration(
                        title="CORS Misconfiguration: Null Origin Allowed",
                        description="Server allows 'null' origin, which can be exploited",
                        severity=SeverityLevel.HIGH,
                        affected_component=f"CORS Headers on {endpoint}",
                        current_value="Access-Control-Allow-Origin: null",
                        recommended_value="Reject null origin",
                        remediation="Never allow 'null' as an origin. "
                                  "Null origin can be triggered by sandboxed iframes and data: URIs."
                    ))

            # Test 4: Pre-flight request handling
            response = await self.client.options(
                endpoint,
                headers={
                    'Origin': 'https://evil.com',
                    'Access-Control-Request-Method': 'DELETE',
                    'Access-Control-Request-Headers': 'X-Custom-Header'
                }
            )
            if response:
                acam = response.headers.get('Access-Control-Allow-Methods', '')
                if 'DELETE' in acam or 'PUT' in acam or '*' in acam:
                    misconfigurations.append(Misconfiguration(
                        title="CORS: Dangerous Methods Allowed",
                        description="CORS allows dangerous HTTP methods (DELETE, PUT)",
                        severity=SeverityLevel.MEDIUM,
                        affected_component=f"CORS Headers on {endpoint}",
                        current_value=f"Access-Control-Allow-Methods: {acam}",
                        recommended_value="Only allow necessary methods (GET, POST)",
                        remediation="Restrict Access-Control-Allow-Methods to only necessary HTTP methods. "
                                  "Avoid allowing DELETE, PUT unless absolutely required."
                    ))

        except Exception as e:
            logger.error(f"Error testing CORS: {e}")

        return misconfigurations
