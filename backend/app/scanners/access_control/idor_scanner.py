"""
Insecure Direct Object Reference (IDOR) detection scanner
"""
import asyncio
import logging
import re
from typing import List, Optional, Dict, Any
from app.models import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class IDORScanner:
    """Detect IDOR vulnerabilities"""

    def __init__(self, client: PentestHTTPClient):
        self.client = client

    async def scan(
        self,
        endpoints: List[str],
        authenticated: bool = False,
        test_user_id: Optional[str] = None
    ) -> List[Vulnerability]:
        """
        Scan for IDOR vulnerabilities

        Args:
            endpoints: List of discovered endpoints
            authenticated: Whether we have authentication (grey_box mode)
            test_user_id: Current user's ID (for grey box testing)
        """
        vulnerabilities = []

        # Extract endpoints with numeric IDs
        id_endpoints = self._find_id_endpoints(endpoints)

        if not authenticated:
            # BLACK BOX MODE: Limited tests on public endpoints only
            logger.info(f"🔒 IDOR Scanner - BLACK BOX mode: Testing {len(id_endpoints)} public endpoints")
            public_endpoints = [ep for ep in id_endpoints if not self._is_authenticated_endpoint(ep)]

            for endpoint in public_endpoints[:10]:  # Limit to 10 in black box
                # Basic enumeration test only
                vulns = await self._test_id_enumeration(endpoint)
                vulnerabilities.extend(vulns)
        else:
            # GREY BOX MODE: Comprehensive tests with authentication
            logger.info(f"🔓 IDOR Scanner - GREY BOX mode: Testing {len(id_endpoints)} authenticated endpoints")

            for endpoint in id_endpoints:
                # Test horizontal IDOR (accessing other users' data)
                vulns = await self._test_horizontal_idor(endpoint, test_user_id)
                vulnerabilities.extend(vulns)

                # Test sequential ID enumeration
                vulns = await self._test_id_enumeration(endpoint)
                vulnerabilities.extend(vulns)

                # Grey box exclusive: Test authenticated endpoints manipulation
                if self._is_authenticated_endpoint(endpoint):
                    vulns = await self._test_authenticated_endpoint_idor(endpoint, test_user_id)
                    vulnerabilities.extend(vulns)

        return vulnerabilities

    def _find_id_endpoints(self, endpoints: List[str]) -> List[str]:
        """Find endpoints that contain ID parameters"""
        id_endpoints = []

        # Patterns that suggest an ID parameter
        id_patterns = [
            r'/\d+',  # /users/123
            r'[?&]id=\d+',  # ?id=123
            r'[?&]user_id=\d+',
            r'[?&]account_id=\d+',
            r'[?&]profile_id=\d+',
            r'[?&]post_id=\d+',
            r'[?&]document_id=\d+',
            r'[?&]order_id=\d+',
            r'/user/\d+',
            r'/profile/\d+',
            r'/account/\d+',
            r'/api/users/\d+',
            r'/api/v\d+/users/\d+',
        ]

        for endpoint in endpoints:
            for pattern in id_patterns:
                if re.search(pattern, endpoint):
                    id_endpoints.append(endpoint)
                    break

        return id_endpoints

    async def _test_horizontal_idor(
        self,
        endpoint: str,
        current_user_id: Optional[str]
    ) -> List[Vulnerability]:
        """Test for horizontal IDOR (accessing other users' data)"""
        vulnerabilities = []

        # Extract current ID from endpoint
        current_id = self._extract_id(endpoint)
        if not current_id:
            return vulnerabilities

        # Test with different user IDs
        test_ids = self._generate_test_ids(current_id)

        # Get baseline response with current ID
        baseline_response = await self.client.get(endpoint)
        if not baseline_response or baseline_response.status_code in [404, 403, 401]:
            return vulnerabilities

        baseline_length = len(baseline_response.text)

        # Test other IDs
        for test_id in test_ids:
            modified_endpoint = self._replace_id(endpoint, test_id)

            response = await self.client.get(modified_endpoint)
            if not response:
                continue

            # If we get 200 OK with similar content length, it's likely IDOR
            if response.status_code == 200:
                response_length = len(response.text)

                # Check if response is similar (not empty, not error page)
                if 0.5 < (response_length / baseline_length) < 2.0:
                    vulnerabilities.append(Vulnerability(
                        id=f"idor_horizontal_{hash(endpoint)}",
                        title="Insecure Direct Object Reference (IDOR) - Horizontal",
                        description="Horizontal privilege escalation via IDOR - accessing other users' data",
                        severity=SeverityLevel.HIGH,
                        category=VulnerabilityCategory.IDOR,
                        affected_url=endpoint,
                        proof_of_concept=f"By changing the ID from {current_id} to {test_id}, "
                                       f"unauthorized access to other users' data is possible. "
                                       f"Both requests returned 200 OK with similar content.",
                        payload=f"Modified ID: {test_id}",
                        remediation="Implement proper authorization checks. "
                                  "Verify that the authenticated user has permission to access the requested resource. "
                                  "Use indirect references (like UUIDs or encrypted IDs). "
                                  "Implement access control lists (ACLs). "
                                  "Never rely solely on ID obscurity for security.",
                        cwe_id="CWE-639",
                        owasp_category="A01:2021 – Broken Access Control",
                        references=[
                            "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
                        ]
                    ))
                    break  # Found vulnerability, no need to test more IDs

        return vulnerabilities

    async def _test_id_enumeration(self, endpoint: str) -> List[Vulnerability]:
        """Test for sequential ID enumeration"""
        vulnerabilities = []

        current_id = self._extract_id(endpoint)
        if not current_id:
            return vulnerabilities

        # Test sequential IDs
        accessible_count = 0
        test_range = 5  # Test 5 sequential IDs

        for i in range(int(current_id) - test_range, int(current_id) + test_range + 1):
            if i <= 0:
                continue

            modified_endpoint = self._replace_id(endpoint, str(i))
            response = await self.client.get(modified_endpoint)

            if response and response.status_code == 200:
                accessible_count += 1

        # If most sequential IDs are accessible, it's enumerable
        if accessible_count >= test_range:
            vulnerabilities.append(Vulnerability(
                id=f"idor_enumeration_{hash(endpoint)}",
                title="Resource Enumeration via Sequential IDs",
                description="Sequential resource IDs allow enumeration of all resources",
                severity=SeverityLevel.MEDIUM,
                category=VulnerabilityCategory.BROKEN_ACCESS,
                affected_url=endpoint,
                proof_of_concept=f"Sequential IDs from {int(current_id) - test_range} to "
                               f"{int(current_id) + test_range} are accessible. "
                               f"This allows enumeration of all resources.",
                remediation="Use non-sequential, unpredictable identifiers (UUIDs). "
                          "Implement rate limiting. "
                          "Add proper authorization checks. "
                          "Consider using indirect references.",
                cwe_id="CWE-639",
                owasp_category="A01:2021 – Broken Access Control",
                references=[
                    "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"
                ]
            ))

        return vulnerabilities

    def _extract_id(self, endpoint: str) -> Optional[str]:
        """Extract numeric ID from endpoint"""
        # Try path-based ID
        match = re.search(r'/(\d+)(?:/|$|\?)', endpoint)
        if match:
            return match.group(1)

        # Try query parameter
        match = re.search(r'[?&](?:id|user_id|account_id|profile_id)=(\d+)', endpoint)
        if match:
            return match.group(1)

        return None

    def _replace_id(self, endpoint: str, new_id: str) -> str:
        """Replace ID in endpoint with new value"""
        # Try path-based replacement
        if re.search(r'/\d+(?:/|$|\?)', endpoint):
            return re.sub(r'/\d+(?=/|$|\?)', f'/{new_id}', endpoint, count=1)

        # Try query parameter replacement
        for param in ['id', 'user_id', 'account_id', 'profile_id']:
            pattern = f'([?&]{param}=)\\d+'
            if re.search(pattern, endpoint):
                return re.sub(pattern, f'\\g<1>{new_id}', endpoint, count=1)

        return endpoint

    def _generate_test_ids(self, current_id: str) -> List[str]:
        """Generate test IDs for IDOR testing"""
        try:
            current = int(current_id)
            return [
                str(current - 1),
                str(current + 1),
                str(current - 10),
                str(current + 10),
                "1",
                "2",
                "999",
                "1000",
            ]
        except ValueError:
            return ["1", "2", "999"]

    def _is_authenticated_endpoint(self, endpoint: str) -> bool:
        """
        Determine if an endpoint requires authentication (Grey Box)

        Authenticated endpoints typically include:
        - User-specific resources (profile, settings, dashboard)
        - Admin/management endpoints
        - API endpoints for user data
        """
        authenticated_patterns = [
            r'/profile',
            r'/dashboard',
            r'/settings',
            r'/account',
            r'/user/\d+',
            r'/api/user',
            r'/api/users/\d+',
            r'/api/me',
            r'/my',
            r'/admin',
            r'/manage',
            r'/orders',
            r'/purchases',
            r'/documents',
            r'/private',
            r'/secure',
        ]

        endpoint_lower = endpoint.lower()
        return any(re.search(pattern, endpoint_lower) for pattern in authenticated_patterns)

    async def _test_authenticated_endpoint_idor(
        self,
        endpoint: str,
        current_user_id: Optional[str]
    ) -> List[Vulnerability]:
        """
        Grey Box Exclusive: Test IDOR on authenticated endpoints

        This tests if the authenticated user can access/modify other users' resources
        by manipulating IDs in authenticated endpoints (profile, orders, documents, etc.)
        """
        vulnerabilities = []

        current_id = self._extract_id(endpoint)
        if not current_id:
            return vulnerabilities

        # Get baseline with current user's ID
        baseline_response = await self.client.get(endpoint)
        if not baseline_response or baseline_response.status_code not in [200, 201]:
            return vulnerabilities

        baseline_content = baseline_response.text

        # Test with other user IDs (attempting to access other users' data while authenticated)
        test_ids = [
            str(int(current_id) - 1),
            str(int(current_id) + 1),
            "1",  # First user
            "2",  # Second user
            "100",  # Random user
        ]

        for test_id in test_ids:
            if test_id == current_id:
                continue

            modified_endpoint = self._replace_id(endpoint, test_id)

            # Test GET access
            response = await self.client.get(modified_endpoint)
            if response and response.status_code == 200:
                # Check if we got different user's data
                if len(response.text) > 100 and response.text != baseline_content:
                    vulnerabilities.append(Vulnerability(
                        id=f"idor_auth_{hash(modified_endpoint)}",
                        title="IDOR on Authenticated Endpoint - Data Exposure",
                        description=f"Authenticated user can access other users' sensitive data by manipulating ID parameters",
                        severity=SeverityLevel.CRITICAL,
                        category=VulnerabilityCategory.IDOR,
                        affected_url=endpoint,
                        proof_of_concept=f"While authenticated, changing ID from {current_id} to {test_id} "
                                       f"in endpoint {endpoint} allows unauthorized access to other users' data. "
                                       f"This is a critical IDOR vulnerability in an authenticated context.",
                        payload=f"Modified authenticated endpoint: {modified_endpoint}",
                        remediation="CRITICAL: Implement server-side authorization checks. "
                                  "Verify that the authenticated user owns or has permission to access the requested resource. "
                                  "Use session user ID from the auth token, never trust client-provided IDs. "
                                  "Example: SELECT * FROM users WHERE id = ? AND user_id = session.user_id",
                        cwe_id="CWE-639",
                        owasp_category="A01:2021 – Broken Access Control",
                        references=[
                            "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
                        ]
                    ))
                    break

            # Test PUT/PATCH modification (Grey box can test write operations)
            # Test PUT
            response = await self.client.put(modified_endpoint, json={"test": "idor_test"})
            if response and response.status_code in [200, 201, 204]:
                vulnerabilities.append(Vulnerability(
                    id=f"idor_write_PUT_{hash(modified_endpoint)}",
                    title=f"IDOR on Authenticated Endpoint - Unauthorized PUT",
                    description=f"Authenticated user can modify other users' data via PUT requests",
                    severity=SeverityLevel.CRITICAL,
                    category=VulnerabilityCategory.IDOR,
                    affected_url=endpoint,
                    proof_of_concept=f"While authenticated, PUT request to {modified_endpoint} "
                                   f"(other user's ID: {test_id}) was successful (HTTP {response.status_code}). "
                                   f"This allows unauthorized modification of other users' resources.",
                    payload=f"PUT {modified_endpoint}",
                    remediation="CRITICAL: Implement proper authorization for write operations. "
                              "Verify ownership before allowing updates. "
                              "Use server-side session validation. "
                              "Log all unauthorized access attempts.",
                    cwe_id="CWE-639",
                    owasp_category="A01:2021 – Broken Access Control"
                ))
                break

            # Test PATCH
            response = await self.client.patch(modified_endpoint, json={"test": "idor_test"})
            if response and response.status_code in [200, 201, 204]:
                vulnerabilities.append(Vulnerability(
                    id=f"idor_write_PATCH_{hash(modified_endpoint)}",
                    title=f"IDOR on Authenticated Endpoint - Unauthorized PATCH",
                    description=f"Authenticated user can modify other users' data via PATCH requests",
                    severity=SeverityLevel.CRITICAL,
                    category=VulnerabilityCategory.IDOR,
                    affected_url=endpoint,
                    proof_of_concept=f"While authenticated, PATCH request to {modified_endpoint} "
                                   f"(other user's ID: {test_id}) was successful (HTTP {response.status_code}). "
                                   f"This allows unauthorized modification of other users' resources.",
                    payload=f"PATCH {modified_endpoint}",
                    remediation="CRITICAL: Implement proper authorization for write operations. "
                              "Verify ownership before allowing updates. "
                              "Use server-side session validation. "
                              "Log all unauthorized access attempts.",
                    cwe_id="CWE-639",
                    owasp_category="A01:2021 – Broken Access Control"
                ))
                break

        return vulnerabilities
