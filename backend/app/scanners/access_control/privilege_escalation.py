"""
Privilege Escalation detection scanner
"""
import asyncio
import logging
from typing import List, Dict, Any, Optional
from app.models import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class PrivilegeEscalationScanner:
    """Detect vertical and horizontal privilege escalation vulnerabilities"""

    # Admin/privileged endpoints to test
    PRIVILEGED_ENDPOINTS = [
        '/admin',
        '/admin/dashboard',
        '/admin/users',
        '/admin/settings',
        '/admin/config',
        '/api/admin',
        '/api/admin/users',
        '/administrator',
        '/dashboard/admin',
        '/management',
        '/superuser',
        '/moderator',
        '/staff',
    ]

    # Privileged actions
    PRIVILEGED_ACTIONS = [
        ('DELETE', 'user deletion'),
        ('PUT', 'user modification'),
        ('PATCH', 'user modification'),
    ]

    def __init__(self, client: PentestHTTPClient, low_priv_client: Optional[PentestHTTPClient] = None):
        self.client = client  # Main authenticated client
        self.low_priv_client = low_priv_client  # Lower privilege client for testing

    async def scan(
        self,
        endpoints: List[str],
        test_users: Optional[List[Dict[str, str]]] = None
    ) -> List[Vulnerability]:
        """
        Scan for privilege escalation vulnerabilities

        Args:
            endpoints: Discovered endpoints
            test_users: List of test users with different privilege levels
                       [{"username": "admin", "token": "...", "role": "admin"}, ...]
        """
        vulnerabilities = []

        # Test vertical privilege escalation (low priv -> admin)
        if self.low_priv_client:
            vulns = await self._test_vertical_escalation(endpoints)
            vulnerabilities.extend(vulns)

        # Test missing function level access control
        vulns = await self._test_function_level_access()
        vulnerabilities.extend(vulns)

        # Test role manipulation
        vulns = await self._test_role_manipulation(endpoints)
        vulnerabilities.extend(vulns)

        return vulnerabilities

    async def _test_vertical_escalation(self, endpoints: List[str]) -> List[Vulnerability]:
        """Test for vertical privilege escalation"""
        vulnerabilities = []

        # Find admin/privileged endpoints
        admin_endpoints = [ep for ep in endpoints if any(
            priv in ep.lower() for priv in ['admin', 'manage', 'staff', 'moderator']
        )]

        for endpoint in admin_endpoints:
            # Try accessing with low privilege account
            response = await self.low_priv_client.get(endpoint)

            if response and response.status_code == 200:
                vulnerabilities.append(Vulnerability(
                    id=f"privesc_vertical_{hash(endpoint)}",
                    title="Vertical Privilege Escalation",
                    description="Low-privileged user can access administrative functionality",
                    severity=SeverityLevel.CRITICAL,
                    category=VulnerabilityCategory.PRIVILEGE_ESCALATION,
                    affected_url=endpoint,
                    proof_of_concept=f"Low-privileged account successfully accessed admin endpoint: {endpoint}. "
                                   f"Response status: 200 OK",
                    remediation="Implement proper role-based access control (RBAC). "
                              "Verify user permissions server-side for every request. "
                              "Never rely on client-side checks. "
                              "Use principle of least privilege. "
                              "Implement proper authorization middleware.",
                    cwe_id="CWE-269",
                    owasp_category="A01:2021 – Broken Access Control",
                    references=[
                        "https://owasp.org/www-community/attacks/Privilege_escalation",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
                    ]
                ))

        return vulnerabilities

    async def _test_function_level_access(self) -> List[Vulnerability]:
        """Test for missing function-level access control"""
        vulnerabilities = []

        for endpoint in self.PRIVILEGED_ENDPOINTS:
            # Test without authentication
            response = await self.client.get(endpoint)

            if response and response.status_code not in [401, 403, 404]:
                severity = SeverityLevel.CRITICAL if response.status_code == 200 else SeverityLevel.HIGH

                vulnerabilities.append(Vulnerability(
                    id=f"missing_func_access_{hash(endpoint)}",
                    title="Missing Function Level Access Control",
                    description=f"Administrative endpoint accessible without proper authorization",
                    severity=severity,
                    category=VulnerabilityCategory.BROKEN_ACCESS,
                    affected_url=endpoint,
                    proof_of_concept=f"Administrative endpoint {endpoint} returned status {response.status_code} "
                                   f"instead of 401/403, indicating missing or weak access control.",
                    remediation="Implement function-level authorization checks. "
                              "Deny access by default. "
                              "Verify user permissions for every privileged operation. "
                              "Implement role-based access control (RBAC).",
                    cwe_id="CWE-862",
                    owasp_category="A01:2021 – Broken Access Control",
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"
                    ]
                ))

        return vulnerabilities

    async def _test_role_manipulation(self, endpoints: List[str]) -> List[Vulnerability]:
        """Test for role/permission manipulation"""
        vulnerabilities = []

        # Look for user update/profile endpoints
        user_endpoints = [ep for ep in endpoints if any(
            keyword in ep.lower() for keyword in ['user', 'profile', 'account', 'settings']
        )]

        for endpoint in user_endpoints:
            # Try to modify role/permission via different methods
            role_payloads = [
                {'role': 'admin'},
                {'role': 'administrator'},
                {'is_admin': True},
                {'is_staff': True},
                {'permission': 'admin'},
                {'privilege': 'admin'},
                {'user_type': 'admin'},
                {'account_type': 'admin'},
            ]

            for payload in role_payloads:
                # Try PUT
                response = await self.client.put(endpoint, json=payload)
                if response and response.status_code in [200, 201, 204]:
                    vulnerabilities.append(self._create_role_manipulation_vuln(
                        endpoint, 'PUT', payload, response.status_code
                    ))
                    break

                # Try PATCH
                response = await self.client.patch(endpoint, json=payload)
                if response and response.status_code in [200, 201, 204]:
                    vulnerabilities.append(self._create_role_manipulation_vuln(
                        endpoint, 'PATCH', payload, response.status_code
                    ))
                    break

        return vulnerabilities

    def _create_role_manipulation_vuln(
        self,
        endpoint: str,
        method: str,
        payload: Dict[str, Any],
        status_code: int
    ) -> Vulnerability:
        """Create vulnerability for role manipulation"""
        return Vulnerability(
            id=f"role_manip_{method.lower()}_{hash(endpoint)}",
            title="Privilege Escalation via Role Manipulation",
            description="User can modify their own role/privileges",
            severity=SeverityLevel.CRITICAL,
            category=VulnerabilityCategory.PRIVILEGE_ESCALATION,
            affected_url=endpoint,
            proof_of_concept=f"User can modify their role/privileges via {method} request to {endpoint}. "
                           f"Payload: {payload}. Response: {status_code}",
            payload=str(payload),
            remediation="Never allow users to modify their own roles/privileges. "
                      "Implement server-side validation for role changes. "
                      "Require admin authentication for privilege modifications. "
                      "Use whitelist approach for modifiable fields. "
                      "Log all privilege changes for audit.",
            cwe_id="CWE-269",
            owasp_category="A01:2021 – Broken Access Control",
            references=[
                "https://owasp.org/www-community/attacks/Privilege_escalation"
            ]
        )


class HorizontalPrivilegeScanner:
    """Test for horizontal privilege issues (user A accessing user B's data)"""

    def __init__(
        self,
        user_a_client: PentestHTTPClient,
        user_b_client: PentestHTTPClient
    ):
        self.user_a_client = user_a_client
        self.user_b_client = user_b_client

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Test for horizontal privilege violations"""
        vulnerabilities = []

        # Find user-specific endpoints
        user_endpoints = [ep for ep in endpoints if any(
            keyword in ep.lower() for keyword in ['/user/', '/profile/', '/account/', '/api/users/']
        )]

        for endpoint in user_endpoints:
            # User A accesses their data (baseline)
            response_a = await self.user_a_client.get(endpoint)
            if not response_a or response_a.status_code != 200:
                continue

            # User B tries to access User A's endpoint
            response_b = await self.user_b_client.get(endpoint)
            if response_b and response_b.status_code == 200:
                # Check if content is similar (indicating successful unauthorized access)
                if len(response_b.text) > 100:  # Not an empty or error response
                    vulnerabilities.append(Vulnerability(
                        id=f"horizontal_priv_{hash(endpoint)}",
                        title="Broken Access Control - Horizontal Privilege Escalation",
                        description="User can access another user's private data",
                        severity=SeverityLevel.HIGH,
                        category=VulnerabilityCategory.BROKEN_ACCESS,
                        affected_url=endpoint,
                        proof_of_concept="User B successfully accessed User A's private endpoint. "
                                       "Both requests returned 200 OK with content.",
                        remediation="Implement proper session validation. "
                                  "Verify that the authenticated user owns the requested resource. "
                                  "Use user-specific tokens/sessions. "
                                  "Implement ownership checks for all user data access.",
                        cwe_id="CWE-639",
                        owasp_category="A01:2021 – Broken Access Control",
                        references=[
                            "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"
                        ]
                    ))

        return vulnerabilities
