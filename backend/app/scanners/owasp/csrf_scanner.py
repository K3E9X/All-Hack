"""
Cross-Site Request Forgery (CSRF) Scanner

Detects missing or weak CSRF protection on state-changing operations.
"""
import asyncio
import logging
import re
from typing import List, Optional, Dict, Any, Callable
from urllib.parse import urlparse, parse_qs
from app.models import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class CSRFScanner:
    """
    Comprehensive CSRF vulnerability scanner

    Tests for:
    - Missing CSRF tokens on POST/PUT/DELETE/PATCH
    - Weak/predictable CSRF tokens
    - Token reuse vulnerabilities
    - Missing SameSite cookie attribute
    - Missing Referer validation
    """

    # Common CSRF token parameter names
    CSRF_TOKEN_NAMES = [
        'csrf_token', 'csrf', '_csrf', 'csrftoken', 'csrf-token',
        '_token', 'token', 'authenticity_token', '__requestverificationtoken',
        'anti_csrf_token', 'xsrf_token', 'xsrf', '_xsrf',
    ]

    # State-changing endpoints (high priority for CSRF testing)
    STATE_CHANGING_PATTERNS = [
        r'/delete', r'/remove', r'/update', r'/edit', r'/create',
        r'/post', r'/add', r'/modify', r'/change', r'/submit',
        r'/transfer', r'/send', r'/payment', r'/checkout',
        r'/admin', r'/settings', r'/profile', r'/account',
        r'/api/.*/delete', r'/api/.*/update', r'/api/.*/create'
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

        # Scan depth configuration
        if scan_depth == "quick":
            self.max_endpoints_to_test = 10
            self.test_token_reuse = False
            self.test_referer = False
        elif scan_depth == "balanced":
            self.max_endpoints_to_test = 30
            self.test_token_reuse = True
            self.test_referer = True
        else:  # deep
            self.max_endpoints_to_test = 100
            self.test_token_reuse = True
            self.test_referer = True

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """
        Scan for CSRF vulnerabilities

        Args:
            endpoints: List of discovered endpoints

        Returns:
            List of CSRF vulnerabilities found
        """
        vulnerabilities = []

        logger.info(f"🔒 CSRF Scanner started - Mode: {self.scan_depth}")

        # Filter to state-changing endpoints
        state_changing_endpoints = self._find_state_changing_endpoints(endpoints)

        if not state_changing_endpoints:
            logger.info("No state-changing endpoints found for CSRF testing")
            return vulnerabilities

        logger.info(f"Found {len(state_changing_endpoints)} potential state-changing endpoints")

        # Test endpoints
        endpoints_to_test = state_changing_endpoints[:self.max_endpoints_to_test]

        for i, endpoint in enumerate(endpoints_to_test):
            if self.progress_callback:
                await self.progress_callback(
                    f"CSRF: Testing endpoint {i+1}/{len(endpoints_to_test)}: {endpoint}"
                )

            # Test missing CSRF token
            vulns = await self._test_missing_csrf_token(endpoint)
            vulnerabilities.extend(vulns)

            # Test weak CSRF token (if token exists)
            if self.test_token_reuse:
                vulns = await self._test_weak_csrf_token(endpoint)
                vulnerabilities.extend(vulns)

            # Test SameSite cookie attribute
            vulns = await self._test_samesite_cookies(endpoint)
            vulnerabilities.extend(vulns)

            await asyncio.sleep(0.1)  # Rate limiting

        # Test Referer validation
        if self.test_referer:
            vulns = await self._test_referer_validation(endpoints_to_test)
            vulnerabilities.extend(vulns)

        logger.info(f"✅ CSRF scan complete: {len(vulnerabilities)} vulnerabilities found")
        return vulnerabilities

    def _find_state_changing_endpoints(self, endpoints: List[str]) -> List[str]:
        """
        Find endpoints that likely perform state-changing operations
        """
        state_changing = []

        for endpoint in endpoints:
            # Check if URL matches state-changing patterns
            for pattern in self.STATE_CHANGING_PATTERNS:
                if re.search(pattern, endpoint.lower()):
                    state_changing.append(endpoint)
                    break

        return state_changing

    async def _test_missing_csrf_token(self, endpoint: str) -> List[Vulnerability]:
        """
        Test for missing CSRF tokens on state-changing operations
        """
        vulnerabilities = []

        # Test POST request without CSRF token
        for method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            try:
                # First, get the form to check if CSRF token is expected
                get_response = await self.client.get(endpoint)
                if not get_response:
                    continue

                # Check if form expects CSRF token
                has_csrf_field = self._has_csrf_field_in_html(get_response.text)

                # Try state-changing operation without token
                response = None
                if method == 'POST':
                    response = await self.client.post(endpoint, data={"test": "csrf_test"})
                elif method == 'PUT':
                    response = await self.client.put(endpoint, json={"test": "csrf_test"})
                elif method == 'DELETE':
                    response = await self.client.delete(endpoint)
                elif method == 'PATCH':
                    response = await self.client.patch(endpoint, json={"test": "csrf_test"})

                if not response:
                    continue

                # If request succeeds (2xx) without CSRF token, it's vulnerable
                if 200 <= response.status_code < 300:
                    # Check if it's a real success (not just returning form again)
                    if not self._is_form_resubmission(response.text, get_response.text):
                        vulnerabilities.append(Vulnerability(
                            id=f"csrf_missing_{method}_{hash(endpoint)}",
                            title=f"Missing CSRF Protection on {method} Request",
                            description=f"The endpoint accepts {method} requests without CSRF token validation. "
                                      f"An attacker can craft a malicious website that triggers unauthorized actions "
                                      f"on behalf of an authenticated user.",
                            severity=SeverityLevel.HIGH if has_csrf_field else SeverityLevel.MEDIUM,
                            category=VulnerabilityCategory.CSRF,
                            affected_url=endpoint,
                            proof_of_concept=f"1. Visit attacker-controlled site while logged into the application\n"
                                           f"2. Attacker's page makes {method} request to: {endpoint}\n"
                                           f"3. Request succeeds without CSRF token (HTTP {response.status_code})\n\n"
                                           f"PoC HTML:\n"
                                           f"<form action=\"{endpoint}\" method=\"{method.upper()}\">\n"
                                           f"  <input name=\"malicious\" value=\"data\">\n"
                                           f"  <input type=\"submit\">\n"
                                           f"</form>\n"
                                           f"<script>document.forms[0].submit()</script>",
                            remediation="Implement CSRF protection:\n\n"
                                      "1. **Synchronizer Token Pattern:**\n"
                                      "   - Generate unique, unpredictable token per session\n"
                                      "   - Include token in all state-changing forms\n"
                                      "   - Validate token server-side before processing\n\n"
                                      "2. **SameSite Cookie Attribute:**\n"
                                      "   - Set SameSite=Strict or SameSite=Lax on session cookies\n"
                                      "   - Prevents cookie from being sent in cross-site requests\n\n"
                                      "3. **Custom Request Headers:**\n"
                                      "   - Require custom header (e.g., X-Requested-With: XMLHttpRequest)\n"
                                      "   - CORS prevents cross-site JavaScript from adding custom headers\n\n"
                                      "4. **Double Submit Cookie:**\n"
                                      "   - Send token in both cookie and request parameter\n"
                                      "   - Verify they match server-side\n\n"
                                      "5. **Referer Validation:**\n"
                                      "   - Check Referer header matches your domain (not sufficient alone)\n\n"
                                      "Example (Python/Flask):\n"
                                      "```python\n"
                                      "from flask_wtf.csrf import CSRFProtect\n"
                                      "csrf = CSRFProtect(app)\n"
                                      "```",
                            cwe_id="CWE-352",
                            owasp_category="A01:2021 – Broken Access Control",
                            references=[
                                "https://owasp.org/www-community/attacks/csrf",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                                "https://portswigger.net/web-security/csrf"
                            ]
                        ))

                        logger.info(f"🚨 CSRF vulnerability found: {method} {endpoint}")
                        break  # One vuln per endpoint is enough

            except Exception as e:
                logger.debug(f"Error testing {method} {endpoint}: {e}")

        return vulnerabilities

    async def _test_weak_csrf_token(self, endpoint: str) -> List[Vulnerability]:
        """
        Test for weak or predictable CSRF tokens
        """
        vulnerabilities = []

        try:
            # Get two tokens
            response1 = await self.client.get(endpoint)
            if not response1:
                return vulnerabilities

            token1 = self._extract_csrf_token(response1.text)
            if not token1:
                return vulnerabilities

            await asyncio.sleep(0.5)

            response2 = await self.client.get(endpoint)
            if not response2:
                return vulnerabilities

            token2 = self._extract_csrf_token(response2.text)
            if not token2:
                return vulnerabilities

            # Check if tokens are the same (token reuse vulnerability)
            if token1 == token2:
                vulnerabilities.append(Vulnerability(
                    id=f"csrf_weak_token_{hash(endpoint)}",
                    title="CSRF Token Reuse Vulnerability",
                    description="The same CSRF token is reused across multiple requests. "
                              "This weakens the protection as tokens should be unique per request or session.",
                    severity=SeverityLevel.MEDIUM,
                    category=VulnerabilityCategory.CSRF,
                    affected_url=endpoint,
                    proof_of_concept=f"1. Request endpoint twice: GET {endpoint}\n"
                                   f"2. Both requests return same token: {token1}\n"
                                   f"3. Token is predictable and can be reused",
                    remediation="Generate unique CSRF tokens per request or session:\n"
                              "- Use cryptographically secure random generation\n"
                              "- Regenerate token after state-changing operations\n"
                              "- Set token expiration time\n"
                              "- Invalidate token after use",
                    cwe_id="CWE-352",
                    owasp_category="A01:2021 – Broken Access Control"
                ))

            # Check if token looks weak (too short, predictable pattern)
            if len(token1) < 16:
                vulnerabilities.append(Vulnerability(
                    id=f"csrf_short_token_{hash(endpoint)}",
                    title="Weak CSRF Token - Too Short",
                    description=f"CSRF token is only {len(token1)} characters long. "
                              f"Tokens should be at least 32 characters to prevent brute-force attacks.",
                    severity=SeverityLevel.MEDIUM,
                    category=VulnerabilityCategory.CSRF,
                    affected_url=endpoint,
                    proof_of_concept=f"Token length: {len(token1)} characters\n"
                                   f"Token value: {token1}\n"
                                   f"Recommended: >= 32 characters",
                    remediation="Use longer, cryptographically secure tokens:\n"
                              "- Minimum 32 characters (128 bits of entropy)\n"
                              "- Use secure random generators (e.g., secrets.token_urlsafe())\n"
                              "- Avoid sequential or predictable patterns",
                    cwe_id="CWE-330",
                    owasp_category="A02:2021 – Cryptographic Failures"
                ))

        except Exception as e:
            logger.debug(f"Error testing weak CSRF token for {endpoint}: {e}")

        return vulnerabilities

    async def _test_samesite_cookies(self, endpoint: str) -> List[Vulnerability]:
        """
        Test for missing SameSite attribute on session cookies
        """
        vulnerabilities = []

        try:
            response = await self.client.get(endpoint)
            if not response:
                return vulnerabilities

            # Check Set-Cookie headers
            cookies = response.headers.get_list('Set-Cookie')

            for cookie in cookies:
                cookie_lower = cookie.lower()

                # Check if it's a session cookie (contains common session names)
                is_session_cookie = any(
                    name in cookie_lower
                    for name in ['session', 'sessionid', 'sess', 'jsessionid', 'phpsessid', 'asp.net_sessionid']
                )

                if is_session_cookie:
                    # Check for SameSite attribute
                    if 'samesite=' not in cookie_lower:
                        vulnerabilities.append(Vulnerability(
                            id=f"csrf_no_samesite_{hash(endpoint)}",
                            title="Missing SameSite Cookie Attribute",
                            description="Session cookie does not have SameSite attribute. "
                                      "This allows the cookie to be sent in cross-site requests, "
                                      "making CSRF attacks easier.",
                            severity=SeverityLevel.MEDIUM,
                            category=VulnerabilityCategory.CSRF,
                            affected_url=endpoint,
                            proof_of_concept=f"Cookie header: {cookie[:100]}...\n"
                                           f"Missing: SameSite attribute\n"
                                           f"Impact: Cookie sent in cross-site requests",
                            remediation="Add SameSite attribute to session cookies:\n\n"
                                      "**Option 1: SameSite=Strict (Most Secure)**\n"
                                      "Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly\n"
                                      "- Cookie never sent in cross-site requests\n"
                                      "- Best for high-security applications\n\n"
                                      "**Option 2: SameSite=Lax (Balanced)**\n"
                                      "Set-Cookie: session=...; SameSite=Lax; Secure; HttpOnly\n"
                                      "- Cookie sent on top-level navigation (GET links)\n"
                                      "- Not sent on POST cross-site requests\n"
                                      "- Good balance for most applications",
                            cwe_id="CWE-352",
                            owasp_category="A01:2021 – Broken Access Control",
                            references=[
                                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                            ]
                        ))

        except Exception as e:
            logger.debug(f"Error testing SameSite cookies for {endpoint}: {e}")

        return vulnerabilities

    async def _test_referer_validation(self, endpoints: List[str]) -> List[Vulnerability]:
        """
        Test if Referer header is validated
        """
        vulnerabilities = []

        if not endpoints:
            return vulnerabilities

        try:
            # Pick one endpoint to test
            test_endpoint = endpoints[0]

            # Try POST with malicious Referer
            response = await self.client.post(
                test_endpoint,
                data={"test": "referer_test"},
                headers={"Referer": "https://attacker.com/malicious"}
            )

            if response and 200 <= response.status_code < 300:
                vulnerabilities.append(Vulnerability(
                    id=f"csrf_weak_referer_{hash(test_endpoint)}",
                    title="Missing or Weak Referer Validation",
                    description="The application accepts requests with arbitrary Referer headers. "
                              "This indicates that Referer validation is not implemented or is insufficient.",
                    severity=SeverityLevel.LOW,
                    category=VulnerabilityCategory.CSRF,
                    affected_url=test_endpoint,
                    proof_of_concept=f"POST request with Referer: https://attacker.com/malicious\n"
                                   f"Response: HTTP {response.status_code} (accepted)\n"
                                   f"Expected: 403 Forbidden",
                    remediation="While Referer validation alone is NOT sufficient for CSRF protection, "
                              "it can be used as a defense-in-depth measure:\n"
                              "1. Check Referer header matches your domain\n"
                              "2. Reject requests with missing or mismatched Referer\n"
                              "3. **Important**: Use alongside CSRF tokens, not as replacement\n"
                              "4. Be aware: Referer can be suppressed by privacy tools",
                    cwe_id="CWE-352",
                    owasp_category="A01:2021 – Broken Access Control"
                ))

        except Exception as e:
            logger.debug(f"Error testing Referer validation: {e}")

        return vulnerabilities

    def _has_csrf_field_in_html(self, html: str) -> bool:
        """Check if HTML contains CSRF token fields"""
        html_lower = html.lower()
        return any(name in html_lower for name in self.CSRF_TOKEN_NAMES)

    def _is_form_resubmission(self, response_html: str, original_html: str) -> bool:
        """Check if response is just form resubmission (not actual success)"""
        # Simple heuristic: if response HTML is very similar to original, it's likely the form again
        return len(response_html) > 0 and (
            response_html == original_html or
            len(set(response_html.split()) & set(original_html.split())) > len(original_html.split()) * 0.8
        )

    def _extract_csrf_token(self, html: str) -> Optional[str]:
        """
        Extract CSRF token from HTML
        """
        # Try to find CSRF token in input fields
        for token_name in self.CSRF_TOKEN_NAMES:
            # Try name="csrf_token" value="..."
            pattern = rf'name=["\']?{re.escape(token_name)}["\']?[^>]*value=["\']([^"\']+)["\']'
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)

            # Try value="..." name="csrf_token"
            pattern = rf'value=["\']([^"\']+)["\'][^>]*name=["\']?{re.escape(token_name)}["\']?'
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)

        return None
