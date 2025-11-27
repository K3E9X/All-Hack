"""
Clickjacking Scanner

Detects missing or weak frame protection allowing clickjacking attacks.
"""
import asyncio
import logging
from typing import List, Optional, Callable
from app.models import Vulnerability, SeverityLevel, VulnerabilityCategory, Misconfiguration
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class ClickjackingScanner:
    """
    Scanner for clickjacking vulnerabilities

    Tests for:
    - Missing X-Frame-Options header
    - Weak X-Frame-Options configuration
    - Missing Content-Security-Policy frame-ancestors
    - Clickjacking on sensitive pages (login, payment, admin)
    """

    # Sensitive pages that should have frame protection
    SENSITIVE_PAGES = [
        '/login', '/signin', '/auth', '/authenticate',
        '/register', '/signup',
        '/payment', '/checkout', '/pay', '/billing',
        '/transfer', '/send', '/deposit', '/withdraw',
        '/admin', '/dashboard', '/panel',
        '/settings', '/profile', '/account',
        '/delete', '/remove', '/update',
        '/api/login', '/api/auth', '/api/payment'
    ]

    def __init__(
        self,
        client: PentestHTTPClient,
        progress_callback: Optional[Callable] = None
    ):
        self.client = client
        self.progress_callback = progress_callback

    async def scan(self, endpoints: Optional[List[str]] = None) -> List[Misconfiguration]:
        """
        Scan for clickjacking vulnerabilities

        Args:
            endpoints: List of discovered endpoints (optional, will test common ones if not provided)

        Returns:
            List of clickjacking misconfigurations found
        """
        misconfigurations = []

        logger.info("🖼️  Clickjacking Scanner started")

        # Determine pages to test
        pages_to_test = []

        if endpoints:
            # Test sensitive endpoints from discovered list
            for endpoint in endpoints:
                if any(sensitive in endpoint.lower() for sensitive in self.SENSITIVE_PAGES):
                    pages_to_test.append(endpoint)

        # Always test common sensitive pages
        base_url = self.client.base_url
        for sensitive_page in self.SENSITIVE_PAGES[:15]:  # Test top 15 common pages
            full_url = f"{base_url}{sensitive_page}"
            if full_url not in pages_to_test:
                pages_to_test.append(full_url)

        if not pages_to_test:
            pages_to_test = [base_url]  # At least test root

        logger.info(f"Testing {len(pages_to_test)} pages for clickjacking")

        # Test each page
        for i, page in enumerate(pages_to_test):
            if self.progress_callback:
                await self.progress_callback(
                    f"Clickjacking: Testing page {i+1}/{len(pages_to_test)}: {page}"
                )

            vulns = await self._test_clickjacking(page)
            misconfigurations.extend(vulns)

            await asyncio.sleep(0.05)  # Rate limiting

        logger.info(f"✅ Clickjacking scan complete: {len(misconfigurations)} issues found")
        return misconfigurations

    async def _test_clickjacking(self, url: str) -> List[Misconfiguration]:
        """
        Test a single URL for clickjacking protection
        """
        misconfigurations = []

        try:
            response = await self.client.get(url)
            if not response:
                return misconfigurations

            # Only test successful responses
            if response.status_code != 200:
                return misconfigurations

            headers = {k.lower(): v for k, v in response.headers.items()}

            # Check X-Frame-Options
            x_frame_options = headers.get('x-frame-options', '').upper()

            # Check Content-Security-Policy frame-ancestors
            csp = headers.get('content-security-policy', '')
            has_frame_ancestors = 'frame-ancestors' in csp.lower()

            # Determine if page is sensitive
            is_sensitive = any(keyword in url.lower() for keyword in self.SENSITIVE_PAGES)

            # Missing X-Frame-Options and CSP frame-ancestors
            if not x_frame_options and not has_frame_ancestors:
                severity = SeverityLevel.HIGH if is_sensitive else SeverityLevel.MEDIUM

                misconfigurations.append(Misconfiguration(
                    title="Missing Clickjacking Protection",
                    description="The page can be framed by any website, making it vulnerable to clickjacking attacks. "
                              "An attacker can overlay invisible frames to trick users into clicking on unintended elements.",
                    severity=severity,
                    affected_url=url,
                    current_value="No X-Frame-Options header\nNo CSP frame-ancestors directive",
                    recommended_value="X-Frame-Options: DENY or SAMEORIGIN\n"
                                    "OR Content-Security-Policy: frame-ancestors 'self'",
                    impact="Attackers can embed this page in a malicious website and trick users into:\n"
                          "- Clicking hidden buttons (e.g., 'Delete Account', 'Transfer Money')\n"
                          "- Entering credentials into what appears to be the legitimate site\n"
                          "- Performing unintended actions while thinking they're on a different site\n\n"
                          f"{'⚠️  CRITICAL: This is a sensitive page (login/payment/admin)!' if is_sensitive else ''}",
                    remediation="**Recommended Solution: X-Frame-Options Header**\n\n"
                              "Add one of these headers to all responses:\n\n"
                              "1. **X-Frame-Options: DENY** (Most Secure)\n"
                              "   - Page cannot be framed at all\n"
                              "   - Use for sensitive pages (login, payment, admin)\n\n"
                              "2. **X-Frame-Options: SAMEORIGIN**\n"
                              "   - Page can only be framed by same origin\n"
                              "   - Use when you need to frame your own pages\n\n"
                              "3. **Content-Security-Policy: frame-ancestors 'self'**\n"
                              "   - Modern alternative to X-Frame-Options\n"
                              "   - More flexible (can specify multiple origins)\n"
                              "   - Recommended for new applications\n\n"
                              "**Implementation Examples:**\n\n"
                              "Nginx:\n"
                              "```nginx\n"
                              "add_header X-Frame-Options \"DENY\" always;\n"
                              "add_header Content-Security-Policy \"frame-ancestors 'self'\" always;\n"
                              "```\n\n"
                              "Apache:\n"
                              "```apache\n"
                              "Header always set X-Frame-Options \"DENY\"\n"
                              "Header always set Content-Security-Policy \"frame-ancestors 'self'\"\n"
                              "```\n\n"
                              "Express.js:\n"
                              "```javascript\n"
                              "app.use(helmet.frameguard({ action: 'deny' }));\n"
                              "```\n\n"
                              "Django:\n"
                              "```python\n"
                              "MIDDLEWARE = [\n"
                              "    'django.middleware.clickjacking.XFrameOptionsMiddleware',\n"
                              "]\n"
                              "X_FRAME_OPTIONS = 'DENY'\n"
                              "```\n\n"
                              "Flask:\n"
                              "```python\n"
                              "@app.after_request\n"
                              "def set_frame_options(response):\n"
                              "    response.headers['X-Frame-Options'] = 'DENY'\n"
                              "    return response\n"
                              "```",
                    references=[
                        "https://owasp.org/www-community/attacks/Clickjacking",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"
                    ],
                    cwe_id="CWE-1021",
                    owasp_category="A04:2021 – Insecure Design"
                ))

                logger.info(f"🚨 Clickjacking vulnerability: {url}")

            # Weak X-Frame-Options configuration
            elif x_frame_options and 'ALLOW-FROM' in x_frame_options:
                misconfigurations.append(Misconfiguration(
                    title="Deprecated X-Frame-Options Configuration",
                    description="The X-Frame-Options ALLOW-FROM directive is deprecated and not supported by modern browsers.",
                    severity=SeverityLevel.MEDIUM,
                    affected_url=url,
                    current_value=f"X-Frame-Options: {x_frame_options}",
                    recommended_value="Content-Security-Policy: frame-ancestors 'self' https://trusted-domain.com",
                    impact="The frame protection is ineffective in modern browsers",
                    remediation="Replace ALLOW-FROM with CSP frame-ancestors:\n"
                              "Content-Security-Policy: frame-ancestors 'self' https://trusted-domain.com",
                    references=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"
                    ],
                    cwe_id="CWE-1021"
                ))

            # Has X-Frame-Options but no CSP (informational)
            elif x_frame_options and not has_frame_ancestors:
                # This is actually OK, but CSP is recommended for modern apps
                if is_sensitive:
                    misconfigurations.append(Misconfiguration(
                        title="Consider Adding CSP frame-ancestors",
                        description="Page has X-Frame-Options but not CSP frame-ancestors. "
                                  "While X-Frame-Options provides protection, CSP frame-ancestors is the modern standard.",
                        severity=SeverityLevel.INFO,
                        affected_url=url,
                        current_value=f"X-Frame-Options: {x_frame_options}",
                        recommended_value=f"X-Frame-Options: {x_frame_options}\n"
                                        "Content-Security-Policy: frame-ancestors 'self'",
                        impact="Current protection is adequate, but CSP provides more flexibility",
                        remediation="Add CSP frame-ancestors alongside X-Frame-Options for better compatibility:\n"
                                  "Content-Security-Policy: frame-ancestors 'self'",
                        cwe_id="CWE-1021"
                    ))

        except Exception as e:
            logger.debug(f"Error testing clickjacking for {url}: {e}")

        return misconfigurations

    async def generate_poc_html(self, target_url: str) -> str:
        """
        Generate HTML proof-of-concept for clickjacking

        Args:
            target_url: The vulnerable URL

        Returns:
            HTML PoC code
        """
        poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
        }}

        /* Invisible iframe overlaying the entire page */
        #target {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0; /* Change to 0.5 to see the iframe during testing */
            z-index: 1000;
        }}

        /* Decoy content that users think they're clicking */
        #decoy {{
            position: absolute;
            top: 200px;
            left: 200px;
            z-index: 1;
        }}

        .button {{
            background-color: #4CAF50;
            border: none;
            color: white;
            padding: 15px 32px;
            text-align: center;
            font-size: 16px;
            cursor: pointer;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <h1>Clickjacking Proof of Concept</h1>
    <p>Instructions: Click the green button below</p>

    <!-- Decoy button that user sees -->
    <div id="decoy">
        <button class="button">Click here to win $1000!</button>
    </div>

    <!-- Invisible iframe with target site -->
    <!-- The iframe is positioned so that when user clicks the decoy button,
         they actually click something in the target site -->
    <iframe id="target" src="{target_url}"></iframe>

    <div style="margin-top: 300px; padding: 20px; background: #ffe6e6; border: 1px solid red;">
        <h3>What happened?</h3>
        <p>When you clicked the green button, you actually clicked something in the hidden iframe!</p>
        <p>Target URL: <a href="{target_url}">{target_url}</a></p>
        <p><strong>Note:</strong> Set opacity to 0.5 in CSS to see the iframe during testing.</p>
    </div>
</body>
</html>"""
        return poc
