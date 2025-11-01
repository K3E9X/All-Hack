"""
Cross-Site Scripting (XSS) detection scanner
"""
import asyncio
import logging
import re
from typing import List, Dict, Any, Optional
from app.models import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.utils import PentestHTTPClient, extract_forms

logger = logging.getLogger(__name__)

class XSSScanner:
    """Detect XSS vulnerabilities (Reflected, Stored, DOM-based)"""

    # XSS payloads
    PAYLOADS = [
        # Basic payloads
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",

        # Encoded payloads
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",

        # Event handlers
        "\" onmouseover=\"alert('XSS')\"",
        "' onmouseover='alert(\"XSS\")'",
        "<input onfocus=alert('XSS') autofocus>",

        # Filter bypass
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "<ScRiPt>alert('XSS')</sCrIpT>",
        "<script>alert`XSS`</script>",

        # Attribute injection
        "\"autofocus onfocus=alert('XSS')\"",
        "'autofocus onfocus=alert('XSS')'",

        # Javascript: protocol
        "javascript:alert('XSS')",
        "javascript:alert('XSS')//",

        # HTML5 events
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
    ]

    # Unique marker to identify our payload
    MARKER = "XSSTEST123456"

    def __init__(self, client: PentestHTTPClient):
        self.client = client

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Scan for XSS vulnerabilities"""
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
        """Test a single endpoint for XSS"""
        vulnerabilities = []

        # Test reflected XSS in GET parameters
        if '?' in endpoint:
            vulns = await self._test_reflected_get(endpoint)
            vulnerabilities.extend(vulns)

        # Test reflected XSS in forms
        vulns = await self._test_forms(endpoint)
        vulnerabilities.extend(vulns)

        # Test DOM-based XSS
        vulns = await self._test_dom_xss(endpoint)
        vulnerabilities.extend(vulns)

        return vulnerabilities

    async def _test_reflected_get(self, endpoint: str) -> List[Vulnerability]:
        """Test for reflected XSS in GET parameters"""
        vulnerabilities = []

        if '?' not in endpoint:
            return vulnerabilities

        base_url, query_string = endpoint.split('?', 1)
        params = {}

        for param in query_string.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                params[key] = value

        # Test each parameter
        for param_name, original_value in params.items():
            # First, test with marker to see if it's reflected
            test_params = params.copy()
            test_params[param_name] = self.MARKER

            response = await self.client.get(base_url, params=test_params)
            if not response or self.MARKER not in response.text:
                continue  # Not reflected, skip

            # If reflected, test with actual XSS payloads
            for payload in self.PAYLOADS[:10]:  # Limit for performance
                test_params = params.copy()
                test_params[param_name] = payload

                response = await self.client.get(base_url, params=test_params)
                if not response:
                    continue

                # Check if payload is reflected without proper encoding
                if self._is_vulnerable(response.text, payload):
                    vulnerabilities.append(Vulnerability(
                        id=f"xss_reflected_{param_name}_{hash(endpoint)}",
                        title="Reflected Cross-Site Scripting (XSS)",
                        description=f"Reflected XSS vulnerability in GET parameter '{param_name}'",
                        severity=SeverityLevel.HIGH,
                        category=VulnerabilityCategory.XSS,
                        affected_url=endpoint,
                        affected_parameter=param_name,
                        proof_of_concept=f"The parameter '{param_name}' reflects user input without proper "
                                       f"encoding/sanitization, allowing execution of arbitrary JavaScript.",
                        payload=payload,
                        remediation="Encode all user input before rendering in HTML context. "
                                  "Use Content-Security-Policy headers. "
                                  "Implement input validation and output encoding. "
                                  "Consider using auto-escaping template engines.",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021 – Injection",
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                        ]
                    ))
                    break  # Found vulnerability, move to next parameter

        return vulnerabilities

    async def _test_forms(self, endpoint: str) -> List[Vulnerability]:
        """Test forms for XSS vulnerabilities"""
        vulnerabilities = []

        try:
            # Get the page and extract forms
            response = await self.client.get(endpoint)
            if not response or response.status_code != 200:
                return vulnerabilities

            forms = extract_forms(response.text)

            for form in forms:
                # Test each input field
                for input_field in form['inputs']:
                    if not input_field['name']:
                        continue

                    # Test with marker first
                    form_data = {inp['name']: self.MARKER for inp in form['inputs'] if inp['name']}

                    action_url = form['action'] or endpoint
                    if form['method'] == 'POST':
                        test_response = await self.client.post(action_url, data=form_data)
                    else:
                        test_response = await self.client.get(action_url, params=form_data)

                    if not test_response or self.MARKER not in test_response.text:
                        continue

                    # Test with XSS payloads
                    for payload in self.PAYLOADS[:5]:
                        form_data[input_field['name']] = payload

                        if form['method'] == 'POST':
                            response = await self.client.post(action_url, data=form_data)
                        else:
                            response = await self.client.get(action_url, params=form_data)

                        if response and self._is_vulnerable(response.text, payload):
                            vulnerabilities.append(Vulnerability(
                                id=f"xss_form_{input_field['name']}_{hash(endpoint)}",
                                title="Cross-Site Scripting (XSS) in Form",
                                description=f"XSS vulnerability in form field '{input_field['name']}'",
                                severity=SeverityLevel.HIGH,
                                category=VulnerabilityCategory.XSS,
                                affected_url=endpoint,
                                affected_parameter=input_field['name'],
                                proof_of_concept=f"Form field '{input_field['name']}' is vulnerable to XSS.",
                                payload=payload,
                                remediation="Encode all user input before rendering. "
                                          "Use Content-Security-Policy headers. "
                                          "Implement proper input validation and output encoding.",
                                cwe_id="CWE-79",
                                owasp_category="A03:2021 – Injection",
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/"
                                ]
                            ))
                            break

        except Exception as e:
            logger.error(f"Error testing forms for XSS: {e}")

        return vulnerabilities

    async def _test_dom_xss(self, endpoint: str) -> List[Vulnerability]:
        """Test for DOM-based XSS"""
        vulnerabilities = []

        try:
            response = await self.client.get(endpoint)
            if not response:
                return vulnerabilities

            # Look for dangerous JavaScript patterns
            dangerous_patterns = [
                r'document\.write\s*\(',
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'document\.location',
                r'document\.URL',
                r'document\.documentURI',
                r'window\.location',
                r'eval\s*\(',
                r'setTimeout\s*\(',
                r'setInterval\s*\('
            ]

            # Check if page uses URL parameters in dangerous sinks
            uses_location = any(re.search(pattern, response.text, re.IGNORECASE)
                              for pattern in dangerous_patterns)

            if uses_location and ('?' in endpoint or '#' in endpoint):
                vulnerabilities.append(Vulnerability(
                    id=f"xss_dom_{hash(endpoint)}",
                    title="Potential DOM-based XSS",
                    description="Page uses URL parameters with potentially dangerous JavaScript functions",
                    severity=SeverityLevel.MEDIUM,
                    category=VulnerabilityCategory.XSS,
                    affected_url=endpoint,
                    proof_of_concept="The page manipulates DOM using URL parameters with functions like "
                                   "document.write(), innerHTML, or eval(). This may lead to DOM-based XSS.",
                    remediation="Avoid using dangerous JavaScript functions with user-controlled input. "
                              "Use textContent instead of innerHTML. "
                              "Validate and sanitize all URL parameters before DOM manipulation.",
                    cwe_id="CWE-79",
                    owasp_category="A03:2021 – Injection",
                    references=[
                        "https://owasp.org/www-community/attacks/DOM_Based_XSS"
                    ]
                ))

        except Exception as e:
            logger.error(f"Error testing DOM XSS: {e}")

        return vulnerabilities

    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        """Check if the payload is reflected in a dangerous way"""
        # Check if payload appears unencoded in the response
        # Look for script tags, event handlers, etc.

        dangerous_contexts = [
            # Unencoded script tags
            payload in response_text,

            # In HTML attribute without quotes
            re.search(rf'\w+={re.escape(payload)}', response_text),

            # In JavaScript context
            re.search(rf'<script[^>]*>.*{re.escape(payload)}.*</script>', response_text, re.DOTALL),
        ]

        return any(dangerous_contexts)
