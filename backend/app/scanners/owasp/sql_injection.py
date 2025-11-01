"""
SQL Injection detection scanner
"""
import asyncio
import logging
import re
from typing import List, Dict, Any, Optional
from app.models import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class SQLInjectionScanner:
    """Detect SQL injection vulnerabilities"""

    # SQL injection payloads
    PAYLOADS = [
        # Error-based
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR '1'='1' --", "\" OR \"1\"=\"1\" --",
        "' OR 1=1--", "\" OR 1=1--",
        "admin' --", "admin\" --",
        "' UNION SELECT NULL--", "\" UNION SELECT NULL--",

        # Time-based blind
        "' AND SLEEP(5)--", "\" AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--", "\"; WAITFOR DELAY '0:0:5'--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",

        # Boolean-based blind
        "' AND 1=1--", "' AND 1=2--",
        "\" AND 1=1--", "\" AND 1=2--",

        # UNION-based
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",

        # Stacked queries
        "'; DROP TABLE users--",
        "'; EXEC xp_cmdshell('whoami')--",
    ]

    # SQL error patterns
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.*SQL Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"SqlException",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_.*",
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_.*",
        r"SQLITE_ERROR",
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"Access Database Engine",
        r"Unclosed quotation mark after the character string",
        r"Syntax error.*near",
    ]

    def __init__(self, client: PentestHTTPClient):
        self.client = client

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Scan for SQL injection vulnerabilities"""
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
        """Test a single endpoint for SQL injection"""
        vulnerabilities = []

        # Test GET parameters
        if '?' in endpoint:
            vulns = await self._test_get_params(endpoint)
            vulnerabilities.extend(vulns)

        # Test POST parameters (if endpoint accepts POST)
        vulns = await self._test_post_params(endpoint)
        vulnerabilities.extend(vulns)

        return vulnerabilities

    async def _test_get_params(self, endpoint: str) -> List[Vulnerability]:
        """Test GET parameters for SQL injection"""
        vulnerabilities = []

        # Parse URL and extract parameters
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
            for payload in self.PAYLOADS[:15]:  # Limit payloads for performance
                test_params = params.copy()
                test_params[param_name] = payload

                vuln = await self._send_payload_get(base_url, test_params, param_name, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    break  # Found vulnerability, move to next parameter

        return vulnerabilities

    async def _test_post_params(self, endpoint: str) -> List[Vulnerability]:
        """Test POST parameters for SQL injection"""
        vulnerabilities = []

        # Common POST parameters to test
        test_params = {
            'id': '1',
            'user_id': '1',
            'username': 'admin',
            'email': 'test@example.com',
            'search': 'test',
            'query': 'test'
        }

        for param_name, original_value in test_params.items():
            for payload in self.PAYLOADS[:15]:
                data = test_params.copy()
                data[param_name] = payload

                vuln = await self._send_payload_post(endpoint, data, param_name, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    break

        return vulnerabilities

    async def _send_payload_get(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        payload: str
    ) -> Optional[Vulnerability]:
        """Send GET request with payload and analyze response"""
        try:
            response = await self.client.get(url, params=params)
            if not response:
                return None

            # Check for SQL errors in response
            if self._detect_sql_error(response.text):
                return Vulnerability(
                    id=f"sqli_get_{param_name}_{hash(url)}",
                    title="SQL Injection (Error-based)",
                    description=f"SQL injection vulnerability detected in GET parameter '{param_name}'",
                    severity=SeverityLevel.CRITICAL,
                    category=VulnerabilityCategory.INJECTION,
                    affected_url=url,
                    affected_parameter=param_name,
                    proof_of_concept=f"Parameter '{param_name}' is vulnerable to SQL injection. "
                                   f"SQL error messages detected in response.",
                    payload=payload,
                    remediation="Use parameterized queries (prepared statements) or ORM. "
                              "Never concatenate user input directly into SQL queries. "
                              "Implement input validation and sanitization.",
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 – Injection",
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                    ]
                )

            # Check for time-based blind SQL injection
            if 'SLEEP' in payload or 'WAITFOR' in payload:
                # This would require timing analysis in real implementation
                pass

        except Exception as e:
            logger.debug(f"Error testing SQL injection: {e}")

        return None

    async def _send_payload_post(
        self,
        url: str,
        data: Dict[str, str],
        param_name: str,
        payload: str
    ) -> Optional[Vulnerability]:
        """Send POST request with payload and analyze response"""
        try:
            response = await self.client.post(url, data=data)
            if not response:
                return None

            if self._detect_sql_error(response.text):
                return Vulnerability(
                    id=f"sqli_post_{param_name}_{hash(url)}",
                    title="SQL Injection (Error-based)",
                    description=f"SQL injection vulnerability detected in POST parameter '{param_name}'",
                    severity=SeverityLevel.CRITICAL,
                    category=VulnerabilityCategory.INJECTION,
                    affected_url=url,
                    affected_parameter=param_name,
                    proof_of_concept=f"Parameter '{param_name}' is vulnerable to SQL injection via POST. "
                                   f"SQL error messages detected in response.",
                    payload=payload,
                    remediation="Use parameterized queries (prepared statements) or ORM. "
                              "Never concatenate user input directly into SQL queries. "
                              "Implement input validation and sanitization.",
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 – Injection",
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                    ]
                )

        except Exception as e:
            logger.debug(f"Error testing SQL injection: {e}")

        return None

    def _detect_sql_error(self, response_text: str) -> bool:
        """Detect SQL error patterns in response"""
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
