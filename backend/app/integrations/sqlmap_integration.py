"""
SQLMap Integration

Integrates SQLMap for advanced SQL injection testing.
"""
import asyncio
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable
from urllib.parse import urlparse, parse_qs
from app.models import Vulnerability, SeverityLevel, VulnerabilityCategory

logger = logging.getLogger(__name__)

class SQLMapIntegration:
    """
    SQLMap integration for advanced SQL injection testing

    Features:
    - Automatic SQLMap installation check
    - Batch URL testing
    - Results parsing and conversion
    - Custom configuration support
    """

    def __init__(
        self,
        sqlmap_path: Optional[str] = None,
        progress_callback: Optional[Callable] = None
    ):
        """
        Initialize SQLMap integration

        Args:
            sqlmap_path: Path to sqlmap executable (auto-detected if None)
            progress_callback: Optional callback for progress updates
        """
        self.sqlmap_path = sqlmap_path or self._find_sqlmap()
        self.progress_callback = progress_callback
        self.temp_dir = tempfile.mkdtemp(prefix="allhack_sqlmap_")

    def _find_sqlmap(self) -> Optional[str]:
        """
        Find SQLMap installation

        Checks common locations:
        - sqlmap in PATH
        - /usr/share/sqlmap/sqlmap.py
        - /opt/sqlmap/sqlmap.py
        """
        # Check if sqlmap is in PATH
        sqlmap_bin = shutil.which('sqlmap')
        if sqlmap_bin:
            logger.info(f"✅ Found SQLMap in PATH: {sqlmap_bin}")
            return sqlmap_bin

        # Check common installation paths
        common_paths = [
            '/usr/share/sqlmap/sqlmap.py',
            '/opt/sqlmap/sqlmap.py',
            '/usr/local/bin/sqlmap',
            os.path.expanduser('~/.local/bin/sqlmap'),
        ]

        for path in common_paths:
            if os.path.exists(path):
                logger.info(f"✅ Found SQLMap at: {path}")
                return path

        logger.warning("⚠️  SQLMap not found. Install with: sudo apt install sqlmap")
        return None

    def is_available(self) -> bool:
        """Check if SQLMap is available"""
        return self.sqlmap_path is not None

    async def scan_urls(
        self,
        urls: List[str],
        scan_depth: str = "balanced",
        auth_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> List[Vulnerability]:
        """
        Scan URLs with SQLMap

        Args:
            urls: List of URLs to test
            scan_depth: Scan depth (quick/balanced/deep)
            auth_headers: Authentication headers
            cookies: Cookies for authenticated requests

        Returns:
            List of SQL injection vulnerabilities found
        """
        if not self.is_available():
            logger.error("❌ SQLMap not available. Skipping SQLMap scan.")
            return []

        vulnerabilities = []

        # Filter URLs with parameters (SQLMap needs parameters)
        testable_urls = [url for url in urls if '?' in url]

        if not testable_urls:
            logger.info("ℹ️  No URLs with parameters found for SQLMap testing")
            return []

        logger.info(f"🗃️  SQLMap: Testing {len(testable_urls)} URLs with parameters")

        # Limit based on scan depth
        limits = {
            'quick': 5,
            'balanced': 15,
            'deep': 50
        }
        max_urls = limits.get(scan_depth, 15)
        testable_urls = testable_urls[:max_urls]

        # Test each URL
        for i, url in enumerate(testable_urls):
            if self.progress_callback:
                await self.progress_callback(
                    f"SQLMap: Testing URL {i+1}/{len(testable_urls)}: {url}"
                )

            vuln = await self._test_url(url, scan_depth, auth_headers, cookies)
            if vuln:
                vulnerabilities.extend(vuln)

        logger.info(f"✅ SQLMap: Found {len(vulnerabilities)} SQL injection vulnerabilities")
        return vulnerabilities

    async def _test_url(
        self,
        url: str,
        scan_depth: str,
        auth_headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]]
    ) -> List[Vulnerability]:
        """
        Test a single URL with SQLMap

        Args:
            url: URL to test
            scan_depth: Scan depth
            auth_headers: Authentication headers
            cookies: Cookies

        Returns:
            List of vulnerabilities found for this URL
        """
        vulnerabilities = []

        # Build SQLMap command
        cmd = [
            self.sqlmap_path if self.sqlmap_path.endswith('.py') else self.sqlmap_path,
            '-u', url,
            '--batch',  # Never ask for user input
            '--random-agent',  # Random user agent
            '--output-dir', self.temp_dir,
        ]

        # Add depth-specific options
        if scan_depth == 'quick':
            cmd.extend([
                '--level=1',
                '--risk=1',
                '--threads=4',
            ])
        elif scan_depth == 'balanced':
            cmd.extend([
                '--level=2',
                '--risk=2',
                '--threads=5',
            ])
        else:  # deep
            cmd.extend([
                '--level=3',
                '--risk=2',
                '--threads=5',
                '--tamper=space2comment',
            ])

        # Add authentication
        if auth_headers:
            headers_str = '\\n'.join([f'{k}: {v}' for k, v in auth_headers.items()])
            cmd.extend(['--headers', headers_str])

        if cookies:
            cookie_str = ';'.join([f'{k}={v}' for k, v in cookies.items()])
            cmd.extend(['--cookie', cookie_str])

        # Add timeout
        cmd.extend(['--timeout=10', '--retries=1'])

        try:
            # Run SQLMap
            logger.debug(f"Running SQLMap: {' '.join(cmd[:5])}...")

            # If sqlmap_path ends with .py, run with python
            if self.sqlmap_path and self.sqlmap_path.endswith('.py'):
                cmd = ['python3'] + cmd

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, 'PYTHONUNBUFFERED': '1'}
            )

            # Wait with timeout (max 120 seconds per URL)
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=120.0
                )
            except asyncio.TimeoutError:
                process.kill()
                logger.warning(f"⚠️  SQLMap timeout for {url}")
                return []

            output = stdout.decode('utf-8', errors='ignore')

            # Parse SQLMap output
            if 'sqlmap identified the following injection point' in output.lower():
                # Extract vulnerability details
                vuln = self._parse_sqlmap_output(url, output)
                if vuln:
                    vulnerabilities.append(vuln)
                    logger.info(f"🚨 SQLMap found SQL injection: {url}")

        except Exception as e:
            logger.error(f"❌ SQLMap error for {url}: {e}")

        return vulnerabilities

    def _parse_sqlmap_output(self, url: str, output: str) -> Optional[Vulnerability]:
        """
        Parse SQLMap output and create Vulnerability object

        Args:
            url: Tested URL
            output: SQLMap output

        Returns:
            Vulnerability object if SQL injection found
        """
        # Extract key information from output
        lines = output.split('\\n')

        # Find injection details
        injection_type = "Unknown"
        parameter = "Unknown"
        payload = ""
        dbms = "Unknown"

        for i, line in enumerate(lines):
            # Extract parameter
            if 'Parameter:' in line:
                parts = line.split('Parameter:')
                if len(parts) > 1:
                    parameter = parts[1].strip().split()[0]

            # Extract injection type
            if 'Type:' in line:
                parts = line.split('Type:')
                if len(parts) > 1:
                    injection_type = parts[1].strip()

            # Extract payload
            if 'Payload:' in line:
                parts = line.split('Payload:')
                if len(parts) > 1:
                    payload = parts[1].strip()

            # Extract DBMS
            if 'back-end DBMS:' in line.lower():
                parts = line.lower().split('back-end dbms:')
                if len(parts) > 1:
                    dbms = parts[1].strip().split()[0].upper()

        # Determine severity based on injection type
        severity = SeverityLevel.HIGH
        if 'time-based' in injection_type.lower() or 'boolean-based' in injection_type.lower():
            severity = SeverityLevel.HIGH
        elif 'error-based' in injection_type.lower() or 'union' in injection_type.lower():
            severity = SeverityLevel.CRITICAL

        # Create vulnerability
        vuln = Vulnerability(
            id=f"sqlmap_sqli_{hash(url)}_{hash(parameter)}",
            title=f"SQL Injection ({injection_type}) - Detected by SQLMap",
            description=f"SQLMap detected a SQL injection vulnerability in parameter '{parameter}'. "
                       f"The backend database is identified as {dbms}. "
                       f"This vulnerability allows attackers to manipulate SQL queries and potentially "
                       f"access, modify, or delete database contents.",
            severity=severity,
            category=VulnerabilityCategory.SQL_INJECTION,
            affected_url=url,
            proof_of_concept=f"SQLMap Detection Report:\\n\\n"
                           f"URL: {url}\\n"
                           f"Vulnerable Parameter: {parameter}\\n"
                           f"Injection Type: {injection_type}\\n"
                           f"Backend DBMS: {dbms}\\n"
                           f"Sample Payload: {payload[:200]}...\\n\\n"
                           f"This vulnerability was confirmed by SQLMap, "
                           f"a professional SQL injection testing tool.",
            payload=payload[:500],
            remediation="""**Critical: SQL Injection Remediation**

1. **Use Parameterized Queries (Prepared Statements)**
   - NEVER concatenate user input into SQL queries
   - Use placeholders for all user-controlled values

2. **Code Examples**

Python (SQLAlchemy):
```python
# BAD - Vulnerable to SQL injection
query = f"SELECT * FROM users WHERE id = {user_id}"

# GOOD - Parameterized query
query = text("SELECT * FROM users WHERE id = :id")
result = db.execute(query, {'id': user_id})
```

3. **Additional Protections**
   - Input validation and sanitization
   - Least privilege database accounts
   - Web Application Firewall (WAF)
   - Regular security audits

4. **Emergency Response**
   - Patch immediately (this is CRITICAL)
   - Review database logs for exploitation
   - Consider changing database credentials
   - Audit all sensitive data access""",
            cwe_id="CWE-89",
            owasp_category="A03:2021 – Injection",
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://github.com/sqlmapproject/sqlmap"
            ],
            tool_output=output[:1000]  # Store partial output
        )

        return vuln

    def cleanup(self):
        """Clean up temporary files"""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.debug(f"🧹 Cleaned up SQLMap temp directory: {self.temp_dir}")
        except Exception as e:
            logger.warning(f"⚠️  Failed to cleanup SQLMap temp dir: {e}")

    def __del__(self):
        """Destructor to ensure cleanup"""
        self.cleanup()
