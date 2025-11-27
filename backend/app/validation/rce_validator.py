"""
RCE/Command Injection PoC Validator

Validates RCE by executing safe commands and detecting output.
"""
import logging
import re
from typing import Optional
from datetime import datetime

from app.validation.base_validator import BaseValidator, ValidationStatus, ValidationResult
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class RCEValidator(BaseValidator):
    """
    Validates RCE and Command Injection vulnerabilities

    Uses safe, read-only commands to detect code execution.
    Looks for command output in responses.
    """

    # Safe commands that don't modify system
    SAFE_COMMANDS = {
        # Unix/Linux commands
        "unix": [
            "whoami",           # Get current user
            "id",               # Get user ID
            "pwd",              # Print working directory
            "uname -a",         # System information
            "echo PENTESTMARKER_{{marker}}"  # Echo unique marker
        ],
        # Windows commands
        "windows": [
            "whoami",
            "echo PENTESTMARKER_{{marker}}",
            "ver",              # Windows version
            "hostname",         # Computer name
        ],
        # Universal markers
        "markers": [
            "echo 'RCE_TEST_{marker}'",
            "printf 'RCE_TEST_{marker}'",
        ]
    }

    # Command injection payloads (common injection points)
    INJECTION_PAYLOADS = [
        "; {command}",          # Command separator
        "| {command}",          # Pipe
        "&& {command}",         # AND operator
        "|| {command}",         # OR operator
        "`{command}`",          # Command substitution (backticks)
        "$({command})",         # Command substitution (modern)
        "\n{command}\n",        # Newline injection
    ]

    def _is_applicable(self, vulnerability: any) -> bool:
        """Check if RCE validator applies"""
        vuln_category = getattr(vulnerability, 'category', '')
        if hasattr(vuln_category, 'value'):
            vuln_category = vuln_category.value

        vuln_title = getattr(vulnerability, 'title', '').lower()
        vuln_desc = getattr(vulnerability, 'description', '').lower()

        # Check for RCE/Command Injection indicators
        indicators = [
            'rce', 'remote code execution', 'command injection',
            'os command', 'shell injection', 'code execution'
        ]

        category_match = any(ind in str(vuln_category).lower() for ind in indicators)
        title_match = any(ind in vuln_title for ind in indicators)
        desc_match = any(ind in vuln_desc for ind in indicators)

        return category_match or title_match or desc_match

    async def validate(
        self,
        vulnerability: any,
        target_url: str,
        client: Optional[PentestHTTPClient] = None,
        **kwargs
    ) -> Optional[ValidationResult]:
        """
        Validate RCE/Command Injection

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

        logger.info(f"🔍 Validating RCE: {vulnerability.title}")

        if client is None:
            client = PentestHTTPClient(base_url=target_url)

        vuln_url = getattr(vulnerability, 'affected_url', target_url)
        vuln_param = getattr(vulnerability, 'affected_parameter', None)

        # Try marker-based validation (most reliable)
        marker_result = await self._validate_with_marker(client, vuln_url, vuln_param)
        if marker_result:
            return marker_result

        # Try command output detection
        command_result = await self._validate_with_command_output(client, vuln_url, vuln_param)
        if command_result:
            return command_result

        # Try timing-based detection (last resort)
        timing_result = await self._validate_with_timing(client, vuln_url, vuln_param)
        if timing_result:
            return timing_result

        # Could not confirm
        return self._create_result(
            status=ValidationStatus.UNCONFIRMED,
            confidence=0.3,
            evidence="Could not confirm RCE",
            details={"reason": "No command output detected"}
        )

    async def _validate_with_marker(
        self,
        client: PentestHTTPClient,
        url: str,
        param: Optional[str]
    ) -> Optional[ValidationResult]:
        """
        Validate RCE using unique marker injection

        Most reliable method - inject unique string and check for it in response.
        """
        import uuid

        # Generate unique marker
        marker = str(uuid.uuid4())[:12]

        # Test Unix-style echo
        for injection_method in self.INJECTION_PAYLOADS:
            command = f"echo RCE_MARKER_{marker}"
            payload = injection_method.format(command=command)

            try:
                test_url = self._inject_payload(url, param, payload)
                response = await client.get(test_url)

                if not response:
                    continue

                content = response.text

                # Check if marker appears in response
                if f"RCE_MARKER_{marker}" in content:
                    logger.info(f"✅ RCE CONFIRMED: Marker detected in response!")

                    return self._create_result(
                        status=ValidationStatus.CONFIRMED,
                        confidence=1.0,
                        evidence=f"RCE confirmed - unique marker '{marker}' detected in response",
                        details={
                            "marker": marker,
                            "payload": payload,
                            "injection_method": injection_method,
                            "method": "marker_injection"
                        }
                    )

            except Exception as e:
                logger.debug(f"Marker validation attempt failed: {e}")
                continue

        return None

    async def _validate_with_command_output(
        self,
        client: PentestHTTPClient,
        url: str,
        param: Optional[str]
    ) -> Optional[ValidationResult]:
        """
        Validate RCE by detecting command output patterns

        Tests common safe commands and looks for expected output.
        """
        test_cases = [
            # (command, expected_patterns, description)
            ("whoami", [r'[a-z]+', r'[a-z0-9_-]+'], "Unix whoami output"),
            ("id", [r'uid=\d+', r'gid=\d+', r'groups='], "Unix id command"),
            ("pwd", [r'/[\w/]+', r'[A-Z]:\\'], "Unix/Windows pwd"),
            ("uname -a", [r'Linux', r'GNU', r'kernel', r'x86_64'], "Unix uname"),
            ("hostname", [r'[\w-]+', r'[a-zA-Z0-9-]+'], "Hostname"),
        ]

        for command, patterns, description in test_cases:
            for injection_method in self.INJECTION_PAYLOADS:
                payload = injection_method.format(command=command)

                try:
                    test_url = self._inject_payload(url, param, payload)
                    response = await client.get(test_url)

                    if not response:
                        continue

                    content = response.text.lower()

                    # Check for expected patterns
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            logger.info(f"✅ RCE LIKELY: {description} detected")

                            return self._create_result(
                                status=ValidationStatus.LIKELY,
                                confidence=0.80,
                                evidence=f"RCE likely - {description} pattern detected in response",
                                details={
                                    "command": command,
                                    "payload": payload,
                                    "pattern": pattern,
                                    "method": "command_output_detection"
                                }
                            )

                except Exception as e:
                    logger.debug(f"Command output validation failed: {e}")
                    continue

        return None

    async def _validate_with_timing(
        self,
        client: PentestHTTPClient,
        url: str,
        param: Optional[str]
    ) -> Optional[ValidationResult]:
        """
        Validate RCE using timing attacks

        Injects sleep/timeout commands and measures response time.
        Less reliable but works when output is not reflected.
        """
        import time

        # Sleep commands for different systems
        sleep_commands = [
            ("sleep 5", 5, "Unix sleep"),
            ("timeout 5", 5, "Windows timeout"),
            ("ping -c 5 127.0.0.1", 5, "Unix ping delay"),
            ("ping -n 5 127.0.0.1", 5, "Windows ping delay"),
        ]

        for sleep_cmd, expected_delay, description in sleep_commands:
            for injection_method in ["; {command}", "| {command}", "&& {command}"]:
                payload = injection_method.format(command=sleep_cmd)

                try:
                    test_url = self._inject_payload(url, param, payload)

                    # Measure baseline response time
                    start = time.time()
                    baseline_response = await client.get(url)
                    baseline_time = time.time() - start

                    # Measure response time with sleep payload
                    start = time.time()
                    sleep_response = await client.get(test_url)
                    sleep_time = time.time() - start

                    # Check if response was delayed by expected amount
                    time_diff = sleep_time - baseline_time

                    if time_diff >= expected_delay - 1:  # Allow 1 second tolerance
                        logger.info(f"✅ RCE POSSIBLE: Timing delay detected ({time_diff:.1f}s)")

                        return self._create_result(
                            status=ValidationStatus.LIKELY,
                            confidence=0.65,
                            evidence=f"Possible RCE - timing delay detected ({time_diff:.1f} seconds)",
                            details={
                                "sleep_command": sleep_cmd,
                                "payload": payload,
                                "expected_delay": expected_delay,
                                "actual_delay": time_diff,
                                "baseline_time": baseline_time,
                                "sleep_time": sleep_time,
                                "method": "timing_attack"
                            }
                        )

                except Exception as e:
                    logger.debug(f"Timing validation failed: {e}")
                    continue

        return None

    def _inject_payload(self, url: str, param: Optional[str], payload: str) -> str:
        """Inject RCE payload into URL"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

        if not param:
            # Try common parameter names
            separator = '&' if '?' in url else '?'
            return f"{url}{separator}cmd={quote(payload)}"

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if param in query_params:
            query_params[param] = [payload]
        else:
            query_params[param] = [payload]

        new_query = urlencode(query_params, doseq=True)
        new_parsed = parsed._replace(query=new_query)

        return urlunparse(new_parsed)
