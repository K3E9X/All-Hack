"""
Security Headers misconfiguration scanner
"""
import logging
from typing import List, Dict, Any
from app.models import Misconfiguration, SeverityLevel
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class SecurityHeadersScanner:
    """Scan for missing or misconfigured security headers"""

    # Expected security headers with their recommended values
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'required': True,
            'severity': SeverityLevel.HIGH,
            'description': 'HTTP Strict Transport Security (HSTS) header missing',
            'recommended': 'max-age=31536000; includeSubDomains; preload',
            'remediation': 'Add HSTS header to force HTTPS connections'
        },
        'Content-Security-Policy': {
            'required': True,
            'severity': SeverityLevel.HIGH,
            'description': 'Content Security Policy (CSP) header missing',
            'recommended': "default-src 'self'; script-src 'self'; style-src 'self'",
            'remediation': 'Implement CSP to prevent XSS and data injection attacks'
        },
        'X-Frame-Options': {
            'required': True,
            'severity': SeverityLevel.MEDIUM,
            'description': 'X-Frame-Options header missing',
            'recommended': 'DENY or SAMEORIGIN',
            'remediation': 'Add X-Frame-Options to prevent clickjacking attacks'
        },
        'X-Content-Type-Options': {
            'required': True,
            'severity': SeverityLevel.MEDIUM,
            'description': 'X-Content-Type-Options header missing',
            'recommended': 'nosniff',
            'remediation': 'Add X-Content-Type-Options: nosniff to prevent MIME sniffing'
        },
        'Referrer-Policy': {
            'required': True,
            'severity': SeverityLevel.LOW,
            'description': 'Referrer-Policy header missing',
            'recommended': 'strict-origin-when-cross-origin or no-referrer',
            'remediation': 'Add Referrer-Policy to control referrer information'
        },
        'Permissions-Policy': {
            'required': False,
            'severity': SeverityLevel.LOW,
            'description': 'Permissions-Policy header missing',
            'recommended': 'geolocation=(), microphone=(), camera=()',
            'remediation': 'Add Permissions-Policy to control browser features'
        },
        'X-XSS-Protection': {
            'required': False,
            'severity': SeverityLevel.LOW,
            'description': 'X-XSS-Protection header missing (legacy)',
            'recommended': '1; mode=block',
            'remediation': 'Add X-XSS-Protection for older browsers (use CSP for modern browsers)'
        }
    }

    # Dangerous header values
    DANGEROUS_VALUES = {
        'X-Frame-Options': ['ALLOW', 'ALLOWALL'],
        'Content-Security-Policy': ['unsafe-inline', 'unsafe-eval'],
        'Access-Control-Allow-Origin': ['*'],
    }

    def __init__(self, client: PentestHTTPClient):
        self.client = client

    async def scan(self) -> List[Misconfiguration]:
        """Scan for security header misconfigurations"""
        misconfigurations = []

        try:
            response = await self.client.get()
            if not response:
                return misconfigurations

            headers = {k.lower(): v for k, v in response.headers.items()}

            # Check for missing headers
            for header_name, config in self.SECURITY_HEADERS.items():
                header_lower = header_name.lower()

                if header_lower not in headers:
                    if config['required']:
                        misconfigurations.append(Misconfiguration(
                            title=f"Missing Security Header: {header_name}",
                            description=config['description'],
                            severity=config['severity'],
                            affected_component=f"HTTP Response Headers",
                            recommended_value=config['recommended'],
                            remediation=config['remediation']
                        ))
                else:
                    # Check for dangerous values
                    header_value = headers[header_lower]
                    if header_name in self.DANGEROUS_VALUES:
                        for dangerous_value in self.DANGEROUS_VALUES[header_name]:
                            if dangerous_value.lower() in header_value.lower():
                                misconfigurations.append(Misconfiguration(
                                    title=f"Insecure {header_name} Configuration",
                                    description=f"{header_name} contains dangerous value: {dangerous_value}",
                                    severity=SeverityLevel.HIGH,
                                    affected_component=f"HTTP Response Headers",
                                    current_value=header_value,
                                    recommended_value=config['recommended'],
                                    remediation=f"Remove '{dangerous_value}' from {header_name} header. "
                                              f"{config['remediation']}"
                                ))

            # Check for information disclosure headers
            disclosure_headers = [
                'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'
            ]
            for header in disclosure_headers:
                if header in headers:
                    misconfigurations.append(Misconfiguration(
                        title=f"Information Disclosure: {header.upper()} Header",
                        description=f"Server exposes technology information via {header.upper()} header",
                        severity=SeverityLevel.LOW,
                        affected_component="HTTP Response Headers",
                        current_value=headers[header],
                        remediation=f"Remove or obfuscate {header.upper()} header to avoid information disclosure"
                    ))

        except Exception as e:
            logger.error(f"Error scanning security headers: {e}")

        return misconfigurations
