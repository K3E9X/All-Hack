"""
SSL/TLS Vulnerability Scanner
"""
import ssl
import socket
import logging
from typing import List
from urllib.parse import urlparse
from datetime import datetime
from app.models import Vulnerability, Misconfiguration, SeverityLevel, VulnerabilityCategory

logger = logging.getLogger(__name__)

class SSLScanner:
    """Advanced SSL/TLS vulnerability scanner"""

    # Weak cipher suites
    WEAK_CIPHERS = [
        'DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon',
        'ADH', 'AECDH', '3DES', 'CBC'
    ]

    # Strong TLS versions
    SUPPORTED_TLS_VERSIONS = {
        ssl.TLSVersion.TLSv1: 'TLSv1.0',
        ssl.TLSVersion.TLSv1_1: 'TLSv1.1',
        ssl.TLSVersion.TLSv1_2: 'TLSv1.2',
        ssl.TLSVersion.TLSv1_3: 'TLSv1.3',
    }

    def __init__(self, target_url: str):
        parsed = urlparse(target_url)
        self.target_host = parsed.hostname
        self.target_port = parsed.port or 443

    async def scan(self) -> tuple[List[Vulnerability], List[Misconfiguration]]:
        """
        Scan SSL/TLS configuration

        Returns:
            (vulnerabilities, misconfigurations)
        """
        vulnerabilities = []
        misconfigurations = []

        if not self.target_host:
            return vulnerabilities, misconfigurations

        logger.info(f"Scanning SSL/TLS configuration for {self.target_host}...")

        try:
            # Get SSL certificate and configuration
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.target_host, self.target_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Analyze certificate
                    cert_vulns, cert_misconfigs = self._analyze_certificate(cert)
                    vulnerabilities.extend(cert_vulns)
                    misconfigurations.extend(cert_misconfigs)

                    # Analyze cipher suite
                    cipher_vulns, cipher_misconfigs = self._analyze_cipher(cipher)
                    vulnerabilities.extend(cipher_vulns)
                    misconfigurations.extend(cipher_misconfigs)

                    # Analyze TLS version
                    version_vulns, version_misconfigs = self._analyze_tls_version(version)
                    vulnerabilities.extend(version_vulns)
                    misconfigurations.extend(version_misconfigs)

        except ssl.SSLError as e:
            logger.warning(f"SSL error: {e}")
            vulnerabilities.append(Vulnerability(
                id="ssl_error",
                title="SSL/TLS Connection Error",
                description=f"Failed to establish secure connection: {str(e)}",
                severity=SeverityLevel.MEDIUM,
                category=VulnerabilityCategory.SECURITY_MISCONFIG,
                affected_url=f"https://{self.target_host}:{self.target_port}",
                proof_of_concept="SSL/TLS handshake failed, indicating potential misconfiguration",
                remediation="Review SSL/TLS configuration and ensure valid certificates are installed",
                cwe_id="CWE-295",
                owasp_category="A05:2021 – Security Misconfiguration"
            ))
        except Exception as e:
            logger.error(f"Error scanning SSL/TLS: {e}")

        return vulnerabilities, misconfigurations

    def _analyze_certificate(self, cert: dict) -> tuple[List[Vulnerability], List[Misconfiguration]]:
        """Analyze SSL certificate"""
        vulnerabilities = []
        misconfigurations = []

        if not cert:
            return vulnerabilities, misconfigurations

        # Check expiration
        not_after = cert.get('notAfter')
        if not_after:
            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (expiry_date - datetime.now()).days

            if days_until_expiry < 0:
                vulnerabilities.append(Vulnerability(
                    id="ssl_cert_expired",
                    title="Expired SSL Certificate",
                    description=f"SSL certificate expired {abs(days_until_expiry)} days ago",
                    severity=SeverityLevel.CRITICAL,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    affected_url=f"https://{self.target_host}",
                    proof_of_concept="Certificate has expired, browsers will show security warnings",
                    remediation="Renew SSL certificate immediately",
                    cwe_id="CWE-298",
                    owasp_category="A02:2021 – Cryptographic Failures"
                ))
            elif days_until_expiry < 30:
                misconfigurations.append(Misconfiguration(
                    title="SSL Certificate Expiring Soon",
                    description=f"SSL certificate will expire in {days_until_expiry} days",
                    severity=SeverityLevel.MEDIUM,
                    affected_component="SSL Certificate",
                    remediation="Renew SSL certificate before expiration"
                ))

        # Check for self-signed certificate
        issuer = cert.get('issuer', ())
        subject = cert.get('subject', ())

        if issuer == subject:
            vulnerabilities.append(Vulnerability(
                id="ssl_self_signed",
                title="Self-Signed SSL Certificate",
                description="Server uses self-signed SSL certificate",
                severity=SeverityLevel.HIGH,
                category=VulnerabilityCategory.SENSITIVE_DATA,
                affected_url=f"https://{self.target_host}",
                proof_of_concept="Certificate is self-signed, not trusted by browsers",
                remediation="Use certificate from trusted Certificate Authority (Let's Encrypt, etc.)",
                cwe_id="CWE-295",
                owasp_category="A02:2021 – Cryptographic Failures"
            ))

        # Check key size
        # Note: Getting actual key size requires more complex parsing
        # This is a simplified check

        return vulnerabilities, misconfigurations

    def _analyze_cipher(self, cipher: tuple) -> tuple[List[Vulnerability], List[Misconfiguration]]:
        """Analyze cipher suite"""
        vulnerabilities = []
        misconfigurations = []

        if not cipher:
            return vulnerabilities, misconfigurations

        cipher_name = cipher[0]
        cipher_version = cipher[1]
        cipher_bits = cipher[2]

        # Check for weak ciphers
        for weak in self.WEAK_CIPHERS:
            if weak.upper() in cipher_name.upper():
                vulnerabilities.append(Vulnerability(
                    id=f"ssl_weak_cipher_{weak.lower()}",
                    title=f"Weak Cipher Suite: {weak}",
                    description=f"Server supports weak cipher: {cipher_name}",
                    severity=SeverityLevel.HIGH,
                    category=VulnerabilityCategory.SENSITIVE_DATA,
                    affected_url=f"https://{self.target_host}",
                    affected_parameter=cipher_name,
                    proof_of_concept=f"Cipher {cipher_name} is considered cryptographically weak",
                    remediation="Disable weak ciphers and use only strong modern ciphers (AES-GCM, ChaCha20)",
                    cwe_id="CWE-327",
                    owasp_category="A02:2021 – Cryptographic Failures",
                    references=[
                        "https://wiki.mozilla.org/Security/Server_Side_TLS"
                    ]
                ))
                break

        # Check key strength
        if cipher_bits < 128:
            vulnerabilities.append(Vulnerability(
                id="ssl_weak_key_size",
                title="Weak Encryption Key Size",
                description=f"Cipher uses only {cipher_bits} bits",
                severity=SeverityLevel.HIGH,
                category=VulnerabilityCategory.SENSITIVE_DATA,
                affected_url=f"https://{self.target_host}",
                proof_of_concept=f"Key size of {cipher_bits} bits is below recommended 128 bits minimum",
                remediation="Use ciphers with at least 128-bit keys, prefer 256-bit",
                cwe_id="CWE-326",
                owasp_category="A02:2021 – Cryptographic Failures"
            ))

        return vulnerabilities, misconfigurations

    def _analyze_tls_version(self, version: str) -> tuple[List[Vulnerability], List[Misconfiguration]]:
        """Analyze TLS protocol version"""
        vulnerabilities = []
        misconfigurations = []

        if not version:
            return vulnerabilities, misconfigurations

        # Check for outdated TLS versions
        if 'TLSv1.0' in version or 'SSLv' in version:
            vulnerabilities.append(Vulnerability(
                id="ssl_outdated_protocol",
                title=f"Outdated TLS Protocol: {version}",
                description=f"Server supports outdated protocol {version}",
                severity=SeverityLevel.HIGH,
                category=VulnerabilityCategory.SENSITIVE_DATA,
                affected_url=f"https://{self.target_host}",
                proof_of_concept=f"Protocol {version} has known vulnerabilities (POODLE, BEAST, etc.)",
                remediation="Disable TLS 1.0, TLS 1.1, and all SSL versions. Use only TLS 1.2 and TLS 1.3",
                cwe_id="CWE-327",
                owasp_category="A02:2021 – Cryptographic Failures",
                references=[
                    "https://tools.ietf.org/html/rfc8996"
                ]
            ))
        elif 'TLSv1.1' in version:
            misconfigurations.append(Misconfiguration(
                title=f"Deprecated TLS Protocol: {version}",
                description=f"Server supports deprecated TLS 1.1",
                severity=SeverityLevel.MEDIUM,
                affected_component="TLS Configuration",
                current_value=version,
                recommended_value="TLS 1.2 or TLS 1.3 only",
                remediation="Disable TLS 1.1, use only TLS 1.2 and TLS 1.3"
            ))

        return vulnerabilities, misconfigurations
