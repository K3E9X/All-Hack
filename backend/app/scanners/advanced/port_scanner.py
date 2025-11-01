"""
Advanced Port Scanner with Service Detection
"""
import asyncio
import socket
import ssl
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from app.models import Vulnerability, Misconfiguration, SeverityLevel, VulnerabilityCategory

logger = logging.getLogger(__name__)

class PortScanner:
    """
    Advanced port scanner with service detection and vulnerability identification
    """

    # Common ports to scan
    COMMON_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        111,   # RPC
        135,   # MSRPC
        139,   # NetBIOS
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        993,   # IMAPS
        995,   # POP3S
        1433,  # MSSQL
        1521,  # Oracle
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        8000,  # HTTP Alt
        8080,  # HTTP Proxy
        8443,  # HTTPS Alt
        8888,  # HTTP Alt
        9090,  # HTTP Alt
        27017, # MongoDB
        5984,  # CouchDB
        6379,  # Redis
        11211, # Memcached
    ]

    # Service signatures
    SERVICE_SIGNATURES = {
        21: ('FTP', ['220', 'FTP']),
        22: ('SSH', ['SSH-2.0', 'SSH-1.99']),
        23: ('Telnet', ['Login:', 'Welcome']),
        25: ('SMTP', ['220', 'SMTP', 'ESMTP']),
        80: ('HTTP', ['HTTP/', 'Server:']),
        110: ('POP3', ['+OK', 'POP3']),
        143: ('IMAP', ['* OK', 'IMAP']),
        443: ('HTTPS', ['HTTP/', 'Server:']),
        3306: ('MySQL', ['mysql', 'MariaDB']),
        5432: ('PostgreSQL', ['PostgreSQL']),
        6379: ('Redis', ['-DENIED', '+PONG']),
        27017: ('MongoDB', ['MongoDB']),
        9200: ('Elasticsearch', ['cluster_name']),
        11211: ('Memcached', ['STAT', 'END']),
    }

    # Vulnerable service versions
    VULNERABLE_VERSIONS = {
        'Apache': [
            ('2.4.49', 'CVE-2021-41773 - Path Traversal'),
            ('2.4.50', 'CVE-2021-42013 - Path Traversal'),
        ],
        'nginx': [
            ('1.20.0', 'CVE-2021-23017 - DNS resolver off-by-one'),
        ],
        'OpenSSH': [
            ('7.4', 'CVE-2018-15473 - User enumeration'),
            ('< 7.7', 'CVE-2018-15919 - User enumeration'),
        ],
        'ProFTPD': [
            ('1.3.5', 'CVE-2015-3306 - Command injection'),
        ],
    }

    def __init__(self, target_url: str):
        parsed = urlparse(target_url)
        self.target_host = parsed.hostname
        self.target_ip = None

    async def scan(self) -> tuple[List[Dict[str, Any]], List[Vulnerability], List[Misconfiguration]]:
        """
        Perform comprehensive port scan

        Returns:
            (open_ports, vulnerabilities, misconfigurations)
        """
        open_ports = []
        vulnerabilities = []
        misconfigurations = []

        # Resolve hostname to IP
        try:
            self.target_ip = socket.gethostbyname(self.target_host)
            logger.info(f"Resolved {self.target_host} to {self.target_ip}")
        except socket.gaierror:
            logger.error(f"Failed to resolve {self.target_host}")
            return open_ports, vulnerabilities, misconfigurations

        # Scan ports
        logger.info(f"Scanning {len(self.COMMON_PORTS)} common ports...")

        tasks = []
        for port in self.COMMON_PORTS:
            tasks.append(self._scan_port(port))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result.get('open'):
                open_ports.append(result)

                # Check for vulnerabilities
                port_vulns, port_misconfigs = self._analyze_service(result)
                vulnerabilities.extend(port_vulns)
                misconfigurations.extend(port_misconfigs)

        logger.info(f"Found {len(open_ports)} open ports")
        return open_ports, vulnerabilities, misconfigurations

    async def _scan_port(self, port: int) -> Dict[str, Any]:
        """Scan a single port"""
        try:
            # Create connection with timeout
            conn = asyncio.open_connection(self.target_ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=2.0)

            # Port is open, try to grab banner
            service_name, version, banner = await self._detect_service(reader, writer, port)

            writer.close()
            await writer.wait_closed()

            return {
                'open': True,
                'port': port,
                'service': service_name,
                'version': version,
                'banner': banner,
                'protocol': 'tcp'
            }

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return {'open': False, 'port': port}
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")
            return {'open': False, 'port': port}

    async def _detect_service(self, reader, writer, port: int) -> tuple[str, str, str]:
        """Detect service and version on open port"""
        service_name = self.SERVICE_SIGNATURES.get(port, ('Unknown', []))[0]
        version = ''
        banner = ''

        try:
            # Try to read banner
            writer.write(b'\r\n')
            await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            banner = data.decode('utf-8', errors='ignore').strip()

            # Parse version from banner
            if banner:
                version = self._extract_version(banner)

            # Protocol-specific probes
            if port == 80 or port == 8080:
                writer.write(b'GET / HTTP/1.0\r\n\r\n')
                await writer.drain()
                data = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                banner = data.decode('utf-8', errors='ignore')
                version = self._extract_version(banner)

                if 'Server:' in banner:
                    for line in banner.split('\n'):
                        if 'Server:' in line:
                            service_name = line.split('Server:')[1].strip().split()[0]
                            break

            elif port == 22:
                # SSH version is sent immediately
                service_name = 'OpenSSH' if 'OpenSSH' in banner else 'SSH'

            elif port == 21:
                service_name = 'FTP'
                if 'ProFTPD' in banner:
                    service_name = 'ProFTPD'
                elif 'vsftpd' in banner:
                    service_name = 'vsftpd'

        except Exception as e:
            logger.debug(f"Error detecting service on port {port}: {e}")

        return service_name, version, banner

    def _extract_version(self, banner: str) -> str:
        """Extract version number from banner"""
        import re

        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
            r'version\s+(\d+\.\d+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)

        return ''

    def _analyze_service(self, port_info: Dict[str, Any]) -> tuple[List[Vulnerability], List[Misconfiguration]]:
        """Analyze open port for vulnerabilities and misconfigurations"""
        vulnerabilities = []
        misconfigurations = []

        port = port_info['port']
        service = port_info['service']
        version = port_info['version']

        # Check for dangerous open ports
        if port in [23, 111, 135, 139, 445]:
            misconfigurations.append(Misconfiguration(
                title=f"Dangerous Port {port} Open",
                description=f"Port {port} ({service}) should not be exposed to the internet",
                severity=SeverityLevel.HIGH,
                affected_component=f"Port {port}/{service}",
                remediation=f"Close port {port} or restrict access with firewall rules. "
                          f"This port is commonly targeted by attackers."
            ))

        # Check for unencrypted services
        if port in [21, 23, 80, 8080]:
            if port in [21, 23]:
                severity = SeverityLevel.HIGH
            else:
                severity = SeverityLevel.MEDIUM

            misconfigurations.append(Misconfiguration(
                title=f"Unencrypted Service on Port {port}",
                description=f"{service} transmits data in cleartext",
                severity=severity,
                affected_component=f"Port {port}/{service}",
                recommended_value=f"Use encrypted alternative (FTPS, SSH, HTTPS)",
                remediation=f"Replace {service} with encrypted alternative to prevent eavesdropping"
            ))

        # Check for databases exposed
        if port in [3306, 5432, 27017, 6379, 9200, 11211, 1433, 1521]:
            vulnerabilities.append(Vulnerability(
                id=f"exposed_db_{port}",
                title=f"Database Service Exposed on Port {port}",
                description=f"{service} database is directly accessible from the internet",
                severity=SeverityLevel.CRITICAL,
                category=VulnerabilityCategory.SECURITY_MISCONFIG,
                affected_url=f"tcp://{self.target_host}:{port}",
                proof_of_concept=f"Database service {service} is accessible on port {port}. "
                               f"This allows direct attacks on the database.",
                remediation="Never expose database ports to the internet. "
                          "Use firewall rules to restrict access. "
                          "Access databases only through application layer. "
                          "Use VPN for administrative access.",
                cwe_id="CWE-668",
                owasp_category="A05:2021 – Security Misconfiguration",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"
                ]
            ))

        # Check for vulnerable versions
        if version and service in self.VULNERABLE_VERSIONS:
            for vuln_version, description in self.VULNERABLE_VERSIONS[service]:
                if version in vuln_version or vuln_version.startswith('<'):
                    vulnerabilities.append(Vulnerability(
                        id=f"vulnerable_version_{service}_{port}",
                        title=f"Vulnerable {service} Version Detected",
                        description=description,
                        severity=SeverityLevel.HIGH,
                        category=VulnerabilityCategory.VULNERABLE_COMPONENTS,
                        affected_url=f"tcp://{self.target_host}:{port}",
                        affected_parameter=f"{service} {version}",
                        proof_of_concept=f"Service {service} version {version} has known vulnerabilities",
                        remediation=f"Update {service} to the latest stable version",
                        cwe_id="CWE-1104",
                        owasp_category="A06:2021 – Vulnerable and Outdated Components",
                        references=[]
                    ))

        # Check for Redis without auth
        if port == 6379 and '-DENIED' not in port_info.get('banner', ''):
            vulnerabilities.append(Vulnerability(
                id="redis_no_auth",
                title="Redis Without Authentication",
                description="Redis server is accessible without authentication",
                severity=SeverityLevel.CRITICAL,
                category=VulnerabilityCategory.BROKEN_AUTH,
                affected_url=f"tcp://{self.target_host}:6379",
                proof_of_concept="Redis server allows connections without password. "
                               "Attackers can read/write/delete data.",
                remediation="Enable Redis authentication with 'requirepass' directive. "
                          "Restrict network access with firewall.",
                cwe_id="CWE-306",
                owasp_category="A07:2021 – Identification and Authentication Failures",
                references=[
                    "https://redis.io/topics/security"
                ]
            ))

        return vulnerabilities, misconfigurations
