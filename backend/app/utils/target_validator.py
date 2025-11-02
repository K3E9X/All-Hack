"""
Target validation - Support both URLs and IP addresses
"""
import re
import socket
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, Optional

class TargetValidator:
    """Validate and normalize scan targets (URLs and IPs)"""

    @staticmethod
    def validate_and_normalize(target: str) -> Tuple[bool, str, Optional[str]]:
        """
        Validate and normalize target (URL or IP)

        Returns:
            (is_valid, normalized_target, error_message)
        """
        target = target.strip()

        # Try as IP address first
        if TargetValidator.is_ip_address(target):
            return True, TargetValidator.normalize_ip(target), None

        # Try as URL
        if TargetValidator.is_valid_url(target):
            return True, TargetValidator.normalize_url(target), None

        # Try to make it a URL
        if not target.startswith(('http://', 'https://')):
            # Check if it looks like a domain
            if '.' in target and not ' ' in target:
                # Try HTTPS first
                normalized = f'https://{target}'
                if TargetValidator.is_valid_url(normalized):
                    return True, normalized, None

                # Try HTTP
                normalized = f'http://{target}'
                if TargetValidator.is_valid_url(normalized):
                    return True, normalized, None

        return False, target, "Invalid target format. Please provide a valid URL or IP address."

    @staticmethod
    def is_ip_address(target: str) -> bool:
        """Check if target is a valid IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if target is a valid URL"""
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception:
            return False

    @staticmethod
    def normalize_ip(ip: str) -> str:
        """
        Normalize IP address to URL format

        Returns:
            http://IP_ADDRESS or https://IP_ADDRESS
        """
        # Try to detect if HTTPS is available (port 443 open)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 443))
            sock.close()

            if result == 0:
                return f'https://{ip}'
        except:
            pass

        # Default to HTTP
        return f'http://{ip}'

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'

        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def extract_host(target: str) -> str:
        """Extract hostname or IP from target"""
        if TargetValidator.is_ip_address(target):
            return target

        parsed = urlparse(target)
        return parsed.hostname or parsed.netloc or target

    @staticmethod
    def is_local_target(target: str) -> bool:
        """Check if target is localhost/internal IP"""
        host = TargetValidator.extract_host(target)

        # Check localhost
        if host in ['localhost', '127.0.0.1', '::1']:
            return True

        # Check private IP ranges
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback
        except:
            pass

        return False
