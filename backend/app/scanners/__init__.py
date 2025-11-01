"""
Scanner modules initialization
"""
from .reconnaissance.tech_detection import TechnologyDetector
from .reconnaissance.endpoint_discovery import EndpointDiscovery
from .owasp.sql_injection import SQLInjectionScanner
from .owasp.xss_scanner import XSSScanner
from .owasp.command_injection import CommandInjectionScanner
from .owasp.ssrf_scanner import SSRFScanner
from .access_control.idor_scanner import IDORScanner
from .access_control.privilege_escalation import PrivilegeEscalationScanner, HorizontalPrivilegeScanner
from .misconfig.security_headers import SecurityHeadersScanner
from .misconfig.cors_scanner import CORSScanner

__all__ = [
    "TechnologyDetector",
    "EndpointDiscovery",
    "SQLInjectionScanner",
    "XSSScanner",
    "CommandInjectionScanner",
    "SSRFScanner",
    "IDORScanner",
    "PrivilegeEscalationScanner",
    "HorizontalPrivilegeScanner",
    "SecurityHeadersScanner",
    "CORSScanner",
]
