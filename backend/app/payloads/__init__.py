"""
Advanced Payloads Collection for Pentest Automation
Organized by vulnerability type with WAF bypass variants
"""

from .sqli import SQLI_PAYLOADS, SQLI_WAF_BYPASS
from .xss import XSS_PAYLOADS, XSS_WAF_BYPASS, XSS_POLYGLOTS
from .ssti import SSTI_PAYLOADS, SSTI_BY_ENGINE
from .xxe import XXE_PAYLOADS, XXE_OOB_PAYLOADS
from .nosql import NOSQL_PAYLOADS
from .jwt import JWT_ATTACKS
from .graphql import GRAPHQL_PAYLOADS
from .deserialization import DESER_PAYLOADS
from .lfi import LFI_PAYLOADS, LFI_WRAPPERS
from .rce import RCE_PAYLOADS, RCE_BY_OS
from .ssrf import SSRF_PAYLOADS, SSRF_BYPASS

__all__ = [
    'SQLI_PAYLOADS', 'SQLI_WAF_BYPASS',
    'XSS_PAYLOADS', 'XSS_WAF_BYPASS', 'XSS_POLYGLOTS',
    'SSTI_PAYLOADS', 'SSTI_BY_ENGINE',
    'XXE_PAYLOADS', 'XXE_OOB_PAYLOADS',
    'NOSQL_PAYLOADS',
    'JWT_ATTACKS',
    'GRAPHQL_PAYLOADS',
    'DESER_PAYLOADS',
    'LFI_PAYLOADS', 'LFI_WRAPPERS',
    'RCE_PAYLOADS', 'RCE_BY_OS',
    'SSRF_PAYLOADS', 'SSRF_BYPASS',
]
