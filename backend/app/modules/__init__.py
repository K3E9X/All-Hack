"""
All-Hack Security Modules

Comprehensive security testing modules:
- auth_testing: Authentication security (session, OAuth, 2FA)
- api_security: API security (BOLA, BFLA, mass assignment)
- websocket_testing: WebSocket security (injection, auth bypass)
- chain_exploits: Chained exploitation (SSRF->RCE, LFI->RCE)
- recon: Automated reconnaissance (subdomains, ports, tech)
- fuzzer: Advanced fuzzing (mutation, grammar-based)
- crawler: Intelligent web crawling (forms, APIs, sitemap)
"""

from .auth_testing import AuthTester, AuthFinding
from .api_security import APISecurityTester, APIFinding, APIEndpoint
from .websocket_testing import WebSocketTester, WSFinding
from .chain_exploits import ChainExploiter, ExploitChain, ChainStep
from .recon import ReconScanner, ReconResult
from .fuzzer import AdvancedFuzzer, FuzzResult
from .crawler import IntelligentCrawler, CrawlResult, Form

__all__ = [
    # Auth Testing
    "AuthTester",
    "AuthFinding",

    # API Security
    "APISecurityTester",
    "APIFinding",
    "APIEndpoint",

    # WebSocket
    "WebSocketTester",
    "WSFinding",

    # Chain Exploits
    "ChainExploiter",
    "ExploitChain",
    "ChainStep",

    # Recon
    "ReconScanner",
    "ReconResult",

    # Fuzzer
    "AdvancedFuzzer",
    "FuzzResult",

    # Crawler
    "IntelligentCrawler",
    "CrawlResult",
    "Form",
]
