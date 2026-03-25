"""
API Security Testing Module

Tests for:
- OpenAPI/Swagger schema parsing
- BOLA (Broken Object Level Authorization)
- BFLA (Broken Function Level Authorization)
- Mass assignment
- Rate limiting
- Excessive data exposure
- Injection via API parameters
"""

import asyncio
import aiohttp
import re
import json
import yaml
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)


@dataclass
class APIFinding:
    vuln_type: str
    severity: str
    endpoint: str
    method: str
    description: str
    evidence: str
    poc: str


@dataclass
class APIEndpoint:
    path: str
    method: str
    parameters: List[Dict]
    responses: Dict
    security: List[Dict]
    description: str = ""


class APISecurityTester:
    """API security testing with schema parsing"""

    def __init__(self, session: aiohttp.ClientSession = None):
        self.session = session
        self.findings: List[APIFinding] = []
        self.endpoints: List[APIEndpoint] = []
        self.base_url: str = ""

    async def _ensure_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=False)
            )

    async def _request(self, method: str, url: str, **kwargs) -> Tuple[Optional[str], int, Dict]:
        await self._ensure_session()
        try:
            async with self.session.request(method, url, **kwargs) as resp:
                return await resp.text(), resp.status, dict(resp.headers)
        except Exception as e:
            logger.error(f"Request failed: {e}")
            return None, 0, {}

    # ==================== SCHEMA DISCOVERY ====================

    async def discover_api_schema(self, base_url: str) -> Optional[Dict]:
        """Discover and parse OpenAPI/Swagger schema"""
        self.base_url = base_url.rstrip("/")

        # Common schema locations
        schema_paths = [
            "/openapi.json",
            "/swagger.json",
            "/api/openapi.json",
            "/api/swagger.json",
            "/v1/openapi.json",
            "/v2/openapi.json",
            "/v3/openapi.json",
            "/api-docs",
            "/api-docs.json",
            "/swagger/v1/swagger.json",
            "/swagger/doc.json",
            "/.well-known/openapi.json",
            "/docs/openapi.json",
            "/openapi.yaml",
            "/swagger.yaml",
        ]

        for path in schema_paths:
            url = f"{self.base_url}{path}"
            resp, status, headers = await self._request("GET", url)

            if status == 200 and resp:
                try:
                    # Try JSON first
                    if resp.strip().startswith("{"):
                        schema = json.loads(resp)
                    else:
                        schema = yaml.safe_load(resp)

                    if schema and ("paths" in schema or "openapi" in schema or "swagger" in schema):
                        logger.info(f"Found API schema at {url}")
                        return schema
                except:
                    continue

        return None

    def parse_openapi_schema(self, schema: Dict) -> List[APIEndpoint]:
        """Parse OpenAPI schema into testable endpoints"""
        endpoints = []
        paths = schema.get("paths", {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ["get", "post", "put", "patch", "delete"]:
                    continue

                params = []

                # Path parameters
                for param in details.get("parameters", []):
                    params.append({
                        "name": param.get("name"),
                        "in": param.get("in"),
                        "type": param.get("schema", {}).get("type", "string"),
                        "required": param.get("required", False)
                    })

                # Request body
                if "requestBody" in details:
                    content = details["requestBody"].get("content", {})
                    for content_type, content_schema in content.items():
                        if "schema" in content_schema:
                            props = content_schema["schema"].get("properties", {})
                            for prop_name, prop_details in props.items():
                                params.append({
                                    "name": prop_name,
                                    "in": "body",
                                    "type": prop_details.get("type", "string"),
                                    "required": prop_name in content_schema["schema"].get("required", [])
                                })

                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=params,
                    responses=details.get("responses", {}),
                    security=details.get("security", []),
                    description=details.get("summary", details.get("description", ""))
                )
                endpoints.append(endpoint)

        self.endpoints = endpoints
        return endpoints

    # ==================== BOLA TESTING ====================

    async def test_bola(self, endpoint: APIEndpoint, auth_headers: Dict = None) -> List[APIFinding]:
        """Test for Broken Object Level Authorization"""
        findings = []

        # Find ID parameters
        id_params = [p for p in endpoint.parameters if
                     p["name"].lower() in ["id", "user_id", "userid", "account_id", "order_id"] or
                     p["in"] == "path"]

        if not id_params:
            return findings

        # Build URL with test IDs
        url_template = f"{self.base_url}{endpoint.path}"

        # Test with different IDs
        test_ids = ["1", "2", "0", "-1", "999999", "admin", "test"]

        for param in id_params:
            original_id = "1"  # Assume current user's ID

            for test_id in test_ids:
                if test_id == original_id:
                    continue

                # Replace ID in path
                test_url = url_template.replace(f"{{{param['name']}}}", test_id)

                headers = auth_headers or {}
                resp, status, _ = await self._request(endpoint.method, test_url, headers=headers)

                if status == 200 and resp:
                    # Check if we got valid data for another user
                    try:
                        data = json.loads(resp)
                        if data and (isinstance(data, dict) or isinstance(data, list)):
                            findings.append(APIFinding(
                                vuln_type="BOLA",
                                severity="critical",
                                endpoint=endpoint.path,
                                method=endpoint.method,
                                description=f"Access to object {test_id} without proper authorization",
                                evidence=f"Status 200 with data for ID {test_id}",
                                poc=f"""# BOLA PoC
curl -X {endpoint.method} "{test_url}" \\
  -H "Authorization: Bearer USER_TOKEN"

# Returns data for user {test_id} while authenticated as user {original_id}
"""
                            ))
                            break
                    except:
                        pass

        return findings

    # ==================== BFLA TESTING ====================

    async def test_bfla(self, auth_headers_user: Dict, auth_headers_admin: Dict = None) -> List[APIFinding]:
        """Test for Broken Function Level Authorization"""
        findings = []

        # Admin-only patterns
        admin_patterns = [
            r"/admin",
            r"/manage",
            r"/users$",
            r"/config",
            r"/settings",
            r"/system",
            r"/delete",
            r"/create",
            r"/update",
            r"/roles",
            r"/permissions",
        ]

        for endpoint in self.endpoints:
            is_admin_endpoint = any(re.search(p, endpoint.path, re.I) for p in admin_patterns)

            if is_admin_endpoint or endpoint.method in ["DELETE", "PUT", "PATCH"]:
                url = f"{self.base_url}{endpoint.path}"

                # Replace path params with test values
                url = re.sub(r"\{[^}]+\}", "1", url)

                # Test with regular user credentials
                resp, status, _ = await self._request(
                    endpoint.method, url,
                    headers=auth_headers_user
                )

                if status in [200, 201, 204]:
                    findings.append(APIFinding(
                        vuln_type="BFLA",
                        severity="critical",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        description="Admin functionality accessible with regular user credentials",
                        evidence=f"Status {status} on {endpoint.method} {endpoint.path}",
                        poc=f"""# BFLA PoC
curl -X {endpoint.method} "{url}" \\
  -H "Authorization: Bearer REGULAR_USER_TOKEN"

# Admin endpoint accessible without admin privileges
"""
                    ))

        return findings

    # ==================== MASS ASSIGNMENT ====================

    async def test_mass_assignment(self, endpoint: APIEndpoint, auth_headers: Dict = None) -> List[APIFinding]:
        """Test for mass assignment vulnerabilities"""
        findings = []

        if endpoint.method not in ["POST", "PUT", "PATCH"]:
            return findings

        # Sensitive fields to inject
        injection_fields = {
            "role": "admin",
            "is_admin": True,
            "isAdmin": True,
            "admin": True,
            "privilege": "admin",
            "privileges": ["admin"],
            "permissions": ["*"],
            "user_type": "admin",
            "userType": "admin",
            "verified": True,
            "is_verified": True,
            "active": True,
            "is_active": True,
            "credits": 999999,
            "balance": 999999,
            "price": 0,
            "discount": 100,
            "is_staff": True,
            "is_superuser": True,
        }

        url = f"{self.base_url}{endpoint.path}"
        url = re.sub(r"\{[^}]+\}", "1", url)

        # Build base payload from schema
        base_payload = {}
        for param in endpoint.parameters:
            if param["in"] == "body":
                if param["type"] == "string":
                    base_payload[param["name"]] = "test"
                elif param["type"] == "integer":
                    base_payload[param["name"]] = 1
                elif param["type"] == "boolean":
                    base_payload[param["name"]] = True

        # Add injection fields
        test_payload = {**base_payload, **injection_fields}

        headers = {"Content-Type": "application/json"}
        if auth_headers:
            headers.update(auth_headers)

        resp, status, _ = await self._request(
            endpoint.method, url,
            headers=headers,
            json=test_payload
        )

        if status in [200, 201]:
            try:
                data = json.loads(resp)
                # Check if any injected field was accepted
                for field, value in injection_fields.items():
                    if field in str(data):
                        findings.append(APIFinding(
                            vuln_type="Mass Assignment",
                            severity="high",
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            description=f"Sensitive field '{field}' can be set via API",
                            evidence=f"Field '{field}' present in response",
                            poc=f"""# Mass Assignment PoC
curl -X {endpoint.method} "{url}" \\
  -H "Content-Type: application/json" \\
  -d '{json.dumps(test_payload)}'
"""
                        ))
                        break
            except:
                pass

        return findings

    # ==================== RATE LIMITING ====================

    async def test_rate_limiting(self, endpoint: APIEndpoint, auth_headers: Dict = None) -> List[APIFinding]:
        """Test for rate limiting"""
        findings = []

        url = f"{self.base_url}{endpoint.path}"
        url = re.sub(r"\{[^}]+\}", "1", url)

        headers = auth_headers or {}
        request_count = 50
        success_count = 0

        for i in range(request_count):
            resp, status, resp_headers = await self._request(endpoint.method, url, headers=headers)

            if status == 429:
                # Rate limiting detected
                return findings

            if status in [200, 201, 204]:
                success_count += 1

            # Check for rate limit headers
            if any(h.lower() in ["x-ratelimit-limit", "x-rate-limit", "retry-after"]
                   for h in resp_headers.keys()):
                return findings

            await asyncio.sleep(0.05)

        if success_count == request_count:
            findings.append(APIFinding(
                vuln_type="Missing Rate Limiting",
                severity="medium",
                endpoint=endpoint.path,
                method=endpoint.method,
                description=f"No rate limiting detected after {request_count} requests",
                evidence=f"{success_count}/{request_count} requests succeeded",
                poc=f"""# Rate Limit Test
for i in $(seq 1 100); do
  curl -X {endpoint.method} "{url}" &
done
wait
"""
            ))

        return findings

    # ==================== EXCESSIVE DATA EXPOSURE ====================

    async def test_data_exposure(self, endpoint: APIEndpoint, auth_headers: Dict = None) -> List[APIFinding]:
        """Test for excessive data exposure"""
        findings = []

        if endpoint.method != "GET":
            return findings

        url = f"{self.base_url}{endpoint.path}"
        url = re.sub(r"\{[^}]+\}", "1", url)

        headers = auth_headers or {}
        resp, status, _ = await self._request("GET", url, headers=headers)

        if status == 200 and resp:
            # Sensitive patterns
            sensitive_patterns = [
                (r'"password":\s*"[^"]+', "password"),
                (r'"secret":\s*"[^"]+', "secret"),
                (r'"api_key":\s*"[^"]+', "api_key"),
                (r'"apiKey":\s*"[^"]+', "apiKey"),
                (r'"token":\s*"[^"]+', "token"),
                (r'"credit_card":\s*"[^"]+', "credit_card"),
                (r'"ssn":\s*"[^"]+', "ssn"),
                (r'"private_key":\s*"[^"]+', "private_key"),
                (r'"aws_secret":\s*"[^"]+', "aws_secret"),
                (r'"password_hash":\s*"[^"]+', "password_hash"),
                (r'"salt":\s*"[^"]+', "salt"),
            ]

            for pattern, field_name in sensitive_patterns:
                if re.search(pattern, resp, re.I):
                    findings.append(APIFinding(
                        vuln_type="Excessive Data Exposure",
                        severity="high",
                        endpoint=endpoint.path,
                        method="GET",
                        description=f"Sensitive field '{field_name}' exposed in API response",
                        evidence=f"Field '{field_name}' found in response",
                        poc=f"""# Data Exposure PoC
curl "{url}" | grep -i "{field_name}"
"""
                    ))

        return findings

    # ==================== FULL API TEST ====================

    async def full_test(
        self,
        base_url: str,
        auth_headers: Dict = None,
        admin_headers: Dict = None
    ) -> List[APIFinding]:
        """Run all API security tests"""
        all_findings = []

        # Discover schema
        schema = await self.discover_api_schema(base_url)

        if schema:
            self.parse_openapi_schema(schema)
            logger.info(f"Parsed {len(self.endpoints)} endpoints from schema")
        else:
            logger.warning("No API schema found, testing common endpoints")
            # Create default endpoints to test
            common_paths = [
                "/api/users", "/api/users/1", "/api/admin", "/api/config",
                "/api/orders", "/api/orders/1", "/api/profile", "/api/settings"
            ]
            for path in common_paths:
                for method in ["GET", "POST", "PUT", "DELETE"]:
                    self.endpoints.append(APIEndpoint(
                        path=path, method=method, parameters=[],
                        responses={}, security=[]
                    ))

        # Test each endpoint
        for endpoint in self.endpoints:
            # BOLA
            findings = await self.test_bola(endpoint, auth_headers)
            all_findings.extend(findings)

            # Mass Assignment
            findings = await self.test_mass_assignment(endpoint, auth_headers)
            all_findings.extend(findings)

            # Rate Limiting (sample only)
            if len(self.endpoints) < 10 or endpoint.method == "POST":
                findings = await self.test_rate_limiting(endpoint, auth_headers)
                all_findings.extend(findings)

            # Data Exposure
            findings = await self.test_data_exposure(endpoint, auth_headers)
            all_findings.extend(findings)

        # BFLA (needs both user and admin creds)
        if auth_headers and admin_headers:
            findings = await self.test_bfla(auth_headers, admin_headers)
            all_findings.extend(findings)

        self.findings = all_findings
        return all_findings
