"""
GraphQL Security Testing Scanner
Tests for introspection, batching attacks, injection flaws, and access control issues
"""

import json
import hashlib
import asyncio
from typing import List, Optional, Dict, Any
import logging

from app.models.scan import Vulnerability, SeverityLevel, VulnerabilityCategory
from app.http.client import PentestHTTPClient

logger = logging.getLogger(__name__)


class GraphQLSecurityScanner:
    """Scanner for GraphQL-specific vulnerabilities"""

    # Introspection query to discover schema
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                name
                kind
                description
                fields {
                    name
                    description
                    args { name type { name kind ofType { name kind } } }
                    type { name kind ofType { name kind } }
                }
            }
        }
    }
    """

    # Batch query attack (alias-based)
    BATCH_ATTACK_TEMPLATE = """
    query BatchAttack {{
        {aliases}
    }}
    """

    # Deep nested query for DoS
    NESTED_QUERY_TEMPLATE = """
    query DeepNesting {{
        {nested_structure}
    }}
    """

    def __init__(self, client: PentestHTTPClient, scan_depth: str = "balanced", progress_callback=None):
        self.client = client
        self.scan_depth = scan_depth
        self.progress_callback = progress_callback
        self.discovered_graphql_endpoints: List[str] = []

        # Adjust depth
        if scan_depth == "quick":
            self.test_introspection = True
            self.test_batching = True
            self.test_nested_queries = False
            self.test_injection = False
            self.max_batch_size = 10
        elif scan_depth == "balanced":
            self.test_introspection = True
            self.test_batching = True
            self.test_nested_queries = True
            self.test_injection = True
            self.max_batch_size = 50
        else:  # deep
            self.test_introspection = True
            self.test_batching = True
            self.test_nested_queries = True
            self.test_injection = True
            self.max_batch_size = 100

    async def scan(self, endpoints: List[str]) -> List[Vulnerability]:
        """Scan for GraphQL vulnerabilities"""
        vulnerabilities = []

        if self.progress_callback:
            await self.progress_callback(f"🎨 Starting GraphQL Security Testing on {len(endpoints)} endpoints...")

        # Step 1: Discover GraphQL endpoints
        graphql_endpoints = await self._discover_graphql_endpoints(endpoints)

        if not graphql_endpoints:
            if self.progress_callback:
                await self.progress_callback("ℹ️  No GraphQL endpoints discovered")
            return vulnerabilities

        if self.progress_callback:
            await self.progress_callback(f"🎯 Found {len(graphql_endpoints)} GraphQL endpoints, starting security tests...")

        # Step 2: Test each discovered GraphQL endpoint
        for idx, endpoint in enumerate(graphql_endpoints, 1):
            if self.progress_callback:
                await self.progress_callback(f"🔍 Testing GraphQL endpoint {idx}/{len(graphql_endpoints)}: {endpoint[:60]}...")

            try:
                # Test for introspection
                if self.test_introspection:
                    vulns = await self._test_introspection(endpoint)
                    vulnerabilities.extend(vulns)

                # Test for batching attacks
                if self.test_batching:
                    vulns = await self._test_batching_attacks(endpoint)
                    vulnerabilities.extend(vulns)

                # Test for nested query DoS
                if self.test_nested_queries:
                    vulns = await self._test_nested_queries(endpoint)
                    vulnerabilities.extend(vulns)

                # Test for injection flaws
                if self.test_injection:
                    vulns = await self._test_injection_flaws(endpoint)
                    vulnerabilities.extend(vulns)

                if vulnerabilities and self.progress_callback:
                    await self.progress_callback(f"✅ Found GraphQL vulnerabilities on {endpoint[:60]}")

            except Exception as e:
                logger.error(f"Error testing GraphQL endpoint {endpoint}: {e}")
                if self.progress_callback:
                    await self.progress_callback(f"⚠️  Error testing GraphQL on {endpoint[:60]}: {str(e)[:50]}")

        return vulnerabilities

    async def _discover_graphql_endpoints(self, endpoints: List[str]) -> List[str]:
        """Discover GraphQL endpoints"""
        graphql_endpoints = []

        # Common GraphQL paths
        common_paths = [
            '/graphql',
            '/graphiql',
            '/api/graphql',
            '/v1/graphql',
            '/query',
            '/api/query',
            '/gql'
        ]

        # Check base URL with common paths
        for endpoint in endpoints[:10]:  # Check first 10 endpoints
            base_url = endpoint.rsplit('/', 1)[0] if '/' in endpoint else endpoint

            for path in common_paths:
                test_url = f"{base_url}{path}"

                try:
                    # Try a simple GraphQL query
                    response = await self._send_graphql_query(test_url, "{ __typename }")

                    if response and self._is_graphql_response(response):
                        graphql_endpoints.append(test_url)
                        logger.info(f"Found GraphQL endpoint: {test_url}")
                        break

                except Exception as e:
                    logger.debug(f"Not a GraphQL endpoint: {test_url} - {e}")

        # Also check if any discovered endpoint responds to GraphQL queries
        for endpoint in endpoints:
            if any(keyword in endpoint.lower() for keyword in ['graphql', 'gql', 'query']):
                try:
                    response = await self._send_graphql_query(endpoint, "{ __typename }")
                    if response and self._is_graphql_response(response):
                        if endpoint not in graphql_endpoints:
                            graphql_endpoints.append(endpoint)
                            logger.info(f"Found GraphQL endpoint: {endpoint}")
                except Exception:
                    pass

        return graphql_endpoints

    async def _send_graphql_query(self, endpoint: str, query: str, variables: Optional[Dict] = None) -> Optional[Any]:
        """Send a GraphQL query"""
        try:
            payload = {"query": query}
            if variables:
                payload["variables"] = variables

            response = await self.client.post(endpoint, json=payload)

            if hasattr(response, 'json'):
                return response.json()
            elif hasattr(response, 'text'):
                return json.loads(response.text)

            return None

        except Exception as e:
            logger.debug(f"GraphQL query failed: {e}")
            return None

    def _is_graphql_response(self, response: Any) -> bool:
        """Check if response looks like a GraphQL response"""
        if not response:
            return False

        if isinstance(response, dict):
            # GraphQL responses typically have 'data' or 'errors' keys
            return 'data' in response or 'errors' in response

        return False

    async def _test_introspection(self, endpoint: str) -> List[Vulnerability]:
        """Test if GraphQL introspection is enabled"""
        vulnerabilities = []

        try:
            response = await self._send_graphql_query(endpoint, self.INTROSPECTION_QUERY)

            if response and 'data' in response and '__schema' in response.get('data', {}):
                schema = response['data']['__schema']
                types_count = len(schema.get('types', []))

                vulnerabilities.append(Vulnerability(
                    id=f"graphql_introspection_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                    title="GraphQL Introspection Enabled in Production",
                    description=f"The GraphQL endpoint has introspection enabled, exposing the entire API schema ({types_count} types discovered). This allows attackers to discover all available queries, mutations, and data structures.",
                    severity=SeverityLevel.MEDIUM,
                    category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    affected_url=endpoint,
                    affected_parameter="GraphQL Introspection",
                    proof_of_concept=f"Successfully retrieved schema with {types_count} types using introspection query. Schema includes: {', '.join([t.get('name', 'Unknown') for t in schema.get('types', [])[:5]])}...",
                    payload=self.INTROSPECTION_QUERY,
                    remediation="Disable introspection in production environments. Only enable it in development/staging. Use schema validation and query complexity analysis.",
                    cwe_id="CWE-209",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    references=[
                        "https://graphql.org/learn/introspection/",
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"
                    ]
                ))
                logger.warning(f"GraphQL introspection enabled on {endpoint}")

        except Exception as e:
            logger.debug(f"Introspection test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_batching_attacks(self, endpoint: str) -> List[Vulnerability]:
        """Test for batching/alias-based attacks that can bypass rate limits"""
        vulnerabilities = []

        try:
            # Create a batch query with many aliases
            aliases = '\n'.join([f'alias{i}: __typename' for i in range(self.max_batch_size)])
            batch_query = self.BATCH_ATTACK_TEMPLATE.format(aliases=aliases)

            response = await self._send_graphql_query(endpoint, batch_query)

            if response and 'data' in response:
                data = response['data']
                # Check if all aliases were processed
                successful_aliases = len([k for k in data.keys() if k.startswith('alias')])

                if successful_aliases >= 10:  # If 10 or more aliases worked
                    vulnerabilities.append(Vulnerability(
                        id=f"graphql_batch_attack_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                        title="GraphQL Batching/Aliasing DoS Vulnerability",
                        description=f"The GraphQL endpoint accepts batch queries with {successful_aliases} aliases, which can be exploited to bypass rate limits, perform brute-force attacks (e.g., on 2FA codes), or cause DoS.",
                        severity=SeverityLevel.HIGH,
                        category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                        affected_url=endpoint,
                        affected_parameter="GraphQL Query Batching",
                        proof_of_concept=f"Successfully executed batch query with {successful_aliases} aliases. This can be used to send {successful_aliases} requests as a single HTTP request, bypassing rate limits.",
                        payload=batch_query[:500] + "...",
                        remediation="Implement query complexity analysis and limit the maximum number of aliases per query (recommend: 5-10). Add rate limiting based on query complexity, not just HTTP requests.",
                        cwe_id="CWE-770",
                        owasp_category="A04:2021 – Insecure Design",
                        references=[
                            "https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"
                        ]
                    ))
                    logger.warning(f"GraphQL batching attack successful on {endpoint}")

        except Exception as e:
            logger.debug(f"Batching test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_nested_queries(self, endpoint: str) -> List[Vulnerability]:
        """Test for deep nested query vulnerabilities (DoS)"""
        vulnerabilities = []

        try:
            # Create deeply nested query (circular references)
            # This is a simple example; real attacks would use schema-specific nesting
            nested_depth = 10 if self.scan_depth == "balanced" else 20
            nested_structure = "{ __typename " * nested_depth + "}" * nested_depth

            nested_query = self.NESTED_QUERY_TEMPLATE.format(nested_structure=nested_structure)

            import time
            start_time = time.time()
            response = await self._send_graphql_query(endpoint, nested_query)
            elapsed_time = time.time() - start_time

            # If query took more than 2 seconds, it might be vulnerable
            if elapsed_time > 2.0:
                vulnerabilities.append(Vulnerability(
                    id=f"graphql_nested_query_{hashlib.md5(endpoint.encode()).hexdigest()[:8]}",
                    title="GraphQL Deep Nesting DoS Vulnerability",
                    description=f"The GraphQL endpoint accepts deeply nested queries (depth: {nested_depth}) without proper depth limiting, taking {elapsed_time:.2f} seconds to process. This can be exploited for DoS attacks.",
                    severity=SeverityLevel.MEDIUM,
                    category=VulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    affected_url=endpoint,
                    affected_parameter="GraphQL Query Depth",
                    proof_of_concept=f"Nested query with depth {nested_depth} took {elapsed_time:.2f} seconds to process. Attackers could use deeper nesting to exhaust server resources.",
                    payload=nested_query[:500] + "...",
                    remediation="Implement query depth limiting (recommend: max depth 5-7). Use query complexity analysis and timeout mechanisms. Consider using tools like graphql-depth-limit.",
                    cwe_id="CWE-400",
                    owasp_category="A04:2021 – Insecure Design",
                    references=[
                        "https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/",
                        "https://github.com/4Catalyzer/graphql-depth-limit"
                    ]
                ))
                logger.warning(f"GraphQL nested query vulnerability on {endpoint}")

        except Exception as e:
            logger.debug(f"Nested query test failed on {endpoint}: {e}")

        return vulnerabilities

    async def _test_injection_flaws(self, endpoint: str) -> List[Vulnerability]:
        """Test for injection flaws in GraphQL resolvers"""
        vulnerabilities = []

        # Common injection payloads
        injection_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "<script>alert('XSS')</script>",
            "${7*7}",
            "{{7*7}}",
            "../../../etc/passwd"
        ]

        try:
            # Try a simple query first to understand structure
            simple_query = "{ __typename }"
            response = await self._send_graphql_query(endpoint, simple_query)

            if not response:
                return vulnerabilities

            # Try injection in query variables
            for payload in injection_payloads[:3]:  # Test a few payloads
                test_query = """
                query TestInjection($input: String!) {
                    __typename
                }
                """
                variables = {"input": payload}

                response = await self._send_graphql_query(endpoint, test_query, variables)

                # Check for error messages that leak information
                if response and 'errors' in response:
                    errors = response['errors']
                    error_messages = ' '.join([str(e) for e in errors])

                    # Look for database errors, stack traces, etc.
                    if any(keyword in error_messages.lower() for keyword in ['sql', 'database', 'mysql', 'postgres', 'mongodb', 'syntax', 'query']):
                        vulnerabilities.append(Vulnerability(
                            id=f"graphql_injection_{hashlib.md5((endpoint + payload).encode()).hexdigest()[:8]}",
                            title="GraphQL Injection / Information Disclosure",
                            description="The GraphQL endpoint returns detailed error messages when processing malicious input, potentially exposing database information or internal implementation details.",
                            severity=SeverityLevel.MEDIUM,
                            category=VulnerabilityCategory.INJECTION,
                            affected_url=endpoint,
                            affected_parameter="GraphQL Variables",
                            proof_of_concept=f"Payload '{payload}' triggered error: {error_messages[:200]}",
                            payload=payload,
                            remediation="Sanitize all user input in GraphQL resolvers. Implement proper error handling that doesn't expose internal details. Use parameterized queries. Add input validation.",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021 – Injection",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"
                            ]
                        ))
                        logger.warning(f"GraphQL injection vulnerability on {endpoint}")
                        break

        except Exception as e:
            logger.debug(f"Injection test failed on {endpoint}: {e}")

        return vulnerabilities
