"""Collect OpenAPI and GraphQL schemas discovered during reconnaissance."""

from __future__ import annotations

import json
import logging
from typing import Dict, Iterable, List

from app.utils.http_client import PentestHTTPClient

logger = logging.getLogger(__name__)


GRAPHQL_INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
        }
      }
    }
    """.strip()
}


class APISchemaCollector:
    """Attempt to retrieve API schemas for targeted testing."""

    def __init__(self, client: PentestHTTPClient):
        self.client = client

    async def collect(self, candidate_paths: Iterable[str]) -> Dict[str, Dict]:
        schemas: Dict[str, Dict] = {}
        openapi_candidates = [
            "/openapi.json",
            "/swagger.json",
            "/v1/openapi.json",
            "/docs/json",
        ]

        for path in openapi_candidates:
            response = await self.client.get(path)
            if response and response.status_code < 400:
                try:
                    schemas[path] = response.json()
                    logger.info("Discovered OpenAPI schema at %s", path)
                except json.JSONDecodeError:
                    logger.debug("Non-JSON response for %s", path)

        for endpoint in candidate_paths:
            if "graphql" not in endpoint.lower():
                continue

            response = await self.client.post(endpoint, json=GRAPHQL_INTROSPECTION_QUERY)
            if response and response.status_code < 400:
                try:
                    data = response.json()
                    if data.get("data"):
                        schemas[endpoint] = data
                        logger.info("Captured GraphQL introspection from %s", endpoint)
                except json.JSONDecodeError:
                    logger.debug("GraphQL introspection failed for %s", endpoint)

        return schemas

