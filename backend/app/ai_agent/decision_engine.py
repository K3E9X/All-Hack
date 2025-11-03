"""
Decision Engine for mapping AI decisions to executable actions
"""

import logging
from typing import Dict, Any, List, Callable, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TestAction:
    """Represents a test action to be executed"""
    test_name: str
    scanner_class: Optional[Any]  # Scanner class to instantiate
    target_endpoints: List[str]
    priority: str
    reason: str
    custom_params: Dict[str, Any]


class DecisionEngine:
    """
    Maps AI agent decisions to executable scanner actions
    """

    def __init__(self):
        """Initialize decision engine with test mappings"""
        self.test_registry: Dict[str, Callable] = {}
        self._register_default_tests()

    def _register_default_tests(self):
        """Register default test types that AI can recommend"""

        # This will be expanded as we add more specialized scanners
        self.test_registry = {
            "jwt_deep_analysis": {
                "description": "Deep JWT security analysis",
                "scanner": "JWTSecurityScanner",
                "params": {"deep_mode": True}
            },
            "graphql_advanced": {
                "description": "Advanced GraphQL testing",
                "scanner": "GraphQLSecurityScanner",
                "params": {"test_all_features": True}
            },
            "nosql_advanced": {
                "description": "Advanced NoSQL injection",
                "scanner": "NoSQLInjectionScanner",
                "params": {"aggressive": True}
            },
            "api_fuzzing": {
                "description": "API endpoint fuzzing",
                "scanner": "APIFuzzer",  # To be implemented
                "params": {}
            },
            "session_management": {
                "description": "Session security testing",
                "scanner": "SessionScanner",  # To be implemented
                "params": {}
            },
            "rate_limiting": {
                "description": "Rate limit testing",
                "scanner": "RateLimitScanner",  # To be implemented
                "params": {}
            },
            "business_logic": {
                "description": "Business logic flaw testing",
                "scanner": "BusinessLogicScanner",  # To be implemented
                "params": {}
            },
            "file_upload_advanced": {
                "description": "Advanced file upload testing",
                "scanner": "FileUploadScanner",
                "params": {"aggressive": True}
            },
            "authentication_bypass": {
                "description": "Authentication bypass attempts",
                "scanner": "AuthBypassScanner",  # To be implemented
                "params": {}
            },
            "authorization_escalation": {
                "description": "Authorization testing",
                "scanner": "IDORScanner",  # Reuse existing
                "params": {"deep_mode": True}
            }
        }

    def parse_action(self, action_dict: Dict[str, Any], available_endpoints: List[str]) -> TestAction:
        """
        Parse an AI-recommended action into an executable TestAction

        Args:
            action_dict: Action dictionary from AI agent
            available_endpoints: List of available endpoints to test

        Returns:
            TestAction object ready for execution
        """
        test_name = action_dict.get('test', 'unknown')
        target = action_dict.get('target', 'all')
        priority = action_dict.get('priority', 'medium')
        reason = action_dict.get('reason', 'AI recommended test')

        # Determine which endpoints to target
        if target == 'all':
            target_endpoints = available_endpoints
        elif isinstance(target, str) and target.startswith('http'):
            target_endpoints = [target]
        else:
            # Try to match by keyword
            target_endpoints = [
                ep for ep in available_endpoints
                if target.lower() in ep.lower()
            ]
            # Fallback to all if no match
            if not target_endpoints:
                target_endpoints = available_endpoints

        # Get test details from registry
        test_info = self.test_registry.get(test_name, {})
        custom_params = test_info.get('params', {})

        logger.info(f"📋 Parsed action: {test_name} on {len(target_endpoints)} endpoints")

        return TestAction(
            test_name=test_name,
            scanner_class=test_info.get('scanner'),
            target_endpoints=target_endpoints,
            priority=priority,
            reason=reason,
            custom_params=custom_params
        )

    def is_test_available(self, test_name: str) -> bool:
        """Check if a test is available in the registry"""
        return test_name in self.test_registry

    def get_available_tests(self) -> List[Dict[str, str]]:
        """Get list of all available tests"""
        return [
            {
                "name": test_name,
                "description": test_info.get('description', ''),
                "scanner": test_info.get('scanner', '')
            }
            for test_name, test_info in self.test_registry.items()
        ]

    def register_custom_test(self, test_name: str, scanner_class: str,
                           description: str, params: Optional[Dict[str, Any]] = None):
        """
        Register a custom test type

        Args:
            test_name: Name of the test (used by AI)
            scanner_class: Scanner class name
            description: Human-readable description
            params: Default parameters for the scanner
        """
        self.test_registry[test_name] = {
            "description": description,
            "scanner": scanner_class,
            "params": params or {}
        }

        logger.info(f"✅ Registered custom test: {test_name}")
