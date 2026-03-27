"""
Base Tool class for Agent Loop
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class ToolCategory(str, Enum):
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    ANALYSIS = "analysis"
    UTILITY = "utility"


@dataclass
class ToolParameter:
    """Definition of a tool parameter"""
    name: str
    type: str  # "string", "int", "bool", "array", "object"
    description: str
    required: bool = True
    default: Any = None
    enum: List[Any] = None  # Allowed values


@dataclass
class ToolResult:
    """Standardized tool execution result"""
    success: bool
    data: Any = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseTool(ABC):
    """
    Base class for all agent tools

    Each tool must implement:
    - name: Unique identifier
    - description: What the tool does
    - parameters: List of ToolParameter definitions
    - execute: Async execution method
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique tool identifier"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description"""
        pass

    @property
    @abstractmethod
    def category(self) -> ToolCategory:
        """Tool category for organization"""
        pass

    @property
    @abstractmethod
    def parameters(self) -> List[ToolParameter]:
        """List of parameter definitions"""
        pass

    @abstractmethod
    async def execute(self, **kwargs) -> ToolResult:
        """
        Execute the tool with given parameters

        Returns:
            ToolResult with success status, data, and any findings
        """
        pass

    def validate_params(self, params: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Validate parameters against definitions"""
        for param in self.parameters:
            if param.required and param.name not in params:
                return False, f"Missing required parameter: {param.name}"

            if param.name in params and param.enum:
                if params[param.name] not in param.enum:
                    return False, f"Invalid value for {param.name}. Must be one of: {param.enum}"

        return True, None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize tool definition"""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "parameters": [
                {
                    "name": p.name,
                    "type": p.type,
                    "description": p.description,
                    "required": p.required,
                    "default": p.default,
                    "enum": p.enum
                }
                for p in self.parameters
            ]
        }

    def to_llm_schema(self) -> Dict[str, Any]:
        """Convert to LLM function calling schema"""
        properties = {}
        required = []

        for param in self.parameters:
            prop = {
                "type": param.type,
                "description": param.description
            }
            if param.enum:
                prop["enum"] = param.enum
            if param.default is not None:
                prop["default"] = param.default

            properties[param.name] = prop

            if param.required:
                required.append(param.name)

        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }
