"""
Tool Registry - Central registry for all agent tools
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from .base import BaseTool, ToolParameter, ToolCategory


@dataclass
class Tool:
    """Tool metadata for registry"""
    name: str
    description: str
    category: ToolCategory
    parameters: List[ToolParameter]
    handler: BaseTool


class ToolRegistry:
    """
    Central registry for all available tools

    Manages tool registration, lookup, and provides
    tool schemas for LLM function calling.
    """

    def __init__(self):
        self._tools: Dict[str, Tool] = {}
        self._by_category: Dict[ToolCategory, List[str]] = {cat: [] for cat in ToolCategory}

    def register(self, tool: BaseTool):
        """Register a tool"""
        entry = Tool(
            name=tool.name,
            description=tool.description,
            category=tool.category,
            parameters=tool.parameters,
            handler=tool
        )
        self._tools[tool.name] = entry
        self._by_category[tool.category].append(tool.name)

    def unregister(self, name: str):
        """Remove a tool from registry"""
        if name in self._tools:
            tool = self._tools[name]
            self._by_category[tool.category].remove(name)
            del self._tools[name]

    def get_tool(self, name: str) -> Optional[BaseTool]:
        """Get tool by name"""
        entry = self._tools.get(name)
        return entry.handler if entry else None

    def has_tool(self, name: str) -> bool:
        """Check if tool exists"""
        return name in self._tools

    def get_all_tools(self) -> List[Tool]:
        """Get all registered tools"""
        return list(self._tools.values())

    def get_by_category(self, category: ToolCategory) -> List[Tool]:
        """Get tools in a category"""
        return [self._tools[name] for name in self._by_category.get(category, [])]

    def get_tool_names(self) -> List[str]:
        """Get list of all tool names"""
        return list(self._tools.keys())

    def get_llm_schemas(self) -> List[Dict[str, Any]]:
        """Get all tool schemas for LLM function calling"""
        return [tool.handler.to_llm_schema() for tool in self._tools.values()]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize registry"""
        return {
            "tools": [tool.handler.to_dict() for tool in self._tools.values()],
            "categories": {
                cat.value: self._by_category[cat]
                for cat in ToolCategory
            }
        }


def create_default_registry() -> ToolRegistry:
    """Create registry with default offensive tools"""
    from .offensive import (
        CrawlTool,
        TechDetectTool,
        SQLiTool,
        XSSTool,
        RCETool,
        SSRFTool,
        LFITool,
        AuthTestTool,
        UnifiedScanTool,
        ChainAnalysisTool
    )

    registry = ToolRegistry()

    # Recon tools
    registry.register(CrawlTool())
    registry.register(TechDetectTool())

    # Vulnerability testing tools
    registry.register(SQLiTool())
    registry.register(XSSTool())
    registry.register(RCETool())
    registry.register(SSRFTool())
    registry.register(LFITool())
    registry.register(AuthTestTool())

    # Analysis tools
    registry.register(UnifiedScanTool())
    registry.register(ChainAnalysisTool())

    return registry
