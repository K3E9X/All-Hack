"""
OpenClaw - Offensive Agent Loop for All-Hack

An intelligent, LLM-powered agent that:
- Plans attack strategies based on target context
- Executes tools autonomously with learning
- Chains vulnerabilities for maximum impact
- Learns from successful patterns
"""

from .core.agent_loop import AgentLoop
from .core.task_planner import TaskPlanner
from .tools.registry import ToolRegistry
from .memory.learning import MemorySystem

__all__ = [
    "AgentLoop",
    "TaskPlanner",
    "ToolRegistry",
    "MemorySystem"
]
