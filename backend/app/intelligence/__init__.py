"""
Intelligence Layer

AI-powered analysis and automation for vulnerability assessment.
"""
from app.intelligence.llm_analyst import (
    LLMVulnerabilityAnalyst,
    VulnerabilityAnalysis,
    ScanSummary,
    get_llm_analyst
)
from app.intelligence.ollama_client import (
    OllamaClient,
    OllamaConfig,
    get_ollama_client
)
from app.intelligence.chat_agent import (
    ChatAgent,
    ChatSession,
    ChatMessage,
    get_chat_agent
)

__all__ = [
    "LLMVulnerabilityAnalyst",
    "VulnerabilityAnalysis",
    "ScanSummary",
    "get_llm_analyst",
    "OllamaClient",
    "OllamaConfig",
    "get_ollama_client",
    "ChatAgent",
    "ChatSession",
    "ChatMessage",
    "get_chat_agent",
]
