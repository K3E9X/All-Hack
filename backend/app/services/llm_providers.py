"""
LLM Provider Abstractions

Unified interface for multiple LLM providers.
Each provider can be configured independently with its own API key.
"""

import aiohttp
import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ProviderType(str, Enum):
    OPENAI = "openai"
    GROQ = "groq"
    GROK = "grok"
    OLLAMA = "ollama"
    QWEN = "qwen"
    ANTHROPIC = "anthropic"
    TOGETHER = "together"
    OPENROUTER = "openrouter"
    CODEX_ILIAD = "codex_iliad"


@dataclass
class ProviderConfig:
    """Configuration for an LLM provider"""
    provider_type: ProviderType
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: Optional[str] = None
    enabled: bool = True
    role: str = "general"  # general, analyst, payload_gen, validator
    priority: int = 0  # Lower = higher priority

    def __post_init__(self):
        # Set defaults based on provider type
        defaults = {
            ProviderType.OPENAI: {
                "base_url": "https://api.openai.com/v1",
                "model": "gpt-4o-mini"
            },
            ProviderType.GROQ: {
                "base_url": "https://api.groq.com/openai/v1",
                "model": "llama-3.1-70b-versatile"
            },
            ProviderType.GROK: {
                "base_url": "https://api.x.ai/v1",
                "model": "grok-beta"
            },
            ProviderType.OLLAMA: {
                "base_url": "http://localhost:11434",
                "model": "qwen2"
            },
            ProviderType.QWEN: {
                "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
                "model": "qwen-plus"
            },
            ProviderType.ANTHROPIC: {
                "base_url": "https://api.anthropic.com/v1",
                "model": "claude-3-haiku-20240307"
            },
            ProviderType.TOGETHER: {
                "base_url": "https://api.together.xyz/v1",
                "model": "meta-llama/Llama-3-70b-chat-hf"
            },
            ProviderType.OPENROUTER: {
                "base_url": "https://openrouter.ai/api/v1",
                "model": "meta-llama/llama-3.1-8b-instruct:free"
            },
            ProviderType.CODEX_ILIAD: {
                "base_url": "https://codex.datax.iliad.fr/v1",
                "model": "Qwen/Qwen3.5-397B-A17B"
            },
        }

        if self.provider_type in defaults:
            if not self.base_url:
                self.base_url = defaults[self.provider_type]["base_url"]
            if not self.model:
                self.model = defaults[self.provider_type]["model"]


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers"""

    def __init__(self, config: ProviderConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self._available: Optional[bool] = None

    async def initialize(self):
        """Initialize HTTP session"""
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60)
            )

    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None

    @abstractmethod
    async def check_available(self) -> bool:
        """Check if provider is available"""
        pass

    @abstractmethod
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """Generate completion"""
        pass

    async def analyze_security(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security context - can be overridden for specialized behavior"""
        prompt = self._build_security_prompt(context)
        response = await self.generate(prompt, system_prompt="You are a security expert.")
        return {
            "provider": self.config.provider_type.value,
            "model": self.config.model,
            "analysis": response,
            "role": self.config.role
        }

    def _build_security_prompt(self, context: Dict[str, Any]) -> str:
        """Build security analysis prompt"""
        return f"""Analyze this security context:

Target: {context.get('target', 'N/A')}
Vulnerability Type: {context.get('vuln_type', 'N/A')}
Evidence: {context.get('evidence', 'N/A')[:500]}
Findings: {context.get('findings', [])}

Provide:
1. Risk assessment (1-2 sentences)
2. Exploitation difficulty (Easy/Medium/Hard)
3. Recommended action
4. Confidence level (0-100%)

Be concise and technical."""

    def get_info(self) -> Dict[str, Any]:
        """Get provider info"""
        return {
            "type": self.config.provider_type.value,
            "model": self.config.model,
            "role": self.config.role,
            "enabled": self.config.enabled,
            "available": self._available
        }


class OpenAICompatibleProvider(BaseLLMProvider):
    """Provider for OpenAI-compatible APIs (OpenAI, Groq, Together, OpenRouter, Grok)"""

    async def check_available(self) -> bool:
        await self.initialize()
        try:
            # Skip check for providers that don't have /models endpoint
            if self.config.provider_type in [ProviderType.GROK]:
                self._available = bool(self.config.api_key)
                return self._available

            url = f"{self.config.base_url}/models"
            headers = {"Authorization": f"Bearer {self.config.api_key}"}

            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                self._available = resp.status == 200
                return self._available
        except Exception as e:
            logger.debug(f"Provider {self.config.provider_type} check failed: {e}")
            self._available = False
            return False

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        if not self._available:
            if not await self.check_available():
                return None

        await self.initialize()

        try:
            url = f"{self.config.base_url}/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json"
            }

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": self.config.model,
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 500
            }

            async with self.session.post(url, headers=headers, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                else:
                    logger.warning(f"Provider {self.config.provider_type} returned {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"Generation error for {self.config.provider_type}: {e}")
            return None


class OllamaProvider(BaseLLMProvider):
    """Provider for local Ollama"""

    async def check_available(self) -> bool:
        await self.initialize()
        try:
            url = f"{self.config.base_url}/api/tags"
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    models = [m.get("name", "") for m in data.get("models", [])]
                    self._available = any(self.config.model in m for m in models)
                    return self._available
                self._available = False
                return False
        except Exception as e:
            logger.debug(f"Ollama check failed: {e}")
            self._available = False
            return False

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        if not self._available:
            if not await self.check_available():
                return None

        await self.initialize()

        try:
            url = f"{self.config.base_url}/api/generate"
            payload = {
                "model": self.config.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3, "num_predict": 500}
            }

            if system_prompt:
                payload["system"] = system_prompt

            async with self.session.post(url, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("response", "").strip()
                return None
        except Exception as e:
            logger.error(f"Ollama generation error: {e}")
            return None


class AnthropicProvider(BaseLLMProvider):
    """Provider for Anthropic Claude"""

    async def check_available(self) -> bool:
        # Anthropic doesn't have a simple check endpoint, assume available if API key exists
        self._available = bool(self.config.api_key)
        return self._available

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        if not self._available:
            if not await self.check_available():
                return None

        await self.initialize()

        try:
            url = f"{self.config.base_url}/messages"
            headers = {
                "x-api-key": self.config.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            }

            payload = {
                "model": self.config.model,
                "max_tokens": 500,
                "messages": [{"role": "user", "content": prompt}]
            }

            if system_prompt:
                payload["system"] = system_prompt

            async with self.session.post(url, headers=headers, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    content = data.get("content", [])
                    if content and content[0].get("type") == "text":
                        return content[0].get("text", "").strip()
                return None
        except Exception as e:
            logger.error(f"Anthropic generation error: {e}")
            return None


def create_provider(config: ProviderConfig) -> BaseLLMProvider:
    """Factory function to create appropriate provider"""
    if config.provider_type == ProviderType.OLLAMA:
        return OllamaProvider(config)
    elif config.provider_type == ProviderType.ANTHROPIC:
        return AnthropicProvider(config)
    else:
        # OpenAI-compatible (OpenAI, Groq, Grok, Together, OpenRouter, Qwen)
        return OpenAICompatibleProvider(config)


class ProviderRegistry:
    """Registry of all configured LLM providers"""

    def __init__(self):
        self.providers: Dict[str, BaseLLMProvider] = {}

    def register(self, name: str, config: ProviderConfig):
        """Register a provider"""
        provider = create_provider(config)
        self.providers[name] = provider
        logger.info(f"Registered provider: {name} ({config.provider_type.value})")

    def unregister(self, name: str):
        """Unregister a provider"""
        if name in self.providers:
            del self.providers[name]

    def get(self, name: str) -> Optional[BaseLLMProvider]:
        """Get a provider by name"""
        return self.providers.get(name)

    def get_by_role(self, role: str) -> List[BaseLLMProvider]:
        """Get all providers with a specific role"""
        return [p for p in self.providers.values() if p.config.role == role]

    def get_enabled(self) -> List[BaseLLMProvider]:
        """Get all enabled providers"""
        return [p for p in self.providers.values() if p.config.enabled]

    async def check_all(self) -> Dict[str, bool]:
        """Check availability of all providers"""
        results = {}
        for name, provider in self.providers.items():
            results[name] = await provider.check_available()
        return results

    def get_status(self) -> List[Dict[str, Any]]:
        """Get status of all providers"""
        return [
            {"name": name, **provider.get_info()}
            for name, provider in self.providers.items()
        ]

    async def close_all(self):
        """Close all provider sessions"""
        for provider in self.providers.values():
            await provider.close()


# Global registry
_provider_registry: Optional[ProviderRegistry] = None


def get_provider_registry() -> ProviderRegistry:
    """Get or create provider registry"""
    global _provider_registry
    if _provider_registry is None:
        _provider_registry = ProviderRegistry()
    return _provider_registry
