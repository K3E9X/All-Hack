"""
Ollama LLM Client

Local LLM client for privacy-first AI analysis.
Free, no API costs, runs completely offline.
"""
import httpx
import json
import logging
from typing import Optional, Dict, Any, AsyncGenerator
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class OllamaConfig:
    """Ollama configuration"""
    base_url: str = "http://localhost:11434"
    model: str = "llama3.2"  # Default model
    timeout: int = 120  # 2 minutes timeout
    temperature: float = 0.7
    top_p: float = 0.9
    max_tokens: int = 4096

class OllamaClient:
    """
    Client for Ollama local LLM

    Installation:
    1. Install Ollama: https://ollama.ai
    2. Pull model: ollama pull llama3.2
    3. Start server: ollama serve (runs on localhost:11434)

    Advantages:
    - $0 cost (completely free)
    - Privacy-first (no data leaves your machine)
    - Offline capable
    - No rate limits

    Recommended models:
    - llama3.2 (8B) - Best balance of speed/quality
    - llama3.2:70b - Best quality (requires 40GB RAM)
    - mistral - Fast and efficient
    - codellama - Best for code analysis
    """

    def __init__(self, config: Optional[OllamaConfig] = None):
        self.config = config or OllamaConfig()
        self.client = httpx.AsyncClient(timeout=self.config.timeout)

    async def check_available(self) -> bool:
        """Check if Ollama is running and model is available"""
        try:
            # Check if Ollama server is running
            response = await self.client.get(f"{self.config.base_url}/api/tags")
            if response.status_code != 200:
                return False

            # Check if requested model is available
            models = response.json().get("models", [])
            model_names = [m.get("name", "") for m in models]

            # Model names can be "llama3.2:latest" or just "llama3.2"
            model_available = any(
                self.config.model in name or name.startswith(self.config.model)
                for name in model_names
            )

            if not model_available:
                logger.warning(
                    f"Model '{self.config.model}' not found. "
                    f"Available models: {model_names}. "
                    f"Install with: ollama pull {self.config.model}"
                )
                return False

            logger.info(f"✅ Ollama available with model: {self.config.model}")
            return True

        except Exception as e:
            logger.warning(f"⚠️  Ollama not available: {e}")
            logger.info("Install Ollama from https://ollama.ai")
            return False

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        stream: bool = False
    ) -> str:
        """
        Generate completion from Ollama

        Args:
            prompt: User prompt
            system_prompt: System instructions
            stream: Enable streaming (for real-time responses)

        Returns:
            Generated text
        """
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": stream,
            "options": {
                "temperature": self.config.temperature,
                "top_p": self.config.top_p,
                "num_predict": self.config.max_tokens
            }
        }

        if system_prompt:
            payload["system"] = system_prompt

        try:
            if stream:
                return await self._generate_stream(payload)
            else:
                return await self._generate_sync(payload)

        except Exception as e:
            logger.error(f"❌ Ollama generation failed: {e}")
            raise

    async def _generate_sync(self, payload: Dict[str, Any]) -> str:
        """Synchronous generation (wait for complete response)"""
        response = await self.client.post(
            f"{self.config.base_url}/api/generate",
            json=payload
        )

        if response.status_code != 200:
            raise Exception(f"Ollama API error: {response.status_code} - {response.text}")

        result = response.json()
        return result.get("response", "")

    async def _generate_stream(self, payload: Dict[str, Any]) -> AsyncGenerator[str, None]:
        """Streaming generation (real-time token-by-token)"""
        async with self.client.stream(
            "POST",
            f"{self.config.base_url}/api/generate",
            json=payload
        ) as response:
            async for line in response.aiter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        if "response" in data:
                            yield data["response"]
                    except json.JSONDecodeError:
                        continue

    async def chat(
        self,
        messages: list[Dict[str, str]],
        stream: bool = False
    ) -> str:
        """
        Chat completion (multi-turn conversation)

        Args:
            messages: List of {"role": "user/assistant/system", "content": "..."}
            stream: Enable streaming

        Returns:
            Generated response
        """
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": stream,
            "options": {
                "temperature": self.config.temperature,
                "top_p": self.config.top_p,
                "num_predict": self.config.max_tokens
            }
        }

        try:
            response = await self.client.post(
                f"{self.config.base_url}/api/chat",
                json=payload
            )

            if response.status_code != 200:
                raise Exception(f"Ollama API error: {response.status_code}")

            result = response.json()
            return result.get("message", {}).get("content", "")

        except Exception as e:
            logger.error(f"❌ Ollama chat failed: {e}")
            raise

    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()

    def __del__(self):
        """Cleanup"""
        try:
            import asyncio
            asyncio.create_task(self.close())
        except:
            pass


# Singleton instance
_ollama_client: Optional[OllamaClient] = None

def get_ollama_client() -> OllamaClient:
    """Get or create Ollama client singleton"""
    global _ollama_client
    if _ollama_client is None:
        _ollama_client = OllamaClient()
    return _ollama_client
