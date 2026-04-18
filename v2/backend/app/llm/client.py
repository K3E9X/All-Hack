"""OpenRouter client (OpenAI-compatible Chat Completions API).

The client is thin on purpose: one `chat()` for sync replies, one `stream()`
for incremental tokens. Higher-level helpers (analyze, suggest, report) live
in sibling modules and call into this.
"""
from __future__ import annotations

import json
from typing import AsyncIterator, Dict, List, Optional

import httpx

from app.config import settings


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        app_name: Optional[str] = None,
        timeout: float = 120.0,
    ) -> None:
        self.api_key = api_key or settings.openrouter_api_key
        self.model = model or settings.openrouter_model
        self.base_url = (base_url or settings.openrouter_base_url).rstrip("/")
        self.app_name = app_name or settings.openrouter_app_name
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> Dict[str, str]:
        if not self.configured:
            raise LLMError(
                "OPENROUTER_API_KEY is not set. Put it in .env and restart the backend."
            )
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            # OpenRouter uses these to attribute usage to your app (helps with free tier).
            "HTTP-Referer": "http://localhost",
            "X-Title": self.app_name,
        }

    async def chat(
        self,
        messages: List[Dict[str, str]],
        *,
        model: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Return the full assistant message as a single string."""
        payload: Dict[str, object] = {
            "model": model or self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
        if response.status_code >= 400:
            raise LLMError(f"OpenRouter {response.status_code}: {response.text[:500]}")

        data = response.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise LLMError(f"Unexpected response shape: {data}") from exc

    async def stream(
        self,
        messages: List[Dict[str, str]],
        *,
        model: Optional[str] = None,
        temperature: float = 0.2,
    ) -> AsyncIterator[str]:
        """Yield incremental text chunks as they arrive (SSE from OpenRouter)."""
        payload = {
            "model": model or self.model,
            "messages": messages,
            "temperature": temperature,
            "stream": True,
        }
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            ) as response:
                if response.status_code >= 400:
                    body = await response.aread()
                    raise LLMError(f"OpenRouter {response.status_code}: {body.decode()[:500]}")
                async for line in response.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[len("data:"):].strip()
                    if data == "[DONE]":
                        return
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content")
                    if delta:
                        yield delta


_client: Optional[LLMClient] = None


def get_llm() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
