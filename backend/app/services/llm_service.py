"""
LLM Service - Local and Cloud AI Analysis

Supports:
- Ollama (local, free, unlimited)
- Groq (cloud, free tier: 30 req/min)
- OpenAI-compatible endpoints
"""

import aiohttp
import os
import json
import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    provider: str  # ollama, groq, openai
    base_url: str
    model: str
    api_key: Optional[str] = None


class LLMService:
    """Unified LLM service for security analysis"""

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.config = self._detect_config()
        self._available: Optional[bool] = None

    def _detect_config(self) -> LLMConfig:
        """Auto-detect available LLM provider"""

        # Priority 1: Groq (free cloud, fast)
        groq_key = os.getenv("GROQ_API_KEY", "")
        if groq_key:
            return LLMConfig(
                provider="groq",
                base_url="https://api.groq.com/openai/v1",
                model=os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
                api_key=groq_key
            )

        # Priority 2: Ollama (local, free)
        ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        return LLMConfig(
            provider="ollama",
            base_url=ollama_host,
            model=os.getenv("OLLAMA_MODEL", "llama3.2")
        )

    async def initialize(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60)
            )

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def is_available(self) -> bool:
        """Check if LLM service is available"""
        if self._available is not None:
            return self._available

        await self.initialize()

        try:
            if self.config.provider == "ollama":
                url = f"{self.config.base_url}/api/tags"
                async with self.session.get(url) as resp:
                    self._available = resp.status == 200
            elif self.config.provider == "groq":
                url = f"{self.config.base_url}/models"
                headers = {"Authorization": f"Bearer {self.config.api_key}"}
                async with self.session.get(url, headers=headers) as resp:
                    self._available = resp.status == 200
            else:
                self._available = False
        except Exception as e:
            logger.debug(f"LLM not available: {e}")
            self._available = False

        return self._available

    async def analyze_vulnerability(self, finding: Dict[str, Any]) -> Optional[str]:
        """Analyze a vulnerability finding with LLM"""
        if not await self.is_available():
            return None

        prompt = f"""Analyze this security vulnerability finding and provide:
1. Risk assessment (1-2 sentences)
2. Exploitation difficulty (Easy/Medium/Hard)
3. Recommended fix (1-2 sentences)

Vulnerability: {finding.get('vuln_type', 'Unknown')}
URL: {finding.get('url', 'N/A')}
Parameter: {finding.get('parameter', 'N/A')}
Evidence: {finding.get('evidence', 'N/A')}
Payload: {finding.get('payload', 'N/A')[:200]}

Be concise and technical."""

        return await self._generate(prompt)

    async def suggest_payloads(self, vuln_type: str, context: str) -> Optional[List[str]]:
        """Generate payload suggestions for a vulnerability type"""
        if not await self.is_available():
            return None

        prompt = f"""Generate 5 unique {vuln_type} payloads for testing.
Context: {context}

Return ONLY the payloads, one per line, no explanations.
Focus on WAF bypass variants."""

        response = await self._generate(prompt)
        if response:
            return [line.strip() for line in response.split("\n") if line.strip()]
        return None

    async def generate_report_summary(self, findings: List[Dict]) -> Optional[str]:
        """Generate executive summary of findings"""
        if not await self.is_available():
            return None

        # Summarize findings
        summary = []
        for f in findings[:10]:  # Limit to first 10
            summary.append(f"- {f.get('vuln_type')}: {f.get('severity')} at {f.get('url', '')[:50]}")

        prompt = f"""Write a brief executive summary (3-4 sentences) for this penetration test:

Findings:
{chr(10).join(summary)}

Total vulnerabilities: {len(findings)}

Focus on business impact and prioritization."""

        return await self._generate(prompt)

    async def _generate(self, prompt: str) -> Optional[str]:
        """Generate response from LLM"""
        await self.initialize()

        try:
            if self.config.provider == "ollama":
                return await self._generate_ollama(prompt)
            elif self.config.provider == "groq":
                return await self._generate_openai_compatible(prompt)
        except Exception as e:
            logger.warning(f"LLM generation error: {e}")

        return None

    async def _generate_ollama(self, prompt: str) -> Optional[str]:
        """Generate with Ollama"""
        url = f"{self.config.base_url}/api/generate"
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "num_predict": 500
            }
        }

        async with self.session.post(url, json=payload) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("response", "").strip()
        return None

    async def _generate_openai_compatible(self, prompt: str) -> Optional[str]:
        """Generate with OpenAI-compatible API (Groq, etc.)"""
        url = f"{self.config.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": "You are a security expert analyzing penetration test results. Be concise and technical."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 500
        }

        async with self.session.post(url, headers=headers, json=payload) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        return None


# Global instance
_llm_service: Optional[LLMService] = None


def get_llm_service() -> LLMService:
    global _llm_service
    if _llm_service is None:
        _llm_service = LLMService()
    return _llm_service


async def analyze_with_llm(finding: Dict) -> Optional[str]:
    """Convenience function to analyze a finding"""
    service = get_llm_service()
    return await service.analyze_vulnerability(finding)
