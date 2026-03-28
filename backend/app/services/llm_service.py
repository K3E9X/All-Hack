"""
LLM Service - AI Analysis (ENABLED BY DEFAULT)

Multiple free providers with automatic fallback:
1. Groq (free tier: 30 req/min) - RECOMMENDED
2. Qwen via DashScope (free tier: 1M tokens/month)
3. Qwen via OpenRouter (free tier available)
4. Together.ai (free tier)
5. HuggingFace Inference API (free)
6. Ollama (local, unlimited) - supports qwen2, llama3

Set GROQ_API_KEY for best results (free at console.groq.com)
Set DASHSCOPE_API_KEY for Qwen (free at dashscope.aliyun.com)
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
    provider: str
    base_url: str
    model: str
    api_key: Optional[str] = None


class LLMService:
    """
    Unified LLM service for security analysis.
    ENABLED BY DEFAULT - tries multiple free providers.
    """

    # Free API providers (in priority order)
    FREE_PROVIDERS = [
        {
            "name": "codex_iliad",
            "env_key": "CODEX_ILIAD_API_KEY",
            "base_url": "https://codex.datax.iliad.fr/v1",
            "model": "Qwen/Qwen3.5-397B-A17B",
            "type": "openai"
        },
        {
            "name": "groq",
            "env_key": "GROQ_API_KEY",
            "base_url": "https://api.groq.com/openai/v1",
            "model": "llama-3.1-8b-instant",
            "type": "openai"
        },
        {
            "name": "dashscope",
            "env_key": "DASHSCOPE_API_KEY",
            "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
            "model": "qwen-turbo",
            "type": "openai"
        },
        {
            "name": "openrouter",
            "env_key": "OPENROUTER_API_KEY",
            "base_url": "https://openrouter.ai/api/v1",
            "model": "qwen/qwen-2-7b-instruct:free",
            "type": "openai"
        },
        {
            "name": "together",
            "env_key": "TOGETHER_API_KEY",
            "base_url": "https://api.together.xyz/v1",
            "model": "Qwen/Qwen2-7B-Instruct",
            "type": "openai"
        },
        {
            "name": "huggingface",
            "env_key": "HF_API_KEY",
            "base_url": "https://api-inference.huggingface.co/models",
            "model": "Qwen/Qwen2-7B-Instruct",
            "type": "huggingface"
        },
        {
            "name": "ollama",
            "env_key": None,
            "base_url": "http://localhost:11434",
            "model": "qwen2",
            "type": "ollama"
        }
    ]

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.configs: List[LLMConfig] = self._detect_configs()
        self.active_config: Optional[LLMConfig] = None
        self._available: Optional[bool] = None
        self._enabled = True  # ENABLED BY DEFAULT

    def _detect_configs(self) -> List[LLMConfig]:
        """Detect all available LLM providers"""
        configs = []

        for provider in self.FREE_PROVIDERS:
            api_key = None
            if provider["env_key"]:
                api_key = os.getenv(provider["env_key"], "")

            # Add if has API key OR is local (Ollama)
            if api_key or provider["name"] == "ollama":
                configs.append(LLMConfig(
                    provider=provider["name"],
                    base_url=os.getenv(f"{provider['name'].upper()}_HOST", provider["base_url"]),
                    model=os.getenv(f"{provider['name'].upper()}_MODEL", provider["model"]),
                    api_key=api_key if api_key else None
                ))

        return configs

    async def initialize(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def is_available(self) -> bool:
        """Check if any LLM service is available"""
        if not self._enabled:
            return False

        if self._available is not None:
            return self._available

        await self.initialize()

        # Try each provider until one works
        for config in self.configs:
            try:
                available = await self._check_provider(config)
                if available:
                    self.active_config = config
                    self._available = True
                    logger.info(f"LLM active: {config.provider} ({config.model})")
                    return True
            except Exception as e:
                logger.debug(f"Provider {config.provider} failed: {e}")
                continue

        self._available = False
        logger.warning("No LLM provider available")
        return False

    async def _check_provider(self, config: LLMConfig) -> bool:
        """Check if a specific provider is available"""
        try:
            if config.provider == "ollama":
                url = f"{config.base_url}/api/tags"
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status == 200

            elif config.provider in ["groq", "together", "openrouter", "codex_iliad"]:
                url = f"{config.base_url}/models"
                headers = {"Authorization": f"Bearer {config.api_key}"}
                async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        return True
                    # Fallback: test completion
                    return await self._test_completion(config)

            elif config.provider == "dashscope":
                # DashScope uses different auth header
                url = f"{config.base_url}/models"
                headers = {"Authorization": f"Bearer {config.api_key}"}
                async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    # DashScope may return 200 or just test with a simple completion
                    if resp.status == 200:
                        return True
                    # Fallback: try a simple completion
                    return await self._test_completion(config)

            elif config.provider == "huggingface":
                url = f"{config.base_url}/{config.model}"
                headers = {"Authorization": f"Bearer {config.api_key}"}
                # Just check if endpoint responds
                async with self.session.post(
                    url,
                    headers=headers,
                    json={"inputs": "test"},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return resp.status in [200, 503]  # 503 = loading, but available

        except Exception as e:
            logger.debug(f"Provider check failed: {e}")

    async def _test_completion(self, config: LLMConfig) -> bool:
        """Test provider with a simple completion request"""
        try:
            url = f"{config.base_url}/chat/completions"
            headers = {
                "Authorization": f"Bearer {config.api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": config.model,
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 5
            }
            async with self.session.post(
                url, headers=headers, json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                return resp.status == 200
        except:
            return False

        return False

    async def analyze_vulnerability(self, finding: Dict[str, Any]) -> Optional[str]:
        """Analyze a vulnerability finding with LLM"""
        if not await self.is_available():
            return self._fallback_analysis(finding)

        prompt = f"""Analyze this security vulnerability:

Type: {finding.get('vuln_type', 'Unknown')}
URL: {finding.get('url', 'N/A')}
Parameter: {finding.get('parameter', 'N/A')}
Evidence: {finding.get('evidence', 'N/A')[:300]}

Provide:
1. Risk (1 sentence)
2. Difficulty (Easy/Medium/Hard)
3. Fix (1 sentence)

Be concise."""

        result = await self._generate(prompt)
        return result if result else self._fallback_analysis(finding)

    def _fallback_analysis(self, finding: Dict[str, Any]) -> str:
        """Rule-based fallback when no LLM available"""
        vuln_type = finding.get('vuln_type', '').lower()
        severity = finding.get('severity', 'medium')

        analyses = {
            'sql': "SQL Injection allows database access. Difficulty: Easy. Fix: Use parameterized queries.",
            'xss': "XSS enables session hijacking. Difficulty: Easy. Fix: Encode output, use CSP.",
            'lfi': "LFI allows file read/RCE. Difficulty: Medium. Fix: Whitelist allowed files.",
            'rce': "RCE gives full server control. Difficulty: Easy. Fix: Never pass user input to commands.",
            'ssrf': "SSRF accesses internal services. Difficulty: Medium. Fix: Whitelist allowed URLs.",
            'ssti': "SSTI leads to RCE. Difficulty: Medium. Fix: Use sandboxed templates.",
            'xxe': "XXE reads files and SSRF. Difficulty: Medium. Fix: Disable external entities.",
        }

        for key, analysis in analyses.items():
            if key in vuln_type:
                return analysis

        return f"Vulnerability detected ({severity}). Review and remediate."

    async def suggest_payloads(self, vuln_type: str, context: str) -> Optional[List[str]]:
        """Generate payload suggestions"""
        if not await self.is_available():
            return None

        prompt = f"""Generate 5 {vuln_type} payloads for WAF bypass.
Context: {context}

Return ONLY payloads, one per line."""

        response = await self._generate(prompt)
        if response:
            return [line.strip() for line in response.split("\n") if line.strip()][:5]
        return None

    async def generate_report_summary(self, findings: List[Dict]) -> Optional[str]:
        """Generate executive summary"""
        if not await self.is_available():
            return self._fallback_summary(findings)

        summary = []
        for f in findings[:10]:
            summary.append(f"- {f.get('vuln_type')}: {f.get('severity')}")

        prompt = f"""Executive summary for pentest (3 sentences):

Findings ({len(findings)} total):
{chr(10).join(summary)}

Focus on business impact."""

        result = await self._generate(prompt)
        return result if result else self._fallback_summary(findings)

    def _fallback_summary(self, findings: List[Dict]) -> str:
        """Rule-based summary when no LLM"""
        critical = sum(1 for f in findings if f.get('severity') == 'critical')
        high = sum(1 for f in findings if f.get('severity') == 'high')
        total = len(findings)

        if critical > 0:
            return f"CRITICAL: {critical} critical and {high} high severity vulnerabilities found. Immediate remediation required. Total {total} issues identified."
        elif high > 0:
            return f"HIGH RISK: {high} high severity vulnerabilities require urgent attention. Total {total} issues found."
        else:
            return f"Assessment complete: {total} vulnerabilities found. Review and prioritize remediation."

    async def analyze(self, prompt: str, system_prompt: str = "You are a security expert. Be helpful.") -> Optional[str]:
        """General analysis method for arbitrary prompts"""
        if not await self.is_available():
            return None

        return await self._generate(prompt, system_prompt)

    @property
    def available(self) -> bool:
        """Check if LLM is available (sync property)"""
        return self._available if self._available is not None else bool(self.configs)

    async def _generate(self, prompt: str, system_prompt: str = "Security expert. Be concise.") -> Optional[str]:
        """Generate response from active LLM provider"""
        if not self.active_config:
            return None

        await self.initialize()

        try:
            if self.active_config.provider == "ollama":
                return await self._generate_ollama(prompt)
            elif self.active_config.provider in ["groq", "together", "openrouter", "dashscope", "codex_iliad"]:
                return await self._generate_openai_compatible(prompt, system_prompt)
            elif self.active_config.provider == "huggingface":
                return await self._generate_huggingface(prompt)
        except Exception as e:
            logger.warning(f"LLM generation error: {e}")
            # Try next provider
            self._available = None
            self.active_config = None

        return None

    async def _generate_ollama(self, prompt: str) -> Optional[str]:
        """Generate with Ollama"""
        url = f"{self.active_config.base_url}/api/generate"
        payload = {
            "model": self.active_config.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 300}
        }

        async with self.session.post(url, json=payload) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("response", "").strip()
        return None

    async def _generate_openai_compatible(self, prompt: str, system_prompt: str = "Security expert. Be concise.") -> Optional[str]:
        """Generate with OpenAI-compatible API (Groq, Together, OpenRouter, DashScope, Codex Iliad)"""
        url = f"{self.active_config.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.active_config.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.active_config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 500
        }

        async with self.session.post(url, headers=headers, json=payload) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
            else:
                error_text = await resp.text()
                logger.warning(f"Provider {self.active_config.provider} returned {resp.status}: {error_text[:200]}")
        return None

    async def _generate_huggingface(self, prompt: str) -> Optional[str]:
        """Generate with HuggingFace Inference API"""
        url = f"{self.active_config.base_url}/{self.active_config.model}"
        headers = {"Authorization": f"Bearer {self.active_config.api_key}"}
        payload = {
            "inputs": f"<|system|>Security expert. Be concise.<|user|>{prompt}<|assistant|>",
            "parameters": {"max_new_tokens": 300, "temperature": 0.3}
        }

        async with self.session.post(url, headers=headers, json=payload) as resp:
            if resp.status == 200:
                data = await resp.json()
                if isinstance(data, list) and len(data) > 0:
                    return data[0].get("generated_text", "").strip()
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get LLM service status"""
        return {
            "enabled": self._enabled,
            "available": self._available,
            "active_provider": self.active_config.provider if self.active_config else None,
            "active_model": self.active_config.model if self.active_config else None,
            "configured_providers": [c.provider for c in self.configs]
        }


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
