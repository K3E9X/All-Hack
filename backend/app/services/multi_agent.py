"""
Multi-Agent Orchestrator

Coordinates multiple LLM providers for consensus-based decisions.
Uses a hierarchical approach with optional voting on critical decisions.
"""

import asyncio
import logging
import json
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum

from app.services.llm_providers import (
    ProviderRegistry,
    get_provider_registry,
    BaseLLMProvider,
    ProviderConfig,
    ProviderType,
    create_provider
)

logger = logging.getLogger(__name__)


class ConsensusMode(str, Enum):
    """How to aggregate multiple agent responses"""
    SINGLE = "single"           # Use primary agent only
    FALLBACK = "fallback"       # Try next if primary fails
    VOTING = "voting"           # Majority vote on decisions
    WEIGHTED = "weighted"       # Weighted by confidence scores
    ALL = "all"                 # Return all responses


@dataclass
class AgentResponse:
    """Response from a single agent"""
    provider_name: str
    provider_type: str
    model: str
    response: Optional[str]
    confidence: float = 0.0
    latency_ms: float = 0.0
    success: bool = True
    error: Optional[str] = None


@dataclass
class ConsensusResult:
    """Aggregated result from multiple agents"""
    mode: ConsensusMode
    final_decision: Optional[str]
    confidence: float
    agent_responses: List[AgentResponse]
    agreement_ratio: float = 0.0
    reasoning: Optional[str] = None


class MultiAgentOrchestrator:
    """
    Orchestrates multiple LLM agents for security testing decisions.

    Architecture:
    - Primary agent handles main reasoning
    - Specialist agents consulted for specific tasks
    - Consensus mode for critical decisions

    This is an ADDITION to the existing LLMService, not a replacement.
    """

    def __init__(self, registry: Optional[ProviderRegistry] = None):
        self.registry = registry or get_provider_registry()
        self.primary_provider: Optional[str] = None
        self.consensus_mode = ConsensusMode.FALLBACK
        self.consensus_threshold = 0.6  # 60% agreement required

    def set_primary(self, provider_name: str):
        """Set the primary provider"""
        self.primary_provider = provider_name

    def set_consensus_mode(self, mode: ConsensusMode):
        """Set how to aggregate responses"""
        self.consensus_mode = mode

    async def query_single(
        self,
        prompt: str,
        provider_name: Optional[str] = None,
        system_prompt: Optional[str] = None
    ) -> AgentResponse:
        """Query a single provider"""
        name = provider_name or self.primary_provider
        if not name:
            # Use first available
            providers = self.registry.get_enabled()
            if not providers:
                return AgentResponse(
                    provider_name="none",
                    provider_type="none",
                    model="none",
                    response=None,
                    success=False,
                    error="No providers available"
                )
            provider = providers[0]
            name = list(self.registry.providers.keys())[0]
        else:
            provider = self.registry.get(name)
            if not provider:
                return AgentResponse(
                    provider_name=name,
                    provider_type="unknown",
                    model="unknown",
                    response=None,
                    success=False,
                    error=f"Provider {name} not found"
                )

        import time
        start = time.time()

        try:
            response = await provider.generate(prompt, system_prompt)
            latency = (time.time() - start) * 1000

            return AgentResponse(
                provider_name=name,
                provider_type=provider.config.provider_type.value,
                model=provider.config.model,
                response=response,
                latency_ms=latency,
                success=response is not None,
                confidence=0.8 if response else 0.0
            )
        except Exception as e:
            return AgentResponse(
                provider_name=name,
                provider_type=provider.config.provider_type.value,
                model=provider.config.model,
                response=None,
                success=False,
                error=str(e)
            )

    async def query_all(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        timeout: float = 30.0
    ) -> List[AgentResponse]:
        """Query all enabled providers in parallel"""
        providers = self.registry.get_enabled()
        if not providers:
            return []

        tasks = []
        provider_names = []

        for name, provider in self.registry.providers.items():
            if provider.config.enabled:
                tasks.append(self._query_with_timeout(provider, prompt, system_prompt, timeout))
                provider_names.append(name)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        responses = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                responses.append(AgentResponse(
                    provider_name=provider_names[i],
                    provider_type="unknown",
                    model="unknown",
                    response=None,
                    success=False,
                    error=str(result)
                ))
            else:
                result.provider_name = provider_names[i]
                responses.append(result)

        return responses

    async def _query_with_timeout(
        self,
        provider: BaseLLMProvider,
        prompt: str,
        system_prompt: Optional[str],
        timeout: float
    ) -> AgentResponse:
        """Query provider with timeout"""
        import time
        start = time.time()

        try:
            response = await asyncio.wait_for(
                provider.generate(prompt, system_prompt),
                timeout=timeout
            )
            latency = (time.time() - start) * 1000

            return AgentResponse(
                provider_name="",  # Filled in by caller
                provider_type=provider.config.provider_type.value,
                model=provider.config.model,
                response=response,
                latency_ms=latency,
                success=response is not None,
                confidence=0.8 if response else 0.0
            )
        except asyncio.TimeoutError:
            return AgentResponse(
                provider_name="",
                provider_type=provider.config.provider_type.value,
                model=provider.config.model,
                response=None,
                success=False,
                error="Timeout"
            )
        except Exception as e:
            return AgentResponse(
                provider_name="",
                provider_type=provider.config.provider_type.value,
                model=provider.config.model,
                response=None,
                success=False,
                error=str(e)
            )

    async def consensus_query(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        mode: Optional[ConsensusMode] = None
    ) -> ConsensusResult:
        """Query with consensus aggregation"""
        use_mode = mode or self.consensus_mode

        if use_mode == ConsensusMode.SINGLE:
            response = await self.query_single(prompt, system_prompt=system_prompt)
            return ConsensusResult(
                mode=use_mode,
                final_decision=response.response,
                confidence=response.confidence,
                agent_responses=[response],
                agreement_ratio=1.0
            )

        elif use_mode == ConsensusMode.FALLBACK:
            return await self._fallback_query(prompt, system_prompt)

        elif use_mode in [ConsensusMode.VOTING, ConsensusMode.WEIGHTED, ConsensusMode.ALL]:
            responses = await self.query_all(prompt, system_prompt)
            return self._aggregate_responses(responses, use_mode)

        return ConsensusResult(
            mode=use_mode,
            final_decision=None,
            confidence=0.0,
            agent_responses=[],
            reasoning="Unknown consensus mode"
        )

    async def _fallback_query(
        self,
        prompt: str,
        system_prompt: Optional[str]
    ) -> ConsensusResult:
        """Try providers in order until one succeeds"""
        providers = sorted(
            self.registry.get_enabled(),
            key=lambda p: p.config.priority
        )

        responses = []
        for provider in providers:
            name = next(
                (n for n, p in self.registry.providers.items() if p == provider),
                "unknown"
            )
            response = await self.query_single(prompt, name, system_prompt)
            responses.append(response)

            if response.success and response.response:
                return ConsensusResult(
                    mode=ConsensusMode.FALLBACK,
                    final_decision=response.response,
                    confidence=response.confidence,
                    agent_responses=responses,
                    agreement_ratio=1.0,
                    reasoning=f"Success with provider: {name}"
                )

        return ConsensusResult(
            mode=ConsensusMode.FALLBACK,
            final_decision=None,
            confidence=0.0,
            agent_responses=responses,
            reasoning="All providers failed"
        )

    def _aggregate_responses(
        self,
        responses: List[AgentResponse],
        mode: ConsensusMode
    ) -> ConsensusResult:
        """Aggregate multiple responses based on mode"""
        successful = [r for r in responses if r.success and r.response]

        if not successful:
            return ConsensusResult(
                mode=mode,
                final_decision=None,
                confidence=0.0,
                agent_responses=responses,
                reasoning="No successful responses"
            )

        if mode == ConsensusMode.ALL:
            # Return all responses, combine them
            combined = "\n\n---\n\n".join([
                f"**{r.provider_name}** ({r.model}):\n{r.response}"
                for r in successful
            ])
            return ConsensusResult(
                mode=mode,
                final_decision=combined,
                confidence=sum(r.confidence for r in successful) / len(successful),
                agent_responses=responses,
                agreement_ratio=len(successful) / len(responses) if responses else 0
            )

        elif mode == ConsensusMode.VOTING:
            # Simple voting - use most common sentiment/decision
            # For now, use the response with highest confidence
            best = max(successful, key=lambda r: r.confidence)
            return ConsensusResult(
                mode=mode,
                final_decision=best.response,
                confidence=best.confidence,
                agent_responses=responses,
                agreement_ratio=len(successful) / len(responses) if responses else 0,
                reasoning=f"Selected response from {best.provider_name} (highest confidence)"
            )

        elif mode == ConsensusMode.WEIGHTED:
            # Weighted by latency and confidence
            # Faster + higher confidence = better
            def score(r: AgentResponse) -> float:
                latency_score = 1.0 / (1.0 + r.latency_ms / 1000)
                return r.confidence * 0.7 + latency_score * 0.3

            best = max(successful, key=score)
            return ConsensusResult(
                mode=mode,
                final_decision=best.response,
                confidence=best.confidence,
                agent_responses=responses,
                agreement_ratio=len(successful) / len(responses) if responses else 0,
                reasoning=f"Selected {best.provider_name} (best weighted score)"
            )

        return ConsensusResult(
            mode=mode,
            final_decision=successful[0].response if successful else None,
            confidence=successful[0].confidence if successful else 0,
            agent_responses=responses
        )

    async def security_consensus(
        self,
        context: Dict[str, Any],
        critical: bool = False
    ) -> ConsensusResult:
        """
        Get security analysis with consensus.
        Uses voting mode for critical decisions.
        """
        prompt = self._build_security_prompt(context)
        system_prompt = """You are a security expert analyzing potential vulnerabilities.
Be concise and technical. Provide:
1. Risk assessment
2. Exploitation difficulty (Easy/Medium/Hard)
3. Recommended action
4. Confidence (0-100%)"""

        mode = ConsensusMode.VOTING if critical else self.consensus_mode
        return await self.consensus_query(prompt, system_prompt, mode)

    async def validate_finding(
        self,
        finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate a security finding using multiple agents.
        Returns confidence score based on agreement.
        """
        prompt = f"""Validate this security finding:

Type: {finding.get('type', 'Unknown')}
URL: {finding.get('url', 'N/A')}
Evidence: {finding.get('evidence', 'N/A')[:300]}
Severity: {finding.get('severity', 'medium')}

Is this a TRUE POSITIVE or FALSE POSITIVE?
Respond with: TRUE_POSITIVE or FALSE_POSITIVE
Then explain why in one sentence."""

        result = await self.consensus_query(
            prompt,
            system_prompt="You are validating security findings. Be strict.",
            mode=ConsensusMode.VOTING
        )

        # Parse responses for TRUE/FALSE POSITIVE
        true_positive_votes = 0
        false_positive_votes = 0

        for response in result.agent_responses:
            if response.response:
                upper = response.response.upper()
                if "TRUE_POSITIVE" in upper or "TRUE POSITIVE" in upper:
                    true_positive_votes += 1
                elif "FALSE_POSITIVE" in upper or "FALSE POSITIVE" in upper:
                    false_positive_votes += 1

        total_votes = true_positive_votes + false_positive_votes
        if total_votes > 0:
            confidence = max(true_positive_votes, false_positive_votes) / total_votes
            is_valid = true_positive_votes > false_positive_votes
        else:
            confidence = 0.5
            is_valid = True  # Default to true positive

        return {
            "valid": is_valid,
            "confidence": confidence,
            "true_positive_votes": true_positive_votes,
            "false_positive_votes": false_positive_votes,
            "total_agents": len(result.agent_responses),
            "details": result
        }

    def _build_security_prompt(self, context: Dict[str, Any]) -> str:
        """Build security analysis prompt"""
        return f"""Analyze this security context:

Target: {context.get('target', 'N/A')}
Vulnerability Type: {context.get('vuln_type', 'N/A')}
Evidence: {context.get('evidence', 'N/A')[:500]}
Current Findings: {len(context.get('findings', []))} items

What is the risk and recommended action?"""

    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        return {
            "primary_provider": self.primary_provider,
            "consensus_mode": self.consensus_mode.value,
            "consensus_threshold": self.consensus_threshold,
            "providers": self.registry.get_status(),
            "total_providers": len(self.registry.providers),
            "enabled_providers": len(self.registry.get_enabled())
        }


# Global orchestrator instance
_orchestrator: Optional[MultiAgentOrchestrator] = None


def get_orchestrator() -> MultiAgentOrchestrator:
    """Get or create orchestrator"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = MultiAgentOrchestrator()
    return _orchestrator


async def setup_providers_from_settings(settings: Dict[str, Any]):
    """Setup providers from user settings"""
    orchestrator = get_orchestrator()
    registry = orchestrator.registry

    # Provider configurations from settings
    provider_configs = settings.get("llm_providers", {})

    for name, config in provider_configs.items():
        if not config.get("enabled", True):
            continue

        try:
            provider_type = ProviderType(config.get("type", "openai"))
            provider_config = ProviderConfig(
                provider_type=provider_type,
                api_key=config.get("api_key"),
                base_url=config.get("base_url"),
                model=config.get("model"),
                enabled=config.get("enabled", True),
                role=config.get("role", "general"),
                priority=config.get("priority", 0)
            )
            registry.register(name, provider_config)
        except Exception as e:
            logger.error(f"Failed to register provider {name}: {e}")

    # Set primary if specified
    primary = settings.get("primary_provider")
    if primary and registry.get(primary):
        orchestrator.set_primary(primary)

    # Set consensus mode
    mode = settings.get("consensus_mode", "fallback")
    try:
        orchestrator.set_consensus_mode(ConsensusMode(mode))
    except ValueError:
        orchestrator.set_consensus_mode(ConsensusMode.FALLBACK)

    # Check availability
    await registry.check_all()

    return orchestrator
