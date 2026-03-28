"""
Multi-Agent API Routes

Endpoints for managing and querying multiple LLM providers.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import logging

from app.services.multi_agent import (
    get_orchestrator,
    setup_providers_from_settings,
    ConsensusMode
)
from app.services.llm_providers import (
    ProviderConfig,
    ProviderType,
    get_provider_registry
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/multi-agent", tags=["multi-agent"])


# ============ Request Models ============

class ProviderSetup(BaseModel):
    name: str = Field(..., description="Provider name (e.g., 'primary-gpt')")
    type: str = Field(..., description="Provider type (openai, groq, grok, ollama, qwen, anthropic)")
    api_key: Optional[str] = Field(None, description="API key")
    base_url: Optional[str] = Field(None, description="Base URL override")
    model: Optional[str] = Field(None, description="Model override")
    role: str = Field("general", description="Role: general, analyst, payload_gen, validator")
    priority: int = Field(0, description="Priority (lower = higher)")
    enabled: bool = Field(True, description="Enable this provider")


class QueryRequest(BaseModel):
    prompt: str = Field(..., description="Prompt to send")
    system_prompt: Optional[str] = Field(None, description="System prompt")
    provider: Optional[str] = Field(None, description="Specific provider to use")


class ConsensusQueryRequest(BaseModel):
    prompt: str = Field(..., description="Prompt to send")
    system_prompt: Optional[str] = Field(None, description="System prompt")
    mode: Optional[str] = Field(None, description="Consensus mode: single, fallback, voting, weighted, all")


class SecurityContextRequest(BaseModel):
    target: str = Field(..., description="Target URL")
    vuln_type: Optional[str] = Field(None, description="Vulnerability type")
    evidence: Optional[str] = Field(None, description="Evidence/payload")
    findings: Optional[List[Dict]] = Field(None, description="Current findings")
    critical: bool = Field(False, description="Use voting for critical decisions")


class ValidateFindingRequest(BaseModel):
    type: str = Field(..., description="Vulnerability type")
    url: str = Field(..., description="Affected URL")
    evidence: Optional[str] = Field(None, description="Evidence")
    severity: str = Field("medium", description="Severity level")


# ============ Endpoints ============

@router.get("/status")
async def get_status():
    """Get multi-agent orchestrator status"""
    orchestrator = get_orchestrator()
    return orchestrator.get_status()


@router.post("/providers")
async def add_provider(config: ProviderSetup):
    """Add or update a provider"""
    try:
        provider_type = ProviderType(config.type)
        provider_config = ProviderConfig(
            provider_type=provider_type,
            api_key=config.api_key,
            base_url=config.base_url,
            model=config.model,
            enabled=config.enabled,
            role=config.role,
            priority=config.priority
        )

        registry = get_provider_registry()
        registry.register(config.name, provider_config)

        # Check availability
        provider = registry.get(config.name)
        available = await provider.check_available() if provider else False

        return {
            "success": True,
            "provider": config.name,
            "type": config.type,
            "model": provider_config.model,
            "available": available
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid provider type: {config.type}")
    except Exception as e:
        logger.error(f"Failed to add provider: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/providers/{name}")
async def remove_provider(name: str):
    """Remove a provider"""
    registry = get_provider_registry()
    if name not in registry.providers:
        raise HTTPException(status_code=404, detail=f"Provider {name} not found")

    registry.unregister(name)
    return {"success": True, "removed": name}


@router.get("/providers")
async def list_providers():
    """List all providers"""
    registry = get_provider_registry()
    return {
        "providers": registry.get_status(),
        "total": len(registry.providers)
    }


@router.post("/providers/check")
async def check_providers():
    """Check availability of all providers"""
    registry = get_provider_registry()
    results = await registry.check_all()
    return {
        "results": results,
        "available": sum(1 for v in results.values() if v),
        "total": len(results)
    }


@router.post("/query")
async def query_single(request: QueryRequest):
    """Query a single provider"""
    orchestrator = get_orchestrator()
    response = await orchestrator.query_single(
        prompt=request.prompt,
        provider_name=request.provider,
        system_prompt=request.system_prompt
    )

    return {
        "provider": response.provider_name,
        "model": response.model,
        "response": response.response,
        "success": response.success,
        "latency_ms": response.latency_ms,
        "error": response.error
    }


@router.post("/query/all")
async def query_all_providers(request: QueryRequest):
    """Query all enabled providers in parallel"""
    orchestrator = get_orchestrator()
    responses = await orchestrator.query_all(
        prompt=request.prompt,
        system_prompt=request.system_prompt
    )

    return {
        "responses": [
            {
                "provider": r.provider_name,
                "model": r.model,
                "response": r.response,
                "success": r.success,
                "latency_ms": r.latency_ms,
                "error": r.error
            }
            for r in responses
        ],
        "successful": sum(1 for r in responses if r.success),
        "total": len(responses)
    }


@router.post("/consensus")
async def consensus_query(request: ConsensusQueryRequest):
    """Query with consensus aggregation"""
    orchestrator = get_orchestrator()

    mode = None
    if request.mode:
        try:
            mode = ConsensusMode(request.mode)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid consensus mode: {request.mode}")

    result = await orchestrator.consensus_query(
        prompt=request.prompt,
        system_prompt=request.system_prompt,
        mode=mode
    )

    return {
        "mode": result.mode.value,
        "decision": result.final_decision,
        "confidence": result.confidence,
        "agreement_ratio": result.agreement_ratio,
        "reasoning": result.reasoning,
        "agent_count": len(result.agent_responses),
        "agents": [
            {
                "provider": r.provider_name,
                "model": r.model,
                "success": r.success,
                "latency_ms": r.latency_ms
            }
            for r in result.agent_responses
        ]
    }


@router.post("/security-analysis")
async def security_analysis(request: SecurityContextRequest):
    """Get security analysis with consensus"""
    orchestrator = get_orchestrator()

    context = {
        "target": request.target,
        "vuln_type": request.vuln_type,
        "evidence": request.evidence,
        "findings": request.findings or []
    }

    result = await orchestrator.security_consensus(context, critical=request.critical)

    return {
        "target": request.target,
        "analysis": result.final_decision,
        "confidence": result.confidence,
        "mode": result.mode.value,
        "agreement": result.agreement_ratio,
        "agents_consulted": len(result.agent_responses)
    }


@router.post("/validate-finding")
async def validate_finding(request: ValidateFindingRequest):
    """Validate a security finding using multiple agents"""
    orchestrator = get_orchestrator()

    finding = {
        "type": request.type,
        "url": request.url,
        "evidence": request.evidence,
        "severity": request.severity
    }

    result = await orchestrator.validate_finding(finding)

    return {
        "valid": result["valid"],
        "confidence": result["confidence"],
        "votes": {
            "true_positive": result["true_positive_votes"],
            "false_positive": result["false_positive_votes"]
        },
        "total_agents": result["total_agents"]
    }


@router.post("/set-primary/{provider_name}")
async def set_primary_provider(provider_name: str):
    """Set the primary provider"""
    registry = get_provider_registry()
    if provider_name not in registry.providers:
        raise HTTPException(status_code=404, detail=f"Provider {provider_name} not found")

    orchestrator = get_orchestrator()
    orchestrator.set_primary(provider_name)

    return {"success": True, "primary": provider_name}


@router.post("/set-consensus-mode/{mode}")
async def set_consensus_mode(mode: str):
    """Set the consensus mode"""
    try:
        consensus_mode = ConsensusMode(mode)
    except ValueError:
        valid_modes = [m.value for m in ConsensusMode]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode: {mode}. Valid modes: {valid_modes}"
        )

    orchestrator = get_orchestrator()
    orchestrator.set_consensus_mode(consensus_mode)

    return {"success": True, "mode": mode}


@router.post("/setup")
async def setup_from_settings(settings: Dict[str, Any]):
    """Setup providers from settings dictionary"""
    try:
        orchestrator = await setup_providers_from_settings(settings)
        return orchestrator.get_status()
    except Exception as e:
        logger.error(f"Setup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
