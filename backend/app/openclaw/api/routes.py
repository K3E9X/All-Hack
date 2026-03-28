"""
API Routes for Agent Loop
"""

import asyncio
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.agent_loop import AgentLoop, AgentLoopBuilder
from ..tools.registry import create_default_registry
from ..memory.learning import MemorySystem
from app.database.connection import get_db
from app.services.llm_service import LLMService
from app.services.multi_agent import get_orchestrator

router = APIRouter(prefix="/agent", tags=["agent"])

# Singleton instances
_agent_loop: Optional[AgentLoop] = None
_llm_service: Optional[LLMService] = None
_orchestrator = None


async def get_llm_service() -> LLMService:
    """Get or create LLM service"""
    global _llm_service
    if _llm_service is None:
        _llm_service = LLMService()
        await _llm_service.initialize()
    return _llm_service


async def get_multi_agent_orchestrator():
    """Get multi-agent orchestrator with all configured providers"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = get_orchestrator()
    return _orchestrator


async def get_agent_loop(db: Session = Depends(get_db)) -> AgentLoop:
    """Get or create agent loop with multi-agent support"""
    global _agent_loop
    if _agent_loop is None:
        llm = await get_llm_service()
        tools = create_default_registry()
        memory = MemorySystem(db)
        orchestrator = await get_multi_agent_orchestrator()

        _agent_loop = (
            AgentLoopBuilder()
            .with_llm(llm)
            .with_tools(tools)
            .with_memory(memory)
            .with_database(db)
            .with_orchestrator(orchestrator)
            .build()
        )
    return _agent_loop


# Request/Response Models

class AgentRequest(BaseModel):
    """Request to execute agent"""
    target: str = Field(..., description="Target URL")
    request: str = Field(..., description="Natural language request")
    scan_id: Optional[str] = Field(None, description="Associated scan ID")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context")


class AgentResponse(BaseModel):
    """Agent execution response"""
    session_id: str
    status: str
    tasks_total: int
    tasks_completed: int
    findings_count: int


class SessionResponse(BaseModel):
    """Session status response"""
    id: str
    status: str
    target: Optional[str]
    user_request: str
    tasks: list
    findings_count: int
    reasoning: list
    tool_calls: list


# Routes

@router.post("/execute", response_model=AgentResponse)
async def execute_agent(
    request: AgentRequest,
    agent: AgentLoop = Depends(get_agent_loop)
):
    """
    Execute agent with a natural language request

    The agent will:
    1. Plan tasks based on the request
    2. Execute tools autonomously
    3. Adapt based on findings
    4. Return results
    """
    try:
        session = await agent.execute_sync(
            target=request.target,
            request=request.request,
            scan_id=request.scan_id,
            context=request.context
        )

        if not session:
            raise HTTPException(status_code=500, detail="Agent execution failed")

        return AgentResponse(
            session_id=session.id,
            status=session.status.value,
            tasks_total=len(session.tasks),
            tasks_completed=sum(1 for t in session.tasks if t.status.value == "completed"),
            findings_count=len(session.findings)
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.websocket("/ws/{target:path}")
async def agent_websocket(
    websocket: WebSocket,
    target: str
):
    """
    WebSocket endpoint for real-time agent execution

    Connect and send a JSON message with your request:
    {"request": "Find all SQL injection vulnerabilities"}

    Receive streaming events as the agent executes.
    """
    await websocket.accept()

    try:
        # Get dependencies with multi-agent support
        llm = await get_llm_service()
        tools = create_default_registry()
        memory = MemorySystem()
        orchestrator = await get_multi_agent_orchestrator()

        agent = (
            AgentLoopBuilder()
            .with_llm(llm)
            .with_tools(tools)
            .with_memory(memory)
            .with_orchestrator(orchestrator)
            .build()
        )

        # Wait for request
        data = await websocket.receive_json()
        user_request = data.get("request", "Perform security scan")
        context = data.get("context", {})

        # Stream events
        async for event in agent.execute(
            target=target,
            request=user_request,
            context=context
        ):
            await websocket.send_json(event.to_dict())

    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({
            "type": "error",
            "data": {"message": str(e)}
        })
        await websocket.close()


@router.get("/session/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    agent: AgentLoop = Depends(get_agent_loop)
):
    """Get status of an agent session"""
    session = agent.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return SessionResponse(
        id=session.id,
        status=session.status.value,
        target=session.target,
        user_request=session.user_request,
        tasks=[
            {
                "id": t.id,
                "description": t.description,
                "tool": t.tool_name,
                "status": t.status.value
            }
            for t in session.tasks
        ],
        findings_count=len(session.findings),
        reasoning=[
            {
                "step": r.step_type,
                "content": r.content
            }
            for r in session.reasoning
        ],
        tool_calls=[
            {
                "tool": tc.tool_name,
                "status": tc.status.value,
                "duration_ms": tc.duration_ms
            }
            for tc in session.tool_calls
        ]
    )


@router.post("/session/{session_id}/stop")
async def stop_session(
    session_id: str,
    agent: AgentLoop = Depends(get_agent_loop)
):
    """Stop a running agent session"""
    agent.stop_session(session_id)
    return {"status": "stopped", "session_id": session_id}


@router.get("/tools")
async def list_tools(agent: AgentLoop = Depends(get_agent_loop)):
    """List all available agent tools"""
    return agent.tools.to_dict()


@router.get("/memory/stats")
async def memory_stats(agent: AgentLoop = Depends(get_agent_loop)):
    """Get memory system statistics"""
    if agent.memory:
        return await agent.memory.get_stats()
    return {"error": "Memory system not initialized"}


@router.get("/memory/patterns/{category}")
async def get_patterns(
    category: str,
    limit: int = 10,
    agent: AgentLoop = Depends(get_agent_loop)
):
    """Get successful patterns for a category"""
    if agent.memory:
        payloads = await agent.memory.get_best_payloads(category, limit=limit)
        return {"category": category, "patterns": payloads}
    return {"error": "Memory system not initialized"}


@router.get("/memory/chains")
async def get_chains(
    chain_type: Optional[str] = None,
    limit: int = 5,
    agent: AgentLoop = Depends(get_agent_loop)
):
    """Get successful exploitation chains"""
    if agent.memory:
        chains = await agent.memory.get_successful_chains(chain_type, limit=limit)
        return {"chains": chains}
    return {"error": "Memory system not initialized"}
