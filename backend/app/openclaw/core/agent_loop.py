"""
Agent Loop - Main orchestrator for offensive AI agent
"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, Callable, AsyncGenerator
from dataclasses import dataclass
import aiohttp

from .session import AgentSession, SessionStatus, TaskStatus
from .task_planner import TaskPlanner

# Import Juice Shop detection
try:
    from app.knowledge.juice_shop import is_juice_shop, get_attack_plan
    JUICE_SHOP_AVAILABLE = True
except ImportError:
    JUICE_SHOP_AVAILABLE = False


@dataclass
class AgentEvent:
    """Event emitted by agent for real-time updates"""
    event_type: str  # "reasoning", "tool_start", "tool_complete", "finding", "status", "error"
    data: Dict[str, Any]
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.event_type,
            "data": self.data,
            "timestamp": self.timestamp.isoformat()
        }


class AgentLoop:
    """
    Main agent loop that:
    1. Receives user requests
    2. Plans tasks using LLM
    3. Executes tools
    4. Adapts based on findings
    5. Learns from results
    """

    def __init__(
        self,
        llm_service,
        tool_registry,
        memory_system=None,
        db_session=None
    ):
        self.llm = llm_service
        self.tools = tool_registry
        self.memory = memory_system
        self.db = db_session
        self.planner = TaskPlanner(llm_service, tool_registry)

        # Active sessions
        self.sessions: Dict[str, AgentSession] = {}

        # Event callbacks for real-time updates
        self._event_callbacks: Dict[str, list] = {}

    async def execute(
        self,
        target: str,
        request: str,
        scan_id: str = None,
        context: Dict[str, Any] = None
    ) -> AsyncGenerator[AgentEvent, None]:
        """
        Execute an agent session with streaming events

        Args:
            target: Target URL/host
            request: User's natural language request
            scan_id: Optional associated scan ID
            context: Additional context

        Yields:
            AgentEvent objects for real-time updates
        """
        # Create session
        session = AgentSession(
            scan_id=scan_id,
            target=target,
            user_request=request,
            context=context or {}
        )
        self.sessions[session.id] = session

        try:
            # Phase 1: Planning
            yield AgentEvent("status", {"phase": "planning", "session_id": session.id})
            session.status = SessionStatus.PLANNING

            session.add_reasoning("thought", f"Analyzing request: {request}")
            yield AgentEvent("reasoning", {
                "step": "thought",
                "content": f"Analyzing request: {request}"
            })

            # Get context from memory if available
            if self.memory:
                memory_context = await self.memory.get_relevant_context(target, request)
                session.context.update(memory_context)

            # Detect known targets (like OWASP Juice Shop)
            await self._detect_known_targets(target, session)

            # Plan tasks
            plan_result = await self.planner.plan(target, request, session.context)

            if not plan_result.success:
                yield AgentEvent("error", {"message": plan_result.error or "Planning failed"})
                session.status = SessionStatus.FAILED
                return

            session.tasks = plan_result.tasks
            session.add_reasoning("plan", plan_result.reasoning)

            yield AgentEvent("reasoning", {
                "step": "plan",
                "content": plan_result.reasoning,
                "tasks": [{"id": t.id, "description": t.description, "tool": t.tool_name} for t in session.tasks]
            })

            # Phase 2: Execution
            yield AgentEvent("status", {"phase": "executing", "session_id": session.id})
            session.status = SessionStatus.EXECUTING

            for task in session.tasks:
                if session.status == SessionStatus.STOPPED:
                    break

                # Start task
                task.status = TaskStatus.RUNNING
                yield AgentEvent("tool_start", {
                    "task_id": task.id,
                    "tool": task.tool_name,
                    "description": task.description,
                    "parameters": task.parameters
                })

                # Record tool call
                tool_call = session.add_tool_call(task.tool_name, task.parameters)

                try:
                    # Execute tool
                    tool = self.tools.get_tool(task.tool_name)
                    if not tool:
                        raise ValueError(f"Unknown tool: {task.tool_name}")

                    result = await tool.execute(**task.parameters)

                    # Process result
                    task.status = TaskStatus.COMPLETED
                    task.result = result
                    session.complete_tool_call(tool_call.id, result=result)

                    yield AgentEvent("tool_complete", {
                        "task_id": task.id,
                        "tool": task.tool_name,
                        "success": True,
                        "duration_ms": tool_call.duration_ms,
                        "summary": self._summarize_result(result)
                    })

                    # Extract findings from result
                    findings = self._extract_findings(result)
                    for finding in findings:
                        session.add_finding(finding)
                        yield AgentEvent("finding", finding)

                        # Record success in memory
                        if self.memory and finding.get("severity") in ["critical", "high"]:
                            await self.memory.record_success(
                                pattern_type="technique",
                                category=finding.get("type", "unknown"),
                                context={"target": target, "tool": task.tool_name},
                                payload=task.parameters.get("payload"),
                                technique=task.tool_name
                            )

                    # Adaptive replanning if significant findings
                    if len(findings) > 0 and any(f.get("severity") in ["critical", "high"] for f in findings):
                        session.add_reasoning("observation", f"Found {len(findings)} vulnerabilities, considering exploitation chains")
                        yield AgentEvent("reasoning", {
                            "step": "observation",
                            "content": f"Found {len(findings)} vulnerabilities, analyzing exploitation paths"
                        })

                        # Check for chain opportunities
                        replan_result = await self.planner.replan(session, findings, session.context)
                        if replan_result.tasks:
                            session.tasks.extend(replan_result.tasks)
                            yield AgentEvent("reasoning", {
                                "step": "decision",
                                "content": f"Adding {len(replan_result.tasks)} follow-up tasks for exploitation"
                            })

                except Exception as e:
                    task.status = TaskStatus.FAILED
                    task.error = str(e)
                    session.complete_tool_call(tool_call.id, error=str(e))

                    yield AgentEvent("tool_complete", {
                        "task_id": task.id,
                        "tool": task.tool_name,
                        "success": False,
                        "error": str(e)
                    })

                    session.add_reasoning("observation", f"Task failed: {str(e)}")

            # Phase 3: Completion
            session.status = SessionStatus.COMPLETED
            yield AgentEvent("status", {
                "phase": "completed",
                "session_id": session.id,
                "summary": {
                    "total_tasks": len(session.tasks),
                    "completed": sum(1 for t in session.tasks if t.status == TaskStatus.COMPLETED),
                    "failed": sum(1 for t in session.tasks if t.status == TaskStatus.FAILED),
                    "findings": len(session.findings)
                }
            })

            # Store session in database if available
            if self.db:
                await self._persist_session(session)

        except Exception as e:
            session.status = SessionStatus.FAILED
            yield AgentEvent("error", {"message": str(e), "session_id": session.id})

        finally:
            # Keep session in memory for retrieval
            pass

    async def execute_sync(
        self,
        target: str,
        request: str,
        scan_id: str = None,
        context: Dict[str, Any] = None
    ) -> AgentSession:
        """
        Execute synchronously and return final session state
        """
        events = []
        async for event in self.execute(target, request, scan_id, context):
            events.append(event)

        session_id = events[0].data.get("session_id") if events else None
        return self.sessions.get(session_id)

    def stop_session(self, session_id: str):
        """Stop a running session"""
        if session_id in self.sessions:
            self.sessions[session_id].status = SessionStatus.STOPPED

    def get_session(self, session_id: str) -> Optional[AgentSession]:
        """Get a session by ID"""
        return self.sessions.get(session_id)

    def _summarize_result(self, result: Any) -> str:
        """Create a brief summary of a tool result"""
        if result is None:
            return "No result"

        if isinstance(result, dict):
            if "findings" in result:
                return f"Found {len(result['findings'])} potential issues"
            if "endpoints" in result:
                return f"Discovered {len(result['endpoints'])} endpoints"
            if "error" in result:
                return f"Error: {result['error']}"
            return f"Result with {len(result)} fields"

        if isinstance(result, list):
            return f"Returned {len(result)} items"

        return str(result)[:100]

    def _extract_findings(self, result: Any) -> list:
        """Extract vulnerability findings from tool result"""
        findings = []

        if isinstance(result, dict):
            # Direct findings list
            if "findings" in result:
                findings.extend(result["findings"])
            # Single finding
            elif "vulnerability" in result or "vuln_type" in result:
                findings.append(result)
            # Nested vulnerabilities
            elif "vulnerabilities" in result:
                findings.extend(result["vulnerabilities"])

        elif isinstance(result, list):
            for item in result:
                if isinstance(item, dict) and ("vulnerability" in item or "vuln_type" in item or "type" in item):
                    findings.append(item)

        return findings

    async def _persist_session(self, session: AgentSession):
        """Persist session to database"""
        # This would save to AgentTask table
        pass

    async def _detect_known_targets(self, target: str, session: AgentSession):
        """Detect known vulnerable targets and update context"""
        if not JUICE_SHOP_AVAILABLE:
            return

        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(target, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = await resp.text()
                    headers = dict(resp.headers)

                    if is_juice_shop(headers, body):
                        session.context["is_juice_shop"] = True
                        session.context["attack_plan"] = get_attack_plan(target)
                        session.add_reasoning(
                            "observation",
                            "🍊 OWASP Juice Shop detected! Loaded specialized attack knowledge with 111 known challenges."
                        )
        except Exception:
            pass  # Continue without detection if request fails


class AgentLoopBuilder:
    """Builder pattern for AgentLoop configuration"""

    def __init__(self):
        self._llm = None
        self._tools = None
        self._memory = None
        self._db = None

    def with_llm(self, llm_service):
        self._llm = llm_service
        return self

    def with_tools(self, tool_registry):
        self._tools = tool_registry
        return self

    def with_memory(self, memory_system):
        self._memory = memory_system
        return self

    def with_database(self, db_session):
        self._db = db_session
        return self

    def build(self) -> AgentLoop:
        if not self._llm:
            raise ValueError("LLM service is required")
        if not self._tools:
            raise ValueError("Tool registry is required")

        return AgentLoop(
            llm_service=self._llm,
            tool_registry=self._tools,
            memory_system=self._memory,
            db_session=self._db
        )
