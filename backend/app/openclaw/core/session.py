"""
Agent Session Management
"""

import uuid
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class SessionStatus(str, Enum):
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING = "waiting"  # Waiting for user input
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ToolCall:
    """Record of a tool invocation"""
    id: str
    tool_name: str
    parameters: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    duration_ms: Optional[float] = None


@dataclass
class ReasoningStep:
    """A step in the agent's reasoning process"""
    id: str
    step_type: str  # "thought", "plan", "observation", "decision"
    content: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Task:
    """A planned task to execute"""
    id: str
    description: str
    tool_name: str
    parameters: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    priority: int = 1  # 1 = highest
    depends_on: List[str] = field(default_factory=list)
    result: Optional[Any] = None
    error: Optional[str] = None


@dataclass
class AgentSession:
    """
    Manages state for an agent execution session
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: Optional[str] = None
    target: Optional[str] = None

    # Status
    status: SessionStatus = SessionStatus.IDLE
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    # User request
    user_request: str = ""

    # Planning
    tasks: List[Task] = field(default_factory=list)
    current_task_index: int = 0

    # Execution trace
    reasoning: List[ReasoningStep] = field(default_factory=list)
    tool_calls: List[ToolCall] = field(default_factory=list)

    # Findings during this session
    findings: List[Dict[str, Any]] = field(default_factory=list)

    # Context for LLM
    context: Dict[str, Any] = field(default_factory=dict)

    def add_reasoning(self, step_type: str, content: str, metadata: Dict = None) -> ReasoningStep:
        """Add a reasoning step"""
        step = ReasoningStep(
            id=str(uuid.uuid4()),
            step_type=step_type,
            content=content,
            metadata=metadata or {}
        )
        self.reasoning.append(step)
        self.updated_at = datetime.utcnow()
        return step

    def add_tool_call(self, tool_name: str, parameters: Dict[str, Any]) -> ToolCall:
        """Record a tool call"""
        call = ToolCall(
            id=str(uuid.uuid4()),
            tool_name=tool_name,
            parameters=parameters,
            started_at=datetime.utcnow()
        )
        self.tool_calls.append(call)
        self.updated_at = datetime.utcnow()
        return call

    def complete_tool_call(self, call_id: str, result: Any = None, error: str = None):
        """Mark a tool call as complete"""
        for call in self.tool_calls:
            if call.id == call_id:
                call.completed_at = datetime.utcnow()
                call.status = TaskStatus.COMPLETED if not error else TaskStatus.FAILED
                call.result = result
                call.error = error
                if call.started_at:
                    call.duration_ms = (call.completed_at - call.started_at).total_seconds() * 1000
                break
        self.updated_at = datetime.utcnow()

    def add_finding(self, finding: Dict[str, Any]):
        """Add a discovered finding"""
        self.findings.append(finding)
        self.updated_at = datetime.utcnow()

    def get_current_task(self) -> Optional[Task]:
        """Get the current task being executed"""
        if 0 <= self.current_task_index < len(self.tasks):
            return self.tasks[self.current_task_index]
        return None

    def advance_task(self) -> Optional[Task]:
        """Move to the next task"""
        self.current_task_index += 1
        return self.get_current_task()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize session state"""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "target": self.target,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "user_request": self.user_request,
            "tasks": [
                {
                    "id": t.id,
                    "description": t.description,
                    "tool_name": t.tool_name,
                    "status": t.status.value,
                    "priority": t.priority
                }
                for t in self.tasks
            ],
            "current_task_index": self.current_task_index,
            "reasoning": [
                {
                    "id": r.id,
                    "step_type": r.step_type,
                    "content": r.content,
                    "timestamp": r.timestamp.isoformat()
                }
                for r in self.reasoning
            ],
            "tool_calls": [
                {
                    "id": tc.id,
                    "tool_name": tc.tool_name,
                    "status": tc.status.value,
                    "duration_ms": tc.duration_ms,
                    "error": tc.error
                }
                for tc in self.tool_calls
            ],
            "findings_count": len(self.findings)
        }
