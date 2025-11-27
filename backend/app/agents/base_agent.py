"""
Base Agent Class

Foundation for all autonomous pentesting agents.
"""
import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

class AgentCapability(str, Enum):
    """Agent capabilities"""
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    ORCHESTRATION = "orchestration"
    VALIDATION = "validation"

@dataclass
class AgentMessage:
    """Message passed between agents"""
    sender: str
    receiver: str
    message_type: str
    content: Dict[str, Any]
    timestamp: datetime
    priority: int = 1  # 1=low, 5=high

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "message_type": self.message_type,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "priority": self.priority
        }

class BaseAgent(ABC):
    """
    Base class for all agents

    Each agent is autonomous and specializes in specific tasks.
    Agents communicate via messages and can request help from other agents.
    """

    def __init__(self, agent_id: str, capabilities: List[AgentCapability]):
        """
        Initialize agent

        Args:
            agent_id: Unique identifier for this agent
            capabilities: List of agent capabilities
        """
        self.agent_id = agent_id
        self.capabilities = capabilities
        self.message_queue: List[AgentMessage] = []
        self.state: Dict[str, Any] = {}
        self.logger = logging.getLogger(f"{__name__}.{agent_id}")

    @abstractmethod
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a task assigned to this agent

        Args:
            task: Task dictionary with type and parameters

        Returns:
            Task execution result
        """
        raise NotImplementedError("Subclasses must implement execute_task()")

    @abstractmethod
    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Process incoming message from another agent

        Args:
            message: Message from another agent

        Returns:
            Optional response message
        """
        raise NotImplementedError("Subclasses must implement process_message()")

    def send_message(
        self,
        receiver: str,
        message_type: str,
        content: Dict[str, Any],
        priority: int = 1
    ) -> AgentMessage:
        """
        Send message to another agent

        Args:
            receiver: Target agent ID
            message_type: Type of message
            content: Message content
            priority: Message priority (1-5)

        Returns:
            Created message
        """
        message = AgentMessage(
            sender=self.agent_id,
            receiver=receiver,
            message_type=message_type,
            content=content,
            timestamp=datetime.now(),
            priority=priority
        )

        self.logger.info(
            f"📤 Sending message to {receiver}: {message_type} (priority: {priority})"
        )

        return message

    def receive_message(self, message: AgentMessage):
        """
        Receive message from another agent

        Args:
            message: Incoming message
        """
        self.logger.info(
            f"📥 Received message from {message.sender}: {message.message_type}"
        )
        self.message_queue.append(message)

    def can_handle(self, capability: AgentCapability) -> bool:
        """Check if agent has specific capability"""
        return capability in self.capabilities

    def get_state(self) -> Dict[str, Any]:
        """Get current agent state"""
        return {
            "agent_id": self.agent_id,
            "capabilities": [c.value for c in self.capabilities],
            "queue_size": len(self.message_queue),
            "state": self.state
        }

    async def think(self, context: Dict[str, Any]) -> str:
        """
        Agent's reasoning process (using LLM if available)

        Args:
            context: Current context and data

        Returns:
            Reasoning/decision
        """
        # Default implementation - subclasses can override for LLM-powered reasoning
        return f"Agent {self.agent_id} analyzing context..."

    def log_action(self, action: str, details: Dict[str, Any] = None):
        """Log agent action"""
        self.logger.info(f"🤖 {self.agent_id}: {action}")
        if details:
            self.logger.debug(f"   Details: {details}")
