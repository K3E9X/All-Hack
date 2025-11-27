"""
Agent Coordinator

Manages all agents and facilitates inter-agent communication.
"""
import logging
from typing import Dict, Any, List, Optional
import asyncio

from app.agents.base_agent import BaseAgent, AgentMessage
from app.agents.orchestrator_agent import OrchestratorAgent
from app.agents.recon_agent import ReconAgent
from app.agents.exploitation_agent import ExploitationAgent
from app.agents.analysis_agent import AnalysisAgent
from app.agents.reporting_agent import ReportingAgent

logger = logging.getLogger(__name__)

class AgentCoordinator:
    """
    Agent Coordinator - Multi-Agent System Manager

    Responsibilities:
    - Initialize all agents
    - Route messages between agents
    - Monitor agent health
    - Coordinate concurrent tasks
    - Provide global view of system state
    """

    def __init__(self):
        """Initialize all agents"""
        self.agents: Dict[str, BaseAgent] = {}
        self.message_queue: List[AgentMessage] = []
        self.running = False

        # Initialize agents
        self._initialize_agents()

        logger.info("🤖 Agent Coordinator initialized with %d agents", len(self.agents))

    def _initialize_agents(self):
        """Initialize all agents"""
        self.agents["orchestrator"] = OrchestratorAgent()
        self.agents["recon"] = ReconAgent()
        self.agents["exploitation"] = ExploitationAgent()
        self.agents["analysis"] = AnalysisAgent()
        self.agents["reporting"] = ReportingAgent()

        logger.info("✅ All agents initialized")

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get agent by ID"""
        return self.agents.get(agent_id)

    async def send_message(self, message: AgentMessage):
        """
        Send message from one agent to another

        Args:
            message: Message to send
        """
        receiver = self.agents.get(message.receiver)

        if not receiver:
            logger.error(f"❌ Agent {message.receiver} not found")
            return

        # Deliver message
        receiver.receive_message(message)

        # Process message and get response
        response = await receiver.process_message(message)

        # If there's a response, queue it
        if response:
            self.message_queue.append(response)
            # Deliver response
            await self.send_message(response)

    async def execute_agent_task(
        self,
        agent_id: str,
        task: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute task on specific agent

        Args:
            agent_id: Target agent ID
            task: Task to execute

        Returns:
            Task result
        """
        agent = self.agents.get(agent_id)

        if not agent:
            return {"error": f"Agent {agent_id} not found"}

        logger.info(f"🎯 Executing task on {agent_id}: {task.get('type')}")

        result = await agent.execute_task(task)

        return result

    async def start_scan_workflow(
        self,
        scan_id: str,
        scan_request: Any
    ) -> Dict[str, Any]:
        """
        Start multi-agent scan workflow

        Workflow:
        1. Orchestrator coordinates
        2. Recon discovers targets
        3. Exploitation tests vulnerabilities
        4. Validation confirms findings
        5. Analysis correlates results
        6. Reporting generates reports

        Args:
            scan_id: Scan identifier
            scan_request: Scan request object

        Returns:
            Workflow initialization result
        """
        logger.info(f"🚀 Starting multi-agent workflow for scan {scan_id}")

        # Send task to orchestrator
        orchestrator = self.agents["orchestrator"]

        task = {
            "type": "start_scan",
            "scan_id": scan_id,
            "scan_request": scan_request
        }

        result = await orchestrator.execute_task(task)

        # Get initial message
        if result.get("message_sent"):
            message_dict = result["message_sent"]

            # Recreate message object
            from datetime import datetime
            message = AgentMessage(
                sender=message_dict["sender"],
                receiver=message_dict["receiver"],
                message_type=message_dict["message_type"],
                content=message_dict["content"],
                timestamp=datetime.fromisoformat(message_dict["timestamp"]),
                priority=message_dict["priority"]
            )

            # Start message delivery chain
            await self.send_message(message)

        return result

    async def get_workflow_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get workflow status for a scan

        Args:
            scan_id: Scan identifier

        Returns:
            Workflow status
        """
        orchestrator = self.agents.get("orchestrator")

        if not isinstance(orchestrator, OrchestratorAgent):
            return None

        return orchestrator.get_workflow_summary(scan_id)

    def get_all_agent_states(self) -> Dict[str, Dict[str, Any]]:
        """Get state of all agents"""
        states = {}

        for agent_id, agent in self.agents.items():
            states[agent_id] = agent.get_state()

        return states

    async def broadcast_message(
        self,
        sender: str,
        message_type: str,
        content: Dict[str, Any],
        exclude: List[str] = None
    ):
        """
        Broadcast message to all agents

        Args:
            sender: Sender agent ID
            message_type: Type of message
            content: Message content
            exclude: Agents to exclude from broadcast
        """
        exclude = exclude or []

        for agent_id, agent in self.agents.items():
            if agent_id not in exclude and agent_id != sender:
                message = AgentMessage(
                    sender=sender,
                    receiver=agent_id,
                    message_type=message_type,
                    content=content,
                    timestamp=asyncio.get_event_loop().time(),
                    priority=1
                )

                await self.send_message(message)

    def shutdown(self):
        """Shutdown all agents"""
        logger.info("🛑 Shutting down Agent Coordinator")
        self.running = False

        for agent_id, agent in self.agents.items():
            logger.info(f"   Stopping {agent_id}...")

        logger.info("✅ All agents stopped")


# Singleton instance
_agent_coordinator: Optional[AgentCoordinator] = None

def get_agent_coordinator() -> AgentCoordinator:
    """Get or create agent coordinator singleton"""
    global _agent_coordinator
    if _agent_coordinator is None:
        _agent_coordinator = AgentCoordinator()
    return _agent_coordinator
