"""
Orchestrator Agent

Coordinates workflow between all agents and manages scan lifecycle.
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.agents.base_agent import BaseAgent, AgentCapability, AgentMessage
from app.models import ScanRequest, ScanResult

logger = logging.getLogger(__name__)

class OrchestratorAgent(BaseAgent):
    """
    Orchestrator Agent - Master coordinator

    Responsibilities:
    - Coordinates workflow between all agents
    - Manages scan lifecycle (start → recon → exploit → analyze → report)
    - Prioritizes tasks based on findings
    - Decides when to call which agent
    - Monitors progress and handles failures
    """

    def __init__(self):
        super().__init__(
            agent_id="orchestrator",
            capabilities=[AgentCapability.ORCHESTRATION]
        )
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.workflow_history: List[Dict[str, Any]] = []

    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute orchestration task

        Task types:
        - start_scan: Initiate new scan workflow
        - monitor_scan: Check scan progress
        - coordinate_agents: Coordinate agent actions
        """
        task_type = task.get("type")

        if task_type == "start_scan":
            return await self._start_scan_workflow(task)
        elif task_type == "monitor_scan":
            return await self._monitor_scan(task)
        elif task_type == "coordinate_agents":
            return await self._coordinate_agents(task)
        else:
            return {"error": f"Unknown task type: {task_type}"}

    async def _start_scan_workflow(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Start a new scan workflow

        Workflow phases:
        1. Recon Phase - Gather information (ReconAgent)
        2. Exploitation Phase - Test vulnerabilities (ExploitationAgent)
        3. Validation Phase - Confirm findings (ValidationOrchestrator)
        4. Analysis Phase - Analyze and correlate (AnalysisAgent)
        5. Reporting Phase - Generate report (ReportingAgent)
        """
        scan_id = task.get("scan_id")
        scan_request: ScanRequest = task.get("scan_request")

        self.log_action(f"Starting scan workflow for {scan_id}")

        # Initialize workflow state
        workflow = {
            "scan_id": scan_id,
            "start_time": datetime.now(),
            "current_phase": "recon",
            "phases": {
                "recon": {"status": "pending", "agent": "recon"},
                "exploitation": {"status": "pending", "agent": "exploitation"},
                "validation": {"status": "pending", "agent": "validation"},
                "analysis": {"status": "pending", "agent": "analysis"},
                "reporting": {"status": "pending", "agent": "reporting"}
            },
            "scan_request": scan_request,
            "findings": [],
            "errors": []
        }

        self.active_scans[scan_id] = workflow

        # Phase 1: Send task to Recon Agent
        recon_message = self.send_message(
            receiver="recon",
            message_type="start_reconnaissance",
            content={
                "scan_id": scan_id,
                "target_url": scan_request.target_url,
                "mode": scan_request.mode,
                "scope": scan_request.scope
            },
            priority=5
        )

        workflow["phases"]["recon"]["status"] = "in_progress"
        workflow["phases"]["recon"]["started_at"] = datetime.now()

        return {
            "scan_id": scan_id,
            "workflow_initiated": True,
            "current_phase": "recon",
            "message_sent": recon_message.to_dict()
        }

    async def _monitor_scan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor scan progress"""
        scan_id = task.get("scan_id")

        if scan_id not in self.active_scans:
            return {"error": f"Scan {scan_id} not found"}

        workflow = self.active_scans[scan_id]

        return {
            "scan_id": scan_id,
            "current_phase": workflow["current_phase"],
            "phases": workflow["phases"],
            "findings_count": len(workflow["findings"]),
            "errors_count": len(workflow["errors"])
        }

    async def _coordinate_agents(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Coordinate multiple agents

        Decides which agents should work together and in what order.
        """
        scan_id = task.get("scan_id")
        current_findings = task.get("findings", [])

        self.log_action(f"Coordinating agents for scan {scan_id}")

        # Decision tree based on findings
        coordination_plan = []

        # If SQL injection found, prioritize exploitation
        sql_findings = [f for f in current_findings if "sql" in f.get("category", "").lower()]
        if sql_findings:
            coordination_plan.append({
                "agent": "exploitation",
                "task": "exploit_sql_injection",
                "priority": 5,
                "findings": sql_findings
            })

        # If XSS found, validate with browser
        xss_findings = [f for f in current_findings if "xss" in f.get("category", "").lower()]
        if xss_findings:
            coordination_plan.append({
                "agent": "validation",
                "task": "validate_xss",
                "priority": 4,
                "findings": xss_findings
            })

        # Always run analysis on all findings
        coordination_plan.append({
            "agent": "analysis",
            "task": "correlate_vulnerabilities",
            "priority": 3,
            "findings": current_findings
        })

        return {
            "scan_id": scan_id,
            "coordination_plan": coordination_plan,
            "agents_involved": len(coordination_plan)
        }

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Process messages from other agents

        Message types:
        - phase_complete: Agent completed their phase
        - findings_update: New findings discovered
        - error: Error occurred
        - help_request: Agent needs assistance
        """
        message_type = message.message_type
        content = message.content

        if message_type == "phase_complete":
            return await self._handle_phase_complete(message)
        elif message_type == "findings_update":
            return await self._handle_findings_update(message)
        elif message_type == "error":
            return await self._handle_error(message)
        elif message_type == "help_request":
            return await self._handle_help_request(message)

        return None

    async def _handle_phase_complete(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Handle phase completion from an agent"""
        scan_id = message.content.get("scan_id")
        phase = message.content.get("phase")

        if scan_id not in self.active_scans:
            return None

        workflow = self.active_scans[scan_id]
        workflow["phases"][phase]["status"] = "completed"
        workflow["phases"][phase]["completed_at"] = datetime.now()

        self.log_action(f"Phase '{phase}' completed for scan {scan_id}")

        # Determine next phase
        next_phase = self._get_next_phase(workflow)

        if next_phase:
            workflow["current_phase"] = next_phase
            workflow["phases"][next_phase]["status"] = "in_progress"

            # Send message to next agent
            next_agent = workflow["phases"][next_phase]["agent"]

            return self.send_message(
                receiver=next_agent,
                message_type=f"start_{next_phase}",
                content={
                    "scan_id": scan_id,
                    "previous_findings": workflow["findings"]
                },
                priority=4
            )
        else:
            # All phases complete
            workflow["status"] = "completed"
            workflow["end_time"] = datetime.now()
            self.log_action(f"Scan {scan_id} workflow completed!")

        return None

    async def _handle_findings_update(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Handle new findings from an agent"""
        scan_id = message.content.get("scan_id")
        findings = message.content.get("findings", [])

        if scan_id in self.active_scans:
            self.active_scans[scan_id]["findings"].extend(findings)
            self.log_action(f"Added {len(findings)} findings to scan {scan_id}")

        return None

    async def _handle_error(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Handle error from an agent"""
        scan_id = message.content.get("scan_id")
        error = message.content.get("error")

        if scan_id in self.active_scans:
            self.active_scans[scan_id]["errors"].append({
                "agent": message.sender,
                "error": error,
                "timestamp": datetime.now()
            })

        self.log_action(f"Error in scan {scan_id} from {message.sender}: {error}")

        return None

    async def _handle_help_request(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Handle help request from an agent"""
        requesting_agent = message.sender
        help_type = message.content.get("help_type")

        self.log_action(f"Help request from {requesting_agent}: {help_type}")

        # Delegate to appropriate agent
        if help_type == "analysis":
            return self.send_message(
                receiver="analysis",
                message_type="analyze_request",
                content=message.content,
                priority=4
            )
        elif help_type == "exploitation":
            return self.send_message(
                receiver="exploitation",
                message_type="exploit_request",
                content=message.content,
                priority=4
            )

        return None

    def _get_next_phase(self, workflow: Dict[str, Any]) -> Optional[str]:
        """Determine next phase in workflow"""
        phase_order = ["recon", "exploitation", "validation", "analysis", "reporting"]
        current_phase = workflow["current_phase"]

        try:
            current_index = phase_order.index(current_phase)
            if current_index + 1 < len(phase_order):
                return phase_order[current_index + 1]
        except ValueError:
            pass

        return None

    def get_workflow_summary(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow summary for a scan"""
        if scan_id not in self.active_scans:
            return None

        workflow = self.active_scans[scan_id]

        return {
            "scan_id": scan_id,
            "current_phase": workflow["current_phase"],
            "status": workflow.get("status", "in_progress"),
            "start_time": workflow["start_time"].isoformat(),
            "findings_count": len(workflow["findings"]),
            "errors_count": len(workflow["errors"]),
            "phases": {
                phase: {
                    "status": data["status"],
                    "agent": data["agent"]
                }
                for phase, data in workflow["phases"].items()
            }
        }
