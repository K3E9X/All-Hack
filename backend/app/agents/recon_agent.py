"""
Reconnaissance Agent

Intelligent enumeration and information gathering.
"""
import logging
from typing import Dict, Any, List, Optional

from app.agents.base_agent import BaseAgent, AgentCapability, AgentMessage
from app.intelligence import get_ollama_client

logger = logging.getLogger(__name__)

class ReconAgent(BaseAgent):
    """
    Recon Agent - Intelligent Reconnaissance

    Responsibilities:
    - Enumerate endpoints and parameters
    - Identify technologies and frameworks
    - Discover hidden resources
    - Map attack surface
    - Prioritize targets based on risk
    - Learn from previous scans
    """

    def __init__(self):
        super().__init__(
            agent_id="recon",
            capabilities=[AgentCapability.RECONNAISSANCE]
        )
        self.discovered_endpoints = []
        self.technologies = []
        self.attack_surface_map = {}

    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute reconnaissance task

        Task types:
        - enumerate_endpoints: Discover all endpoints
        - identify_tech_stack: Detect technologies
        - map_attack_surface: Create attack surface map
        - prioritize_targets: Rank targets by risk
        """
        task_type = task.get("type")

        if task_type == "enumerate_endpoints":
            return await self._enumerate_endpoints(task)
        elif task_type == "identify_tech_stack":
            return await self._identify_tech_stack(task)
        elif task_type == "map_attack_surface":
            return await self._map_attack_surface(task)
        elif task_type == "prioritize_targets":
            return await self._prioritize_targets(task)
        else:
            return {"error": f"Unknown task type: {task_type}"}

    async def _enumerate_endpoints(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Intelligently enumerate endpoints

        Uses:
        - Spider/crawler
        - Sitemap.xml parsing
        - Robots.txt analysis
        - JavaScript parsing for API endpoints
        - Historical data from memory
        """
        target_url = task.get("target_url")

        self.log_action(f"Enumerating endpoints for {target_url}")

        # TODO: Implement intelligent crawling
        # For now, return structure
        endpoints = []

        return {
            "target_url": target_url,
            "endpoints_found": len(endpoints),
            "endpoints": endpoints,
            "methods": ["GET", "POST", "PUT", "DELETE"]
        }

    async def _identify_tech_stack(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Identify technologies using AI

        Analyzes:
        - HTTP headers
        - HTML/JavaScript signatures
        - Error messages
        - Cookie patterns
        - Response timing
        """
        target_url = task.get("target_url")

        self.log_action(f"Identifying tech stack for {target_url}")

        # Use LLM for intelligent tech detection
        ollama = get_ollama_client()
        if await ollama.check_available():
            prompt = f"""Analyze this target for technology stack: {target_url}

Based on common patterns, what technologies are likely used?
List: Web server, framework, database, CMS, etc."""

            tech_analysis = await ollama.generate(
                prompt=prompt,
                system_prompt="You are a web technology identification expert."
            )

            self.technologies.append({
                "target": target_url,
                "analysis": tech_analysis
            })

        return {
            "target_url": target_url,
            "technologies": self.technologies
        }

    async def _map_attack_surface(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create comprehensive attack surface map

        Identifies:
        - User inputs (forms, parameters)
        - Authentication endpoints
        - File uploads
        - API endpoints
        - Admin panels
        - Sensitive paths
        """
        target_url = task.get("target_url")
        endpoints = task.get("endpoints", [])

        self.log_action(f"Mapping attack surface for {target_url}")

        attack_surface = {
            "user_inputs": [],
            "auth_endpoints": [],
            "file_uploads": [],
            "api_endpoints": [],
            "admin_paths": [],
            "sensitive_paths": []
        }

        # TODO: Intelligent mapping based on endpoints
        # Use AI to categorize and prioritize

        self.attack_surface_map[target_url] = attack_surface

        return {
            "target_url": target_url,
            "attack_surface": attack_surface,
            "risk_areas": len(attack_surface["user_inputs"])
        }

    async def _prioritize_targets(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prioritize targets based on risk and likelihood

        Factors:
        - Input complexity
        - Authentication requirements
        - Technology vulnerabilities
        - Historical exploitation success
        - Business criticality
        """
        endpoints = task.get("endpoints", [])

        self.log_action(f"Prioritizing {len(endpoints)} targets")

        # Use AI for intelligent prioritization
        prioritized = []

        # TODO: Implement AI-powered risk scoring

        return {
            "total_targets": len(endpoints),
            "prioritized_targets": prioritized,
            "high_priority": len([t for t in prioritized if t.get("priority") == "high"])
        }

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process messages from orchestrator"""
        message_type = message.message_type

        if message_type == "start_reconnaissance":
            # Start recon phase
            scan_id = message.content.get("scan_id")
            target_url = message.content.get("target_url")

            self.log_action(f"Starting reconnaissance for scan {scan_id}")

            # Execute all recon tasks
            await self._enumerate_endpoints({"target_url": target_url})
            await self._identify_tech_stack({"target_url": target_url})
            await self._map_attack_surface({"target_url": target_url})

            # Notify orchestrator of completion
            return self.send_message(
                receiver="orchestrator",
                message_type="phase_complete",
                content={
                    "scan_id": scan_id,
                    "phase": "recon",
                    "endpoints_found": len(self.discovered_endpoints),
                    "technologies": self.technologies
                },
                priority=4
            )

        return None

    async def think(self, context: Dict[str, Any]) -> str:
        """
        Recon agent reasoning

        Analyzes context and decides:
        - Which endpoints to scan first
        - What techniques to use
        - How deep to enumerate
        """
        ollama = get_ollama_client()
        if not await ollama.check_available():
            return "LLM not available for reasoning"

        prompt = f"""You are a reconnaissance agent in a pentesting tool.

Context:
- Target: {context.get('target_url')}
- Endpoints found: {context.get('endpoints_count', 0)}
- Technologies: {context.get('technologies', [])}

Decision needed: What should be the next reconnaissance action?
Consider: thoroughness vs speed, target sensitivity, common vulnerabilities.

Provide a concise recommendation."""

        reasoning = await ollama.generate(
            prompt=prompt,
            system_prompt="You are an expert reconnaissance specialist in cybersecurity."
        )

        return reasoning
