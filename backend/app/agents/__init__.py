"""
Multi-Agent System for Intelligent Pentesting

Phase 2 - Autonomous agent architecture for coordinated security testing.
"""

from app.agents.base_agent import BaseAgent, AgentCapability, AgentMessage
from app.agents.orchestrator_agent import OrchestratorAgent
from app.agents.recon_agent import ReconAgent
from app.agents.exploitation_agent import ExploitationAgent
from app.agents.analysis_agent import AnalysisAgent
from app.agents.reporting_agent import ReportingAgent
from app.agents.agent_coordinator import AgentCoordinator, get_agent_coordinator

__all__ = [
    # Base
    'BaseAgent',
    'AgentCapability',
    'AgentMessage',

    # Agents
    'OrchestratorAgent',
    'ReconAgent',
    'ExploitationAgent',
    'AnalysisAgent',
    'ReportingAgent',

    # Coordinator
    'AgentCoordinator',
    'get_agent_coordinator',
]
