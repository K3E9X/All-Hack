"""
Task Planner - LLM-powered task decomposition and planning
"""

import uuid
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .session import Task, TaskStatus


# Planning prompt template
PLANNING_PROMPT = """You are an expert penetration tester AI assistant. Your job is to break down user requests into specific, executable tasks.

TARGET: {target}
USER REQUEST: {request}

AVAILABLE TOOLS:
{tools}

CONTEXT:
{context}

Based on the request, create a plan of tasks. Each task should:
1. Be specific and actionable
2. Map to exactly one available tool
3. Include all required parameters
4. Be ordered logically (dependencies first)

Respond with a JSON array of tasks:
```json
[
  {{
    "description": "Brief description of what this task does",
    "tool": "tool_name",
    "params": {{"param1": "value1"}},
    "priority": 1,
    "reasoning": "Why this task is needed"
  }}
]
```

Important:
- Start with reconnaissance if target is unknown
- Prioritize high-impact vulnerabilities (RCE, SQLi, Auth bypass)
- Consider chaining vulnerabilities when possible
- Be thorough but efficient

Return ONLY the JSON array, no other text."""


@dataclass
class PlanResult:
    """Result of planning operation"""
    success: bool
    tasks: List[Task]
    reasoning: str
    error: Optional[str] = None


class TaskPlanner:
    """
    Plans attack tasks using LLM reasoning
    """

    def __init__(self, llm_service, tool_registry):
        self.llm = llm_service
        self.tools = tool_registry

    async def plan(
        self,
        target: str,
        request: str,
        context: Dict[str, Any] = None
    ) -> PlanResult:
        """
        Create an execution plan from a user request

        Args:
            target: Target URL/host
            request: User's natural language request
            context: Additional context (tech stack, previous findings, etc.)

        Returns:
            PlanResult with list of tasks
        """
        context = context or {}

        # Build tool descriptions for prompt
        tool_descriptions = self._format_tool_descriptions()

        # Build context string
        context_str = self._format_context(context)

        # Create planning prompt
        prompt = PLANNING_PROMPT.format(
            target=target,
            request=request,
            tools=tool_descriptions,
            context=context_str
        )

        try:
            # Get plan from LLM
            response = await self.llm.analyze(prompt, context="task_planning")

            if not response:
                # Fallback to rule-based planning
                return self._fallback_plan(target, request, context)

            # Parse response
            tasks = self._parse_plan_response(response)

            if not tasks:
                return self._fallback_plan(target, request, context)

            return PlanResult(
                success=True,
                tasks=tasks,
                reasoning=f"Planned {len(tasks)} tasks based on: {request}"
            )

        except Exception as e:
            # Fallback on any error
            return self._fallback_plan(target, request, context)

    def _format_tool_descriptions(self) -> str:
        """Format tool registry for prompt"""
        lines = []
        for tool in self.tools.get_all_tools():
            params = ", ".join(f"{p.name}: {p.type}" for p in tool.parameters)
            lines.append(f"- {tool.name}: {tool.description}")
            if params:
                lines.append(f"  Parameters: {params}")
        return "\n".join(lines)

    def _format_context(self, context: Dict[str, Any]) -> str:
        """Format context for prompt"""
        if not context:
            return "No additional context available."

        lines = []
        if "technologies" in context:
            lines.append(f"Technologies: {', '.join(context['technologies'])}")
        if "previous_findings" in context:
            findings = context["previous_findings"]
            lines.append(f"Previous findings: {len(findings)} vulnerabilities found")
        if "endpoints" in context:
            lines.append(f"Known endpoints: {len(context['endpoints'])} discovered")
        if "waf_detected" in context:
            lines.append(f"WAF detected: {context['waf_detected']}")

        return "\n".join(lines) if lines else "No additional context available."

    def _parse_plan_response(self, response: str) -> List[Task]:
        """Parse LLM response into Task objects"""
        tasks = []

        try:
            # Extract JSON from response
            json_start = response.find("[")
            json_end = response.rfind("]") + 1

            if json_start == -1 or json_end == 0:
                return []

            json_str = response[json_start:json_end]
            plan_data = json.loads(json_str)

            for i, item in enumerate(plan_data):
                tool_name = item.get("tool", "")

                # Validate tool exists
                if not self.tools.has_tool(tool_name):
                    continue

                task = Task(
                    id=str(uuid.uuid4()),
                    description=item.get("description", f"Task {i+1}"),
                    tool_name=tool_name,
                    parameters=item.get("params", {}),
                    status=TaskStatus.PENDING,
                    priority=item.get("priority", i + 1)
                )
                tasks.append(task)

        except json.JSONDecodeError:
            return []

        # Sort by priority
        tasks.sort(key=lambda t: t.priority)
        return tasks

    def _fallback_plan(
        self,
        target: str,
        request: str,
        context: Dict[str, Any]
    ) -> PlanResult:
        """
        Rule-based fallback planning when LLM unavailable
        """
        tasks = []
        request_lower = request.lower()

        # Determine what the user wants
        wants_recon = any(w in request_lower for w in ["scan", "find", "discover", "recon", "crawl"])
        wants_sqli = any(w in request_lower for w in ["sql", "sqli", "injection", "database"])
        wants_xss = any(w in request_lower for w in ["xss", "cross-site", "script"])
        wants_rce = any(w in request_lower for w in ["rce", "command", "exec", "shell"])
        wants_auth = any(w in request_lower for w in ["auth", "login", "bypass", "session"])
        wants_all = any(w in request_lower for w in ["all", "full", "complete", "everything"])
        wants_chain = any(w in request_lower for w in ["chain", "escalate", "pivot"])

        # Always start with recon if no context
        if wants_recon or not context.get("endpoints"):
            tasks.append(Task(
                id=str(uuid.uuid4()),
                description="Crawl target and discover endpoints",
                tool_name="crawl",
                parameters={"url": target, "depth": 3},
                priority=1
            ))
            tasks.append(Task(
                id=str(uuid.uuid4()),
                description="Detect technologies and frameworks",
                tool_name="tech_detect",
                parameters={"url": target},
                priority=2
            ))

        # Add requested vuln tests
        priority = 10

        if wants_sqli or wants_all:
            tasks.append(Task(
                id=str(uuid.uuid4()),
                description="Test for SQL injection vulnerabilities",
                tool_name="test_sqli",
                parameters={"url": target, "methods": ["boolean", "error", "time"]},
                priority=priority
            ))
            priority += 1

        if wants_xss or wants_all:
            tasks.append(Task(
                id=str(uuid.uuid4()),
                description="Test for XSS vulnerabilities",
                tool_name="test_xss",
                parameters={"url": target, "contexts": ["html", "attr", "js"]},
                priority=priority
            ))
            priority += 1

        if wants_rce or wants_all:
            tasks.append(Task(
                id=str(uuid.uuid4()),
                description="Test for command injection / RCE",
                tool_name="test_rce",
                parameters={"url": target},
                priority=priority
            ))
            priority += 1

        if wants_auth or wants_all:
            tasks.append(Task(
                id=str(uuid.uuid4()),
                description="Test authentication mechanisms",
                tool_name="test_auth",
                parameters={"url": target},
                priority=priority
            ))
            priority += 1

        if wants_chain:
            tasks.append(Task(
                id=str(uuid.uuid4()),
                description="Analyze and chain discovered vulnerabilities",
                tool_name="chain_analysis",
                parameters={},
                priority=100
            ))

        # Default: basic scan
        if not tasks:
            tasks = [
                Task(
                    id=str(uuid.uuid4()),
                    description="Perform comprehensive security scan",
                    tool_name="unified_scan",
                    parameters={"url": target, "depth": "balanced"},
                    priority=1
                )
            ]

        return PlanResult(
            success=True,
            tasks=tasks,
            reasoning=f"Fallback plan: {len(tasks)} tasks created based on request keywords"
        )

    async def replan(
        self,
        session,
        new_findings: List[Dict],
        context: Dict[str, Any]
    ) -> PlanResult:
        """
        Replan based on new findings during execution

        This allows the agent to adapt its strategy based on what it discovers.
        """
        if not new_findings:
            return PlanResult(success=True, tasks=[], reasoning="No new findings to replan for")

        # Build replan prompt
        findings_summary = "\n".join([
            f"- {f['type']}: {f.get('title', 'Unknown')} ({f.get('severity', 'unknown')})"
            for f in new_findings[:10]  # Limit to top 10
        ])

        prompt = f"""Based on new findings during the scan, suggest additional tasks:

TARGET: {context.get('target', 'Unknown')}

NEW FINDINGS:
{findings_summary}

CURRENT CONTEXT:
{self._format_context(context)}

What additional tests or exploitation attempts should we try based on these findings?
Consider:
- Chaining vulnerabilities (e.g., SQLi -> file read -> RCE)
- Escalation paths
- Related vulnerability types to check

Respond with a JSON array of additional tasks, or empty array if no additional tasks needed."""

        try:
            response = await self.llm.analyze(prompt, context="replanning")
            additional_tasks = self._parse_plan_response(response) if response else []

            return PlanResult(
                success=True,
                tasks=additional_tasks,
                reasoning=f"Replanned: {len(additional_tasks)} additional tasks based on findings"
            )
        except Exception:
            return PlanResult(success=True, tasks=[], reasoning="Replan failed, continuing with current plan")
