"""
AI-Powered Payload Generator
Uses Claude to generate intelligent, context-aware payloads

Features:
- Context-aware payload generation
- Technology-specific payloads
- Learning from successful patterns
- Evasion technique suggestions
- Payload optimization
"""

import json
import logging
from typing import List, Dict, Any, Optional
from anthropic import AsyncAnthropic

logger = logging.getLogger(__name__)


class AIPayloadGenerator:
    """
    AI-powered payload generator using Claude

    Generates intelligent payloads based on:
    - Target technology stack
    - Previously successful patterns
    - Vulnerability context
    - Evasion requirements
    """

    def __init__(self, api_key: str, memory_system=None):
        """
        Initialize payload generator

        Args:
            api_key: Anthropic API key
            memory_system: AgentMemory instance for learning
        """
        self.client = AsyncAnthropic(api_key=api_key)
        self.memory = memory_system
        logger.info("🎯 AI Payload Generator initialized")

    async def generate_payloads(
        self,
        vulnerability_type: str,
        target_url: str,
        context: Dict[str, Any],
        count: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Generate intelligent payloads for a vulnerability type

        Args:
            vulnerability_type: Type of vulnerability (e.g., "sql_injection", "xss")
            target_url: Target URL for context
            context: Additional context (technologies, filters detected, etc.)
            count: Number of payloads to generate

        Returns:
            List of payload dictionaries with explanations
        """
        try:
            # Get successful patterns from memory
            successful_patterns = []
            if self.memory:
                successful_patterns = self.memory.get_successful_patterns(vulnerability_type)

            # Build prompt for Claude
            prompt = self._build_generation_prompt(
                vulnerability_type, target_url, context, successful_patterns, count
            )

            logger.info(f"🤖 Generating {count} AI payloads for {vulnerability_type}...")

            response = await self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=4000,
                temperature=0.8,  # Higher temperature for creativity
                messages=[{"role": "user", "content": prompt}]
            )

            # Parse response
            payloads = self._parse_payloads(response.content[0].text)

            logger.info(f"✅ Generated {len(payloads)} AI-powered payloads")

            return payloads

        except Exception as e:
            logger.error(f"Failed to generate AI payloads: {e}")
            return []

    def _build_generation_prompt(
        self,
        vuln_type: str,
        target_url: str,
        context: Dict[str, Any],
        successful_patterns: List[Dict[str, Any]],
        count: int
    ) -> str:
        """Build prompt for Claude to generate payloads"""

        technologies = context.get("technologies", [])
        filters_detected = context.get("filters_detected", [])
        waf_detected = context.get("waf_detected", False)
        encoding_hints = context.get("encoding_hints", [])

        prompt = f"""You are an expert penetration tester specializing in payload generation. Generate {count} intelligent, context-aware payloads for exploitation.

# Target Information
- **URL:** {target_url}
- **Vulnerability Type:** {vuln_type}
- **Technologies Detected:** {', '.join(technologies) if technologies else 'Unknown'}
- **WAF Detected:** {'Yes' if waf_detected else 'No'}
- **Filters Detected:** {', '.join(filters_detected) if filters_detected else 'None identified'}

# Context Clues
{json.dumps(context, indent=2)}
"""

        if successful_patterns:
            prompt += f"""
# Previously Successful Patterns (Learn from these!)
{json.dumps(successful_patterns[:5], indent=2)}

**Important:** Adapt these successful patterns to current context. Don't copy exactly, but use the techniques that worked.
"""

        prompt += f"""
---

# Your Task

Generate {count} **advanced, production-ready** payloads for {vuln_type} that:

1. **Are context-aware** - Adapted to detected technologies
2. **Bypass common filters** - Use encoding, obfuscation if WAF detected
3. **Have high success probability** - Based on context analysis
4. **Are creative** - Not just basic textbook payloads
5. **Include evasion techniques** - If filters/WAF detected

"""

        # Vulnerability-specific instructions
        vuln_specific = {
            "sql_injection": """
## SQL Injection Specifics:
- Include payloads for different databases (MySQL, PostgreSQL, MSSQL, Oracle)
- Use comment obfuscation (/**/, --, #)
- Try encoding variations (%27, %2527, 0x27)
- Include time-based and boolean-based blind techniques
- Consider WAF bypass techniques (case manipulation, inline comments)
""",
            "xss": """
## XSS Specifics:
- Test for reflected, stored, and DOM-based XSS
- Use different event handlers (onerror, onload, onfocus, etc.)
- Include filter bypass techniques (<svg>, <details>, <marquee>)
- Try encoding (HTML entities, Unicode, URL encoding)
- Include payloads for CSP bypass if detected
""",
            "command_injection": """
## Command Injection Specifics:
- Include OS-specific payloads (Linux, Windows)
- Use command chaining (;, &&, ||, |)
- Try encoding and obfuscation ($(), ``, ${IFS})
- Include time-based blind techniques (sleep, ping)
- Test for different shells (bash, sh, cmd, powershell)
""",
            "xxe": """
## XXE Specifics:
- File disclosure payloads (file:///etc/passwd, file:///c:/windows/win.ini)
- SSRF payloads (http://internal-server)
- Parameter entity attacks
- DOCTYPE variations
- OOB (Out-of-Band) exfiltration techniques
""",
            "nosql_injection": """
## NoSQL Injection Specifics:
- MongoDB operator injection ($ne, $gt, $where, $regex)
- JavaScript injection in $where clauses
- Authentication bypass techniques
- Array-based injections
- Timing-based blind NoSQL injection
""",
            "jwt": """
## JWT Attack Specifics:
- Algorithm confusion (none, RS256→HS256)
- Weak secret brute-force attempts
- JKU/X5U header injection
- Kid parameter manipulation
- Claims manipulation (role, admin, exp)
""",
        }

        prompt += vuln_specific.get(vuln_type, "")

        prompt += """
---

## Output Format

Respond with ONLY valid JSON array in this format:

```json
[
    {
        "payload": "actual payload string",
        "description": "What this payload does and why it works",
        "technique": "evasion technique used (if any)",
        "success_indicators": ["what to look for in response", "status codes", "error messages"],
        "priority": "critical|high|medium|low",
        "encoding_used": "none|url|double-url|unicode|hex|base64",
        "target_tech": "specific technology this targets"
    }
]
```

**Rules:**
- Return ONLY the JSON array, no explanations before or after
- Payloads must be practical and ready to use
- Include variety: different techniques, encodings, approaches
- Prioritize payloads likely to succeed given the context
- Be creative but realistic
"""

        return prompt

    def _parse_payloads(self, response_text: str) -> List[Dict[str, Any]]:
        """Parse Claude's response into payload list"""
        try:
            # Extract JSON array from response
            import re

            # Find JSON array
            json_match = re.search(r'\[.*\]', response_text, re.DOTALL)

            if json_match:
                payloads = json.loads(json_match.group())
                return payloads

            # Fallback: try to parse entire response
            return json.loads(response_text)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI payloads: {e}")
            logger.debug(f"Raw response: {response_text[:500]}")
            return []

    async def optimize_payload(
        self,
        original_payload: str,
        target: str,
        constraints: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Optimize a payload for specific constraints

        Args:
            original_payload: Original payload
            target: Target URL/endpoint
            constraints: Constraints (filters, WAF, encoding requirements)

        Returns:
            Optimized payload with explanation
        """
        try:
            prompt = f"""You are a penetration testing expert. Optimize this payload to bypass constraints.

# Original Payload
```
{original_payload}
```

# Target
{target}

# Constraints to Bypass
{json.dumps(constraints, indent=2)}

# Your Task
Create an optimized version of this payload that:
1. Maintains the same exploitation goal
2. Bypasses the detected constraints
3. Uses appropriate encoding/obfuscation
4. Has higher success probability

Respond with JSON:
{{
    "optimized_payload": "the optimized payload",
    "changes_made": ["list of optimizations applied"],
    "bypass_techniques": ["techniques used to bypass constraints"],
    "explanation": "why this optimized version should work better"
}}
"""

            response = await self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=2000,
                temperature=0.7,
                messages=[{"role": "user", "content": prompt}]
            )

            # Parse response
            import re
            json_match = re.search(r'\{.*\}', response.content[0].text, re.DOTALL)

            if json_match:
                return json.loads(json_match.group())

            return {"optimized_payload": original_payload, "changes_made": [], "explanation": "Failed to optimize"}

        except Exception as e:
            logger.error(f"Failed to optimize payload: {e}")
            return {"optimized_payload": original_payload, "changes_made": [], "explanation": f"Error: {e}"}

    async def generate_evasion_variants(
        self,
        base_payload: str,
        evasion_types: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Generate evasion variants of a base payload

        Args:
            base_payload: Base payload to create variants from
            evasion_types: Types of evasion (e.g., ["encoding", "obfuscation", "case_manipulation"])

        Returns:
            List of evasion variants
        """
        try:
            prompt = f"""Generate evasion variants for this payload using specified techniques.

# Base Payload
```
{base_payload}
```

# Evasion Techniques to Apply
{', '.join(evasion_types)}

Create 3-5 variants using different combinations of:
- URL encoding (single, double)
- Unicode encoding
- HTML entity encoding
- Case manipulation
- Comment insertion
- Whitespace manipulation
- Alternative syntax

Respond with JSON array:
[
    {{
        "variant": "the evasion variant",
        "techniques_used": ["list of evasion techniques"],
        "effectiveness": "high|medium|low"
    }}
]
"""

            response = await self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=3000,
                temperature=0.8,
                messages=[{"role": "user", "content": prompt}]
            )

            # Parse response
            import re
            json_match = re.search(r'\[.*\]', response.content[0].text, re.DOTALL)

            if json_match:
                return json.loads(json_match.group())

            return []

        except Exception as e:
            logger.error(f"Failed to generate evasion variants: {e}")
            return []

    async def suggest_exploitation_chain(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_goal: str
    ) -> Dict[str, Any]:
        """
        Suggest how to chain multiple vulnerabilities for maximum impact

        Args:
            vulnerabilities: List of discovered vulnerabilities
            target_goal: Goal (e.g., "remote code execution", "data exfiltration")

        Returns:
            Exploitation chain suggestion
        """
        try:
            prompt = f"""You are a penetration testing expert. Analyze these vulnerabilities and suggest an exploitation chain.

# Discovered Vulnerabilities
{json.dumps(vulnerabilities, indent=2)}

# Target Goal
{target_goal}

# Your Task
Analyze how these vulnerabilities can be chained together to achieve the target goal. Be creative and think like an attacker.

Consider:
- Which vulnerabilities to exploit first (foothold)
- How to chain them (e.g., XSS + CSRF, SQLi + File Upload)
- What intermediate steps are needed
- What the final impact would be

Respond with JSON:
{{
    "chain": [
        {{
            "step": 1,
            "vulnerability": "vulnerability ID or type",
            "action": "what to do in this step",
            "expected_result": "what this achieves"
        }}
    ],
    "final_impact": "description of final outcome",
    "prerequisites": ["what's needed before starting"],
    "success_probability": "high|medium|low",
    "alternative_chains": ["other possible exploitation paths"]
}}
"""

            response = await self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=3000,
                temperature=0.7,
                messages=[{"role": "user", "content": prompt}]
            )

            # Parse response
            import re
            json_match = re.search(r'\{.*\}', response.content[0].text, re.DOTALL)

            if json_match:
                return json.loads(json_match.group())

            return {"chain": [], "final_impact": "Unable to generate chain"}

        except Exception as e:
            logger.error(f"Failed to suggest exploitation chain: {e}")
            return {"chain": [], "final_impact": f"Error: {e}"}
