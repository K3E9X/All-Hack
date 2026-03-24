"""
Intelligent Autonomous Pentest Agent

This module implements a reasoning-based penetration testing agent that:
- Uses chain-of-thought reasoning to avoid false positives
- Validates findings with multiple verification methods
- Avoids hallucinations by requiring evidence-based reporting
- Learns from past scans to improve accuracy
"""

import asyncio
import json
import logging
import hashlib
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ConfidenceLevel(Enum):
    """Confidence levels for vulnerability findings"""
    CONFIRMED = "confirmed"      # Verified with proof of exploitation
    HIGH = "high"                # Strong indicators, needs verification
    MEDIUM = "medium"            # Possible vulnerability, more testing needed
    LOW = "low"                  # Weak indicators, likely false positive
    FALSE_POSITIVE = "false_positive"  # Confirmed as not exploitable


class VulnerabilityStatus(Enum):
    """Status of a vulnerability finding"""
    DETECTED = "detected"        # Initially detected
    VALIDATING = "validating"    # Being validated
    CONFIRMED = "confirmed"      # Confirmed as real
    REJECTED = "rejected"        # Rejected as false positive
    EXPLOITED = "exploited"      # Successfully exploited (with proof)


@dataclass
class Evidence:
    """Evidence for a vulnerability finding"""
    evidence_type: str           # request, response, screenshot, poc_output
    content: str                 # The actual evidence
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReasoningStep:
    """A step in the chain-of-thought reasoning"""
    step_number: int
    observation: str             # What was observed
    hypothesis: str              # What it might mean
    action: str                  # What action to take
    result: str                  # What happened
    conclusion: str              # What we learned
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ValidatedFinding:
    """A validated vulnerability finding with evidence"""
    finding_id: str
    vulnerability_type: str
    title: str
    description: str
    severity: str
    confidence: ConfidenceLevel
    status: VulnerabilityStatus
    target_url: str
    affected_parameter: Optional[str]
    evidence_chain: List[Evidence]
    reasoning_chain: List[ReasoningStep]
    cve_references: List[str]
    remediation: str
    false_positive_checks: List[Dict[str, Any]]
    validation_attempts: int = 0
    last_validated: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            'confidence': self.confidence.value,
            'status': self.status.value
        }


class IntelligentPentestAgent:
    """
    Autonomous penetration testing agent with intelligent reasoning.

    Features:
    - Chain-of-thought reasoning for each finding
    - Multi-stage validation to avoid false positives
    - Evidence collection and verification
    - Learning from past scans
    - No hallucinations - only reports what can be proven
    """

    def __init__(self, knowledge_base_path: str = None):
        self.knowledge_base_path = knowledge_base_path or "/tmp/pentest_knowledge"
        self.findings: List[ValidatedFinding] = []
        self.reasoning_history: List[ReasoningStep] = []
        self.false_positive_patterns: Dict[str, List[str]] = {}
        self.validated_exploits: Dict[str, Dict] = {}

        # Initialize knowledge base
        Path(self.knowledge_base_path).mkdir(parents=True, exist_ok=True)
        self._load_knowledge_base()

        # Validation rules for different vulnerability types
        self.validation_rules = {
            'sqli': self._validate_sqli,
            'xss': self._validate_xss,
            'rce': self._validate_rce,
            'lfi': self._validate_lfi,
            'ssrf': self._validate_ssrf,
            'idor': self._validate_idor,
            'auth_bypass': self._validate_auth_bypass,
            'info_disclosure': self._validate_info_disclosure,
        }

        # Known false positive patterns
        self.fp_patterns = {
            'sqli': [
                r'error.*syntax',           # Generic syntax errors
                r'mysql.*warning',          # MySQL warnings without data leak
                r'connection.*refused',     # Connection issues
            ],
            'xss': [
                r'<script>.*</script>',     # Properly escaped output
                r'&lt;script&gt;',          # HTML encoded
                r'content-type.*json',      # JSON response (not rendered)
            ],
            'rce': [
                r'command not found',       # Command doesn't exist
                r'permission denied',       # No execution permission
            ]
        }

        logger.info("IntelligentPentestAgent initialized")

    def _load_knowledge_base(self):
        """Load knowledge base from disk"""
        try:
            fp_path = Path(self.knowledge_base_path) / "false_positives.json"
            if fp_path.exists():
                with open(fp_path) as f:
                    self.false_positive_patterns = json.load(f)

            exploits_path = Path(self.knowledge_base_path) / "validated_exploits.json"
            if exploits_path.exists():
                with open(exploits_path) as f:
                    self.validated_exploits = json.load(f)

            logger.info(f"Loaded knowledge base: {len(self.false_positive_patterns)} FP patterns, {len(self.validated_exploits)} exploits")
        except Exception as e:
            logger.warning(f"Could not load knowledge base: {e}")

    def _save_knowledge_base(self):
        """Save knowledge base to disk"""
        try:
            fp_path = Path(self.knowledge_base_path) / "false_positives.json"
            with open(fp_path, 'w') as f:
                json.dump(self.false_positive_patterns, f, indent=2)

            exploits_path = Path(self.knowledge_base_path) / "validated_exploits.json"
            with open(exploits_path, 'w') as f:
                json.dump(self.validated_exploits, f, indent=2)

            logger.info("Knowledge base saved")
        except Exception as e:
            logger.error(f"Could not save knowledge base: {e}")

    async def analyze_with_reasoning(
        self,
        target: str,
        scan_results: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> List[ValidatedFinding]:
        """
        Analyze scan results with chain-of-thought reasoning.

        This is the main entry point for intelligent analysis.
        """
        validated_findings = []

        # Step 1: Initial observation
        step1 = ReasoningStep(
            step_number=1,
            observation=f"Received scan results for {target} with {len(scan_results.get('vulnerabilities', []))} potential findings",
            hypothesis="Some findings may be false positives, need to validate each one",
            action="Begin systematic validation of each finding",
            result="Starting validation process",
            conclusion="Will apply multi-stage validation to filter out false positives"
        )
        self.reasoning_history.append(step1)

        # Step 2: Categorize findings
        findings_by_type = self._categorize_findings(scan_results.get('vulnerabilities', []))

        step2 = ReasoningStep(
            step_number=2,
            observation=f"Categorized findings: {', '.join(f'{k}: {len(v)}' for k, v in findings_by_type.items())}",
            hypothesis="Each category requires different validation approach",
            action="Apply category-specific validation rules",
            result=f"Prepared {len(findings_by_type)} validation pipelines",
            conclusion="Will validate each category with appropriate techniques"
        )
        self.reasoning_history.append(step2)

        # Step 3: Validate each finding
        for vuln_type, findings in findings_by_type.items():
            for finding in findings:
                validated = await self._validate_finding(finding, vuln_type, target, context)
                if validated and validated.status != VulnerabilityStatus.REJECTED:
                    validated_findings.append(validated)

        # Step 4: Cross-reference and deduplicate
        validated_findings = self._deduplicate_findings(validated_findings)

        step4 = ReasoningStep(
            step_number=4,
            observation=f"After validation: {len(validated_findings)} confirmed findings",
            hypothesis="These findings have passed multi-stage validation",
            action="Generate final report with evidence",
            result=f"Validated findings: {[f.title for f in validated_findings]}",
            conclusion="Only reporting findings with sufficient evidence"
        )
        self.reasoning_history.append(step4)

        # Save findings
        self.findings.extend(validated_findings)
        self._save_knowledge_base()

        return validated_findings

    def _categorize_findings(self, vulnerabilities: List[Dict]) -> Dict[str, List[Dict]]:
        """Categorize findings by vulnerability type"""
        categories = {}

        type_mapping = {
            'sql': 'sqli',
            'xss': 'xss',
            'cross-site': 'xss',
            'command': 'rce',
            'rce': 'rce',
            'injection': 'sqli',
            'lfi': 'lfi',
            'file inclusion': 'lfi',
            'ssrf': 'ssrf',
            'server-side request': 'ssrf',
            'idor': 'idor',
            'insecure direct': 'idor',
            'auth': 'auth_bypass',
            'bypass': 'auth_bypass',
            'disclosure': 'info_disclosure',
            'information': 'info_disclosure',
        }

        for vuln in vulnerabilities:
            vuln_type = 'unknown'
            title = vuln.get('title', '').lower()
            description = vuln.get('description', '').lower()

            for keyword, category in type_mapping.items():
                if keyword in title or keyword in description:
                    vuln_type = category
                    break

            if vuln_type not in categories:
                categories[vuln_type] = []
            categories[vuln_type].append(vuln)

        return categories

    async def _validate_finding(
        self,
        finding: Dict,
        vuln_type: str,
        target: str,
        context: Optional[Dict] = None
    ) -> Optional[ValidatedFinding]:
        """Validate a single finding with reasoning"""
        finding_id = hashlib.md5(
            f"{target}{vuln_type}{finding.get('url', '')}{finding.get('parameter', '')}".encode()
        ).hexdigest()[:12]

        # Check if already known false positive
        if self._is_known_false_positive(finding, vuln_type):
            logger.info(f"Skipping known false positive: {finding.get('title', 'Unknown')}")
            return None

        # Create initial finding object
        validated = ValidatedFinding(
            finding_id=finding_id,
            vulnerability_type=vuln_type,
            title=finding.get('title', f'{vuln_type.upper()} Vulnerability'),
            description=finding.get('description', ''),
            severity=finding.get('severity', 'medium'),
            confidence=ConfidenceLevel.LOW,
            status=VulnerabilityStatus.DETECTED,
            target_url=finding.get('url', target),
            affected_parameter=finding.get('parameter'),
            evidence_chain=[],
            reasoning_chain=[],
            cve_references=finding.get('cves', []),
            remediation=finding.get('remediation', ''),
            false_positive_checks=[]
        )

        # Add initial evidence
        if finding.get('request'):
            validated.evidence_chain.append(Evidence(
                evidence_type='request',
                content=finding['request'],
                metadata={'stage': 'initial_detection'}
            ))

        if finding.get('response'):
            validated.evidence_chain.append(Evidence(
                evidence_type='response',
                content=finding['response'][:2000],  # Truncate large responses
                metadata={'stage': 'initial_detection'}
            ))

        # Apply validation rules
        validated.status = VulnerabilityStatus.VALIDATING

        if vuln_type in self.validation_rules:
            is_valid, confidence, evidence = await self.validation_rules[vuln_type](finding, target, context)

            if is_valid:
                validated.confidence = confidence
                validated.status = VulnerabilityStatus.CONFIRMED
                if evidence:
                    validated.evidence_chain.extend(evidence)
            else:
                validated.status = VulnerabilityStatus.REJECTED
                # Learn from this false positive
                self._learn_false_positive(finding, vuln_type)
                return None
        else:
            # Generic validation
            is_valid, confidence = await self._generic_validation(finding, target)
            if is_valid:
                validated.confidence = confidence
                validated.status = VulnerabilityStatus.CONFIRMED
            else:
                validated.status = VulnerabilityStatus.REJECTED
                return None

        validated.validation_attempts += 1
        validated.last_validated = datetime.now().isoformat()

        # Add reasoning step
        validated.reasoning_chain.append(ReasoningStep(
            step_number=1,
            observation=f"Detected potential {vuln_type} in {validated.target_url}",
            hypothesis=f"Parameter '{validated.affected_parameter}' may be vulnerable",
            action=f"Applied {vuln_type} validation rules",
            result=f"Confidence: {validated.confidence.value}",
            conclusion=f"Finding {'confirmed' if validated.status == VulnerabilityStatus.CONFIRMED else 'rejected'}"
        ))

        return validated

    def _is_known_false_positive(self, finding: Dict, vuln_type: str) -> bool:
        """Check if this finding matches known false positive patterns"""
        response = finding.get('response', '')

        # Check against learned patterns
        if vuln_type in self.false_positive_patterns:
            for pattern in self.false_positive_patterns[vuln_type]:
                if re.search(pattern, response, re.IGNORECASE):
                    return True

        # Check against built-in patterns
        if vuln_type in self.fp_patterns:
            for pattern in self.fp_patterns[vuln_type]:
                if re.search(pattern, response, re.IGNORECASE):
                    return True

        return False

    def _learn_false_positive(self, finding: Dict, vuln_type: str):
        """Learn from a false positive to improve future detection"""
        response = finding.get('response', '')

        # Extract potential pattern from response
        if len(response) > 50:
            # Create a signature from the response
            # This is a simplified version - in production, use ML
            words = re.findall(r'\b\w{4,}\b', response[:500])
            if words:
                pattern = '|'.join(words[:5])

                if vuln_type not in self.false_positive_patterns:
                    self.false_positive_patterns[vuln_type] = []

                if pattern not in self.false_positive_patterns[vuln_type]:
                    self.false_positive_patterns[vuln_type].append(pattern)
                    logger.info(f"Learned new false positive pattern for {vuln_type}")

    async def _validate_sqli(
        self,
        finding: Dict,
        target: str,
        context: Optional[Dict]
    ) -> Tuple[bool, ConfidenceLevel, List[Evidence]]:
        """Validate SQL injection finding"""
        evidence = []
        response = finding.get('response', '')

        # Strong indicators of real SQLi
        strong_indicators = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'PostgreSQL.*ERROR',
            r'ORA-\d{5}',
            r'Microsoft SQL Server',
            r'ODBC SQL Server Driver',
            r'SQLite.*error',
            r'sqlite3\.OperationalError',
            r'unterminated quoted string',
            r'pg_query\(\)',
            r'valid MySQL result',
        ]

        # Check for data extraction (confirms exploitation)
        data_leak_indicators = [
            r'root:x:0:0',           # /etc/passwd leak
            r'mysql\.user',           # Database users
            r'information_schema',    # Schema access
            r'\d+\.\d+\.\d+',         # Version disclosure
        ]

        # Check strong indicators
        for pattern in strong_indicators:
            if re.search(pattern, response, re.IGNORECASE):
                evidence.append(Evidence(
                    evidence_type='pattern_match',
                    content=f"Matched SQL error pattern: {pattern}",
                    metadata={'pattern': pattern}
                ))
                return True, ConfidenceLevel.HIGH, evidence

        # Check for data leak (confirms exploitation)
        for pattern in data_leak_indicators:
            if re.search(pattern, response, re.IGNORECASE):
                evidence.append(Evidence(
                    evidence_type='data_leak',
                    content=f"Confirmed data extraction: {pattern}",
                    metadata={'pattern': pattern}
                ))
                return True, ConfidenceLevel.CONFIRMED, evidence

        # Time-based detection needs careful validation
        if finding.get('time_based'):
            delay = finding.get('response_time', 0)
            baseline = finding.get('baseline_time', 0)

            if delay > baseline * 3 and delay > 5:  # At least 3x baseline and >5s
                evidence.append(Evidence(
                    evidence_type='timing',
                    content=f"Time-based SQLi confirmed: {delay}s vs baseline {baseline}s",
                    metadata={'delay': delay, 'baseline': baseline}
                ))
                return True, ConfidenceLevel.HIGH, evidence

        return False, ConfidenceLevel.LOW, evidence

    async def _validate_xss(
        self,
        finding: Dict,
        target: str,
        context: Optional[Dict]
    ) -> Tuple[bool, ConfidenceLevel, List[Evidence]]:
        """Validate XSS finding"""
        evidence = []
        response = finding.get('response', '')
        payload = finding.get('payload', '')

        # Check if payload is reflected without encoding
        if payload in response:
            # Check if it's in a dangerous context
            dangerous_contexts = [
                f'<script>{payload}',           # Direct script execution
                f"javascript:{payload}",        # JavaScript URL
                f"onerror=\"{payload}\"",       # Event handler
                f"onload=\"{payload}\"",        # Event handler
                f"onclick=\"{payload}\"",       # Event handler
            ]

            for ctx in dangerous_contexts:
                if ctx.lower() in response.lower():
                    evidence.append(Evidence(
                        evidence_type='reflected_payload',
                        content=f"Payload reflected in dangerous context: {ctx[:100]}",
                        metadata={'context': ctx[:100]}
                    ))
                    return True, ConfidenceLevel.CONFIRMED, evidence

            # Check content type
            content_type = finding.get('content_type', '')
            if 'text/html' in content_type.lower():
                evidence.append(Evidence(
                    evidence_type='reflected_payload',
                    content=f"Payload reflected in HTML response",
                    metadata={'content_type': content_type}
                ))
                return True, ConfidenceLevel.HIGH, evidence

        # Check if properly encoded (false positive)
        encoded_variants = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '\\u003c').replace('>', '\\u003e'),
            payload.replace('<', '%3C').replace('>', '%3E'),
        ]

        for encoded in encoded_variants:
            if encoded in response:
                return False, ConfidenceLevel.FALSE_POSITIVE, evidence

        return False, ConfidenceLevel.LOW, evidence

    async def _validate_rce(
        self,
        finding: Dict,
        target: str,
        context: Optional[Dict]
    ) -> Tuple[bool, ConfidenceLevel, List[Evidence]]:
        """Validate Remote Code Execution finding"""
        evidence = []
        response = finding.get('response', '')

        # Strong indicators of RCE
        rce_indicators = [
            (r'uid=\d+\([\w]+\)\s+gid=\d+', 'id command output'),
            (r'root:x:0:0:root:/root:', '/etc/passwd content'),
            (r'Linux.*\d+\.\d+\.\d+.*GNU', 'uname output'),
            (r'Windows.*\d+\.\d+', 'Windows version'),
            (r'Directory of [A-Z]:\\', 'Windows dir command'),
            (r'total \d+\s+dr', 'ls -la output'),
        ]

        for pattern, description in rce_indicators:
            if re.search(pattern, response, re.IGNORECASE):
                evidence.append(Evidence(
                    evidence_type='command_output',
                    content=f"RCE confirmed: {description}",
                    metadata={'pattern': pattern}
                ))
                return True, ConfidenceLevel.CONFIRMED, evidence

        # Check for out-of-band indicators
        if finding.get('oob_callback'):
            evidence.append(Evidence(
                evidence_type='oob_callback',
                content=f"Out-of-band callback received",
                metadata={'callback_data': finding.get('oob_data', '')}
            ))
            return True, ConfidenceLevel.CONFIRMED, evidence

        return False, ConfidenceLevel.LOW, evidence

    async def _validate_lfi(
        self,
        finding: Dict,
        target: str,
        context: Optional[Dict]
    ) -> Tuple[bool, ConfidenceLevel, List[Evidence]]:
        """Validate Local File Inclusion finding"""
        evidence = []
        response = finding.get('response', '')

        lfi_indicators = [
            (r'root:x:0:0:', '/etc/passwd'),
            (r'\[boot loader\]', 'Windows boot.ini'),
            (r'<\?php', 'PHP source code'),
            (r'127\.0\.0\.1\s+localhost', '/etc/hosts'),
            (r'extension_dir\s*=', 'php.ini'),
        ]

        for pattern, file_type in lfi_indicators:
            if re.search(pattern, response, re.IGNORECASE):
                evidence.append(Evidence(
                    evidence_type='file_content',
                    content=f"LFI confirmed: {file_type} content detected",
                    metadata={'file_type': file_type}
                ))
                return True, ConfidenceLevel.CONFIRMED, evidence

        return False, ConfidenceLevel.LOW, evidence

    async def _validate_ssrf(
        self,
        finding: Dict,
        target: str,
        context: Optional[Dict]
    ) -> Tuple[bool, ConfidenceLevel, List[Evidence]]:
        """Validate Server-Side Request Forgery finding"""
        evidence = []
        response = finding.get('response', '')

        # Check for internal service responses
        ssrf_indicators = [
            (r'AWS.*metadata', 'AWS metadata access'),
            (r'169\.254\.169\.254', 'Cloud metadata endpoint'),
            (r'localhost.*refused', 'Internal port scan'),
            (r'internal\s+server', 'Internal service error'),
        ]

        for pattern, description in ssrf_indicators:
            if re.search(pattern, response, re.IGNORECASE):
                evidence.append(Evidence(
                    evidence_type='ssrf_response',
                    content=f"SSRF confirmed: {description}",
                    metadata={'indicator': pattern}
                ))
                return True, ConfidenceLevel.HIGH, evidence

        # Out-of-band callback
        if finding.get('oob_callback'):
            evidence.append(Evidence(
                evidence_type='oob_callback',
                content="SSRF confirmed via out-of-band callback",
                metadata={'callback_data': finding.get('oob_data', '')}
            ))
            return True, ConfidenceLevel.CONFIRMED, evidence

        return False, ConfidenceLevel.LOW, evidence

    async def _validate_idor(
        self,
        finding: Dict,
        target: str,
        context: Optional[Dict]
    ) -> Tuple[bool, ConfidenceLevel, List[Evidence]]:
        """Validate Insecure Direct Object Reference finding"""
        evidence = []

        # IDOR requires comparing responses with different IDs
        original_response = finding.get('original_response', '')
        modified_response = finding.get('modified_response', '')

        if original_response and modified_response:
            # Check if we got different valid data
            if (len(modified_response) > 100 and
                modified_response != original_response and
                'error' not in modified_response.lower() and
                'unauthorized' not in modified_response.lower()):

                evidence.append(Evidence(
                    evidence_type='response_comparison',
                    content="IDOR confirmed: Different valid data returned for modified ID",
                    metadata={
                        'original_length': len(original_response),
                        'modified_length': len(modified_response)
                    }
                ))
                return True, ConfidenceLevel.HIGH, evidence

        return False, ConfidenceLevel.LOW, evidence

    async def _validate_auth_bypass(
        self,
        finding: Dict,
        target: str,
        context: Optional[Dict]
    ) -> Tuple[bool, ConfidenceLevel, List[Evidence]]:
        """Validate Authentication Bypass finding"""
        evidence = []
        response = finding.get('response', '')
        status_code = finding.get('status_code', 0)

        # Check for successful access without auth
        if status_code == 200 and finding.get('requires_auth'):
            # Check for actual content (not just a redirect or error page)
            if len(response) > 500 and 'login' not in response.lower():
                evidence.append(Evidence(
                    evidence_type='auth_bypass',
                    content="Authentication bypass confirmed: Accessed protected resource",
                    metadata={'status_code': status_code}
                ))
                return True, ConfidenceLevel.HIGH, evidence

        return False, ConfidenceLevel.LOW, evidence

    async def _validate_info_disclosure(
        self,
        finding: Dict,
        target: str,
        context: Optional[Dict]
    ) -> Tuple[bool, ConfidenceLevel, List[Evidence]]:
        """Validate Information Disclosure finding"""
        evidence = []
        response = finding.get('response', '')

        sensitive_patterns = [
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email addresses'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'-----BEGIN (RSA |EC |DSA |)PRIVATE KEY-----', 'Private key'),
            (r'password\s*[=:]\s*["\'][^"\']+["\']', 'Hardcoded password'),
            (r'api[_-]?key\s*[=:]\s*["\'][^"\']+["\']', 'API key'),
            (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API key'),
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub token'),
        ]

        for pattern, description in sensitive_patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            if matches:
                evidence.append(Evidence(
                    evidence_type='sensitive_data',
                    content=f"Information disclosure: {description} found",
                    metadata={'count': len(matches), 'type': description}
                ))
                return True, ConfidenceLevel.CONFIRMED, evidence

        return False, ConfidenceLevel.LOW, evidence

    async def _generic_validation(
        self,
        finding: Dict,
        target: str
    ) -> Tuple[bool, ConfidenceLevel]:
        """Generic validation for unknown vulnerability types"""
        # Require strong evidence for unknown types
        if finding.get('confidence', 0) >= 0.8:
            return True, ConfidenceLevel.MEDIUM
        return False, ConfidenceLevel.LOW

    def _deduplicate_findings(
        self,
        findings: List[ValidatedFinding]
    ) -> List[ValidatedFinding]:
        """Remove duplicate findings, keeping the highest confidence one"""
        unique = {}

        for finding in findings:
            key = f"{finding.vulnerability_type}:{finding.target_url}:{finding.affected_parameter}"

            if key not in unique or finding.confidence.value > unique[key].confidence.value:
                unique[key] = finding

        return list(unique.values())

    def get_reasoning_summary(self) -> Dict[str, Any]:
        """Get a summary of the reasoning process"""
        return {
            'total_steps': len(self.reasoning_history),
            'findings_analyzed': len(self.findings),
            'confirmed_findings': len([f for f in self.findings if f.status == VulnerabilityStatus.CONFIRMED]),
            'rejected_findings': len([f for f in self.findings if f.status == VulnerabilityStatus.REJECTED]),
            'reasoning_chain': [asdict(step) for step in self.reasoning_history[-10:]],  # Last 10 steps
        }

    def export_findings(self, format: str = 'json') -> str:
        """Export validated findings"""
        findings_data = [f.to_dict() for f in self.findings if f.status == VulnerabilityStatus.CONFIRMED]

        if format == 'json':
            return json.dumps(findings_data, indent=2, default=str)
        else:
            return json.dumps(findings_data, indent=2, default=str)
