"""
Data models for pentest scans
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime

class ScanMode(str, Enum):
    BLACK_BOX = "black_box"  # No authentication, external perspective
    GREY_BOX = "grey_box"    # With credentials, partial knowledge

class ScanDepth(str, Enum):
    QUICK = "quick"          # Fast scan - 10 priority endpoints, ~5-15 min
    BALANCED = "balanced"    # Balanced scan - 50 endpoints, ~30-60 min (DEFAULT)
    DEEP = "deep"            # Deep scan - all endpoints, 2-10 hours

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityCategory(str, Enum):
    INJECTION = "injection"
    BROKEN_AUTH = "broken_authentication"
    SENSITIVE_DATA = "sensitive_data_exposure"
    XXE = "xml_external_entities"
    BROKEN_ACCESS = "broken_access_control"
    SECURITY_MISCONFIG = "security_misconfiguration"
    XSS = "cross_site_scripting"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    INSUFFICIENT_LOGGING = "insufficient_logging"
    SSRF = "server_side_request_forgery"
    IDOR = "insecure_direct_object_reference"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    OTHER = "other"

class ScanRequest(BaseModel):
    target_url: str = Field(..., description="Target URL to scan")
    mode: ScanMode = Field(default=ScanMode.BLACK_BOX, description="Scan mode")
    scan_depth: ScanDepth = Field(default=ScanDepth.BALANCED, description="Scan depth/speed")

    # Grey box options
    auth_token: Optional[str] = Field(None, description="Authentication token (Bearer)")
    cookies: Optional[Dict[str, str]] = Field(None, description="Session cookies")
    custom_headers: Optional[Dict[str, str]] = Field(None, description="Custom HTTP headers")
    auth_sequence: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of HTTP steps to reproduce complex authentication flows",
    )
    mfa_totp_secret: Optional[str] = Field(
        default=None,
        description="TOTP secret for MFA flows",
    )

    # Test users for access control testing (grey box)
    test_users: Optional[List[Dict[str, str]]] = Field(None, description="Test users with different privileges")

    # Scan options
    enable_active_tests: bool = Field(default=True, description="Enable active exploitation tests")
    enable_fuzzing: bool = Field(default=True, description="Enable endpoint fuzzing")
    enable_nuclei: bool = Field(default=True, description="Enable Nuclei template scanning")
    enable_sqlmap: bool = Field(default=True, description="Enable SQLMap for SQL injection")
    browser_crawling: bool = Field(default=True, description="Use headless browser to discover SPA routes")
    collect_api_schemas: bool = Field(default=True, description="Attempt to download OpenAPI/GraphQL schemas")
    enrich_osint: bool = Field(default=True, description="Collect local OSINT data (DNS, certs, secrets)")
    track_stability: bool = Field(default=True, description="Capture host stability metrics during the scan")

    # Advanced options
    rate_limit: int = Field(default=10, description="Requests per second")
    max_depth: int = Field(default=3, description="Maximum crawling depth")
    custom_wordlist: Optional[str] = Field(None, description="Path to custom wordlist")

class Vulnerability(BaseModel):
    id: str
    title: str
    description: str
    severity: SeverityLevel
    category: VulnerabilityCategory
    affected_url: str
    affected_parameter: Optional[str] = None
    proof_of_concept: Optional[str] = None
    payload: Optional[str] = None
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    references: List[str] = Field(default_factory=list)

class Misconfiguration(BaseModel):
    title: str
    description: str
    severity: SeverityLevel
    affected_component: str
    current_value: Optional[str] = None
    recommended_value: Optional[str] = None
    remediation: str

class EndpointInfo(BaseModel):
    url: str
    method: str
    status_code: int
    requires_auth: bool
    parameters: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)

class TechnologyInfo(BaseModel):
    name: str
    version: Optional[str] = None
    category: str  # framework, server, language, etc.
    confidence: float  # 0.0 to 1.0


class TimelineEvent(BaseModel):
    id: str
    timestamp: datetime
    phase: str
    message: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackChainStep(BaseModel):
    name: str
    severity: SeverityLevel
    description: str
    steps: List[str] = Field(default_factory=list)
    impacted_assets: List[str] = Field(default_factory=list)


class ScanArtifact(BaseModel):
    name: str
    type: str
    description: str
    content: str
    related_items: List[str] = Field(default_factory=list)


class PlaybookTarget(BaseModel):
    target_url: str
    mode: ScanMode = ScanMode.BLACK_BOX
    auth_token: Optional[str] = None
    custom_headers: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    notes: Optional[str] = None


class PlaybookRequest(BaseModel):
    name: str
    targets: List[PlaybookTarget]
    sequential: bool = True


class PlaybookRun(BaseModel):
    playbook_id: str
    name: str
    started_at: datetime
    targets: List[PlaybookTarget]
    scan_ids: List[str] = Field(default_factory=list)
    completed: bool = False
    status_overview: List[Dict[str, Any]] = Field(default_factory=list)
    sequential: bool = True


class StabilitySnapshot(BaseModel):
    label: str
    timestamp: datetime
    load_average: Dict[str, float]
    memory: Dict[str, float]

class ScanProgress(BaseModel):
    scan_id: str
    status: str  # queued, running, completed, failed
    current_phase: str
    progress_percentage: float
    start_time: datetime
    estimated_time_remaining: Optional[int] = None  # seconds

class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    mode: ScanMode
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str

    # Results
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    misconfigurations: List[Misconfiguration] = Field(default_factory=list)
    discovered_endpoints: List[EndpointInfo] = Field(default_factory=list)
    detected_technologies: List[TechnologyInfo] = Field(default_factory=list)
    dynamic_endpoints: List[EndpointInfo] = Field(default_factory=list)
    api_schemas: Dict[str, Any] = Field(default_factory=dict)
    osint_findings: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    attack_chains: List[AttackChainStep] = Field(default_factory=list)
    artifacts: List[ScanArtifact] = Field(default_factory=list)
    stability_metrics: List[StabilitySnapshot] = Field(default_factory=list)

    # Statistics
    total_requests: int = 0
    vulnerabilities_by_severity: Dict[str, int] = Field(default_factory=dict)

    # Metadata
    scan_duration: Optional[float] = None  # seconds
    error_message: Optional[str] = None
    browser_crawl_summary: Optional[str] = None
    playbook_runs: List[PlaybookRun] = Field(default_factory=list)
    scan_notes: Optional[str] = None
