"""
Data models for pentest scans
"""
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime

class ScanMode(str, Enum):
    BLACK_BOX = "black_box"  # No authentication, external perspective
    GREY_BOX = "grey_box"    # With credentials, partial knowledge

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

    # Grey box options
    auth_token: Optional[str] = Field(None, description="Authentication token (Bearer)")
    cookies: Optional[Dict[str, str]] = Field(None, description="Session cookies")
    custom_headers: Optional[Dict[str, str]] = Field(None, description="Custom HTTP headers")

    # Test users for access control testing (grey box)
    test_users: Optional[List[Dict[str, str]]] = Field(None, description="Test users with different privileges")

    # Scan options
    enable_active_tests: bool = Field(default=True, description="Enable active exploitation tests")
    enable_fuzzing: bool = Field(default=True, description="Enable endpoint fuzzing")
    enable_nuclei: bool = Field(default=True, description="Enable Nuclei template scanning")
    enable_sqlmap: bool = Field(default=True, description="Enable SQLMap for SQL injection")

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
    references: List[str] = []

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
    parameters: List[str] = []
    headers: Dict[str, str] = {}

class TechnologyInfo(BaseModel):
    name: str
    version: Optional[str] = None
    category: str  # framework, server, language, etc.
    confidence: float  # 0.0 to 1.0

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
    vulnerabilities: List[Vulnerability] = []
    misconfigurations: List[Misconfiguration] = []
    discovered_endpoints: List[EndpointInfo] = []
    detected_technologies: List[TechnologyInfo] = []

    # Statistics
    total_requests: int = 0
    vulnerabilities_by_severity: Dict[str, int] = {}

    # Metadata
    scan_duration: Optional[float] = None  # seconds
    error_message: Optional[str] = None
