"""
Database models for All-Hack
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean,
    DateTime, ForeignKey, JSON, Index
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Scan(Base):
    """Scan history and results"""
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True)  # UUID
    target = Column(String(2048), nullable=False, index=True)
    mode = Column(String(20), default="black_box")  # black_box, grey_box
    depth = Column(String(20), default="balanced")  # quick, balanced, deep
    status = Column(String(20), default="pending", index=True)  # pending, running, completed, failed, stopped

    # Timing
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # Configuration
    config = Column(JSON, default=dict)  # Full scan config
    auth_config = Column(JSON, nullable=True)  # Auth details (encrypted in production)

    # Results summary
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Metadata
    technologies = Column(JSON, default=list)  # Detected tech stack
    endpoints_found = Column(Integer, default=0)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scan_target_status", "target", "status"),
        Index("idx_scan_started", "started_at"),
    )


class Finding(Base):
    """Individual vulnerability findings"""
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True)  # UUID
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    # Vulnerability details
    vuln_type = Column(String(50), nullable=False, index=True)  # sqli, xss, rce, etc.
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low, info
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)

    # Location
    url = Column(String(2048), nullable=False)
    parameter = Column(String(256), nullable=True)
    method = Column(String(10), default="GET")

    # Evidence
    payload_used = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    http_request = Column(Text, nullable=True)
    http_response = Column(Text, nullable=True)
    screenshot_path = Column(String(512), nullable=True)

    # Validation
    validated = Column(Boolean, default=False)
    confidence = Column(Float, default=0.0)  # 0.0 to 1.0
    false_positive = Column(Boolean, default=False)

    # Exploitation
    exploited = Column(Boolean, default=False)
    exploit_details = Column(JSON, nullable=True)

    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("idx_finding_type_severity", "vuln_type", "severity"),
        Index("idx_finding_scan_type", "scan_id", "vuln_type"),
    )


class AgentMemory(Base):
    """Agent learning and memory system"""
    __tablename__ = "agent_memory"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Pattern identification
    pattern_type = Column(String(50), nullable=False, index=True)  # payload, technique, chain, bypass
    category = Column(String(50), nullable=False, index=True)  # sqli, xss, waf_bypass, etc.

    # Context
    context = Column(JSON, nullable=False)  # When this pattern applies
    # Example: {"tech": "php", "waf": "cloudflare", "db": "mysql"}

    # The actual pattern/payload
    payload = Column(Text, nullable=True)
    technique = Column(Text, nullable=True)

    # Learning metrics
    times_used = Column(Integer, default=0)
    times_succeeded = Column(Integer, default=0)
    success_rate = Column(Float, default=0.0)

    # Metadata
    source = Column(String(50), default="discovered")  # discovered, imported, manual
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    last_succeeded = Column(DateTime, nullable=True)

    # Additional data
    metadata = Column(JSON, default=dict)

    __table_args__ = (
        Index("idx_memory_pattern_category", "pattern_type", "category"),
        Index("idx_memory_success_rate", "success_rate"),
    )

    def record_usage(self, succeeded: bool):
        """Record a usage of this pattern"""
        self.times_used += 1
        self.last_used = datetime.utcnow()
        if succeeded:
            self.times_succeeded += 1
            self.last_succeeded = datetime.utcnow()
        self.success_rate = self.times_succeeded / self.times_used if self.times_used > 0 else 0.0


class ExploitChain(Base):
    """Successful exploitation chains for learning"""
    __tablename__ = "exploit_chains"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Chain identification
    chain_type = Column(String(100), nullable=False, index=True)  # e.g., "sqli_to_rce", "ssrf_to_cloud"
    name = Column(String(256), nullable=True)

    # Chain definition
    steps = Column(JSON, nullable=False)  # List of steps with vuln types and techniques
    # Example: [{"vuln": "sqli", "technique": "union"}, {"vuln": "file_write", "technique": "into_outfile"}]

    # Target context
    target_pattern = Column(JSON, default=dict)  # What kind of target this works on
    # Example: {"tech": ["php", "mysql"], "features": ["file_upload"]}

    # Success tracking
    times_attempted = Column(Integer, default=0)
    times_succeeded = Column(Integer, default=0)
    success_rate = Column(Float, default=0.0)

    # Metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_chain_type", "chain_type"),
        Index("idx_chain_success", "success_rate"),
    )


class UserSettings(Base):
    """User preferences and settings"""
    __tablename__ = "user_settings"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Theme
    theme = Column(String(20), default="dark")  # light, dark, system

    # API Keys (should be encrypted in production)
    api_keys = Column(JSON, default=dict)
    # Example: {"groq": "gsk_...", "dashscope": "sk-..."}

    # Scan preferences
    default_depth = Column(String(20), default="balanced")
    default_mode = Column(String(20), default="black_box")
    auto_exploit = Column(Boolean, default=True)
    validate_findings = Column(Boolean, default=True)

    # Agent preferences
    agent_enabled = Column(Boolean, default=True)
    agent_autonomy = Column(String(20), default="guided")  # guided, autonomous, manual

    # UI preferences
    show_raw_requests = Column(Boolean, default=True)
    compact_mode = Column(Boolean, default=False)

    # Notifications
    notify_critical = Column(Boolean, default=True)
    notify_high = Column(Boolean, default=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AgentTask(Base):
    """Agent task queue and history"""
    __tablename__ = "agent_tasks"

    id = Column(String(36), primary_key=True)  # UUID
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True)

    # Task details
    task_type = Column(String(50), nullable=False)  # plan, execute, analyze, chain
    status = Column(String(20), default="pending")  # pending, running, completed, failed

    # Input/Output
    input_data = Column(JSON, nullable=False)
    output_data = Column(JSON, nullable=True)

    # Reasoning trace
    reasoning = Column(JSON, default=list)  # List of reasoning steps
    tools_called = Column(JSON, default=list)  # List of tools invoked

    # Timing
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Error handling
    error = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)

    __table_args__ = (
        Index("idx_task_status", "status"),
        Index("idx_task_scan", "scan_id"),
    )
