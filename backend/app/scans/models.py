"""Dataclasses shared by wrappers, runner, storage and API."""
from __future__ import annotations

import enum
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Finding:
    """Normalized finding produced by any wrapper.

    `severity` is free-form for now: info/low/medium/high/critical when the
    tool gives us one, else "info". `metadata` is tool-specific and opaque
    to the rest of the app (UI just renders it as key/value).
    """
    severity: str = "info"
    title: str = ""
    description: str = ""
    target: str = ""
    evidence: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Job:
    id: str
    tool: str
    target: str
    args: List[str]
    status: JobStatus
    created_at: float
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    exit_code: Optional[int] = None
    stdout: bytes = b""
    stderr: bytes = b""
    findings: List[Finding] = field(default_factory=list)
    flow_id: Optional[str] = None
    error: Optional[str] = None
    engagement_id: Optional[str] = None
    # Set when the autonomous orchestrator launched the job (catalog item id).
    catalog_item_id: Optional[str] = None

    def to_public(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "target": self.target,
            "args": self.args,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "duration_ms": (
                int((self.finished_at - self.started_at) * 1000)
                if self.started_at and self.finished_at
                else None
            ),
            "findings_count": len(self.findings),
            "flow_id": self.flow_id,
            "engagement_id": self.engagement_id,
            "catalog_item_id": self.catalog_item_id,
            "error": self.error,
        }

    def to_detail(self, tail_bytes: int = 64 * 1024) -> Dict[str, Any]:
        base = self.to_public()
        base["findings"] = [f.to_dict() for f in self.findings]
        base["stdout_tail"] = _tail_text(self.stdout, tail_bytes)
        base["stderr_tail"] = _tail_text(self.stderr, tail_bytes)
        return base


def _tail_text(data: bytes, n: int) -> str:
    if not data:
        return ""
    if len(data) <= n:
        return data.decode("utf-8", errors="replace")
    return "... (truncated) ...\n" + data[-n:].decode("utf-8", errors="replace")


def findings_to_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], ensure_ascii=False)


def findings_from_json(raw: Optional[str]) -> List[Finding]:
    if not raw:
        return []
    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [Finding(**item) for item in items if isinstance(item, dict)]
