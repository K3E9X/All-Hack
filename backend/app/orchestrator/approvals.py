"""Human approval checkpoints (spec §11).

When an engagement is created with require_exploit_approval=true, the loop
pauses before the exploitation phase and waits for an operator decision via
POST /api/engagements/{id}/approvals/{approval_id}. One pending approval per
run at a time.
"""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app import db

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS approvals (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    run_id        TEXT NOT NULL,
    summary       TEXT,
    tools_json    TEXT,
    targets_json  TEXT,
    decision      TEXT,                 -- NULL = pending | approved | denied
    created_at    DOUBLE PRECISION NOT NULL,
    decided_at    DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_approvals_run ON approvals(run_id);
"""

db.register_schema(SCHEMA_SQL)


def requires_exploit_approval(engagement) -> bool:
    return bool(getattr(engagement, "require_exploit_approval", False))


@dataclass
class Approval:
    id: str
    engagement_id: str
    run_id: str
    summary: str
    tools: List[str]
    targets: List[str]
    decision: Optional[str]
    created_at: float
    decided_at: Optional[float] = None

    def to_public(self) -> Dict[str, Any]:
        return {
            "id": self.id, "engagement_id": self.engagement_id, "run_id": self.run_id,
            "summary": self.summary, "tools": self.tools, "targets": self.targets,
            "decision": self.decision, "created_at": self.created_at,
            "decided_at": self.decided_at,
        }


class ApprovalRepository:
    async def create(
        self, engagement_id: str, run_id: str, *, summary: str,
        tools: List[str], targets: List[str],
    ) -> Approval:
        appr = Approval(
            id=f"appr_{int(time.time()*1000)}_{secrets.token_hex(2)}",
            engagement_id=engagement_id, run_id=run_id, summary=summary,
            tools=tools, targets=targets, decision=None, created_at=time.time(),
        )
        async with db.acquire() as conn:
            await conn.execute(
                "INSERT INTO approvals (id, engagement_id, run_id, summary, tools_json, "
                "targets_json, decision, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
                appr.id, engagement_id, run_id, summary,
                json.dumps(tools), json.dumps(targets), None, appr.created_at,
            )
        return appr

    async def pending_for_run(self, run_id: str) -> Optional[Approval]:
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM approvals WHERE run_id=$1 AND decision IS NULL "
                "ORDER BY created_at DESC LIMIT 1",
                run_id,
            )
        return _row(row) if row else None

    async def decision_for_run(self, run_id: str) -> Optional[str]:
        """Latest decision for the run's most recent approval (or None)."""
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT decision FROM approvals WHERE run_id=$1 ORDER BY created_at DESC LIMIT 1",
                run_id,
            )
        return row["decision"] if row else None

    async def get(self, approval_id: str) -> Optional[Approval]:
        async with db.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM approvals WHERE id=$1", approval_id)
        return _row(row) if row else None

    async def decide(self, approval_id: str, decision: str) -> bool:
        async with db.acquire() as conn:
            result = await conn.execute(
                "UPDATE approvals SET decision=$1, decided_at=$2 WHERE id=$3 AND decision IS NULL",
                decision, time.time(), approval_id,
            )
        try:
            return int(result.split()[-1]) > 0
        except (IndexError, ValueError):
            return False

    async def list_for_engagement(self, engagement_id: str) -> List[Approval]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM approvals WHERE engagement_id=$1 ORDER BY created_at DESC",
                engagement_id,
            )
        return [_row(r) for r in rows]


def _row(row) -> Approval:
    return Approval(
        id=row["id"], engagement_id=row["engagement_id"], run_id=row["run_id"],
        summary=row["summary"], tools=json.loads(row["tools_json"] or "[]"),
        targets=json.loads(row["targets_json"] or "[]"), decision=row["decision"],
        created_at=row["created_at"], decided_at=row["decided_at"],
    )
