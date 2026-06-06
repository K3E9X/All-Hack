"""Read-only view of the append-only audit log."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query

from app import audit as audit_log

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
async def list_audit(
    engagement_id: Optional[str] = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict:
    events = await audit_log.list_events(
        engagement_id=engagement_id, limit=limit, offset=offset
    )
    return {"count": len(events), "items": events}
