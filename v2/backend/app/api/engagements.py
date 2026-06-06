"""Engagement endpoints: create, show authorization challenge, verify, list.

This is the authorization gate from spec §8. No scan can run against a host
unless an AUTHORIZED engagement covers it (enforced in app/api/scans.py).
"""
from __future__ import annotations

import time
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.audit import audit
from app.engagements import (
    Engagement,
    EngagementRepository,
    EngagementStatus,
    get_verifier,
)

router = APIRouter(prefix="/api/engagements", tags=["engagements"])

_repo = EngagementRepository()


class CreateEngagementRequest(BaseModel):
    target_url: str
    title: Optional[str] = None
    notes: Optional[str] = None
    scope_hosts: Optional[List[str]] = None
    budget_requests: Optional[int] = None
    budget_seconds: Optional[int] = None
    # Pause before the exploitation phase and wait for human approval.
    require_exploit_approval: bool = False
    # The operator must attest they are authorized to test this target.
    attest_authorized: bool = False


@router.post("", status_code=201)
async def create_engagement(req: CreateEngagementRequest) -> dict:
    if not req.target_url:
        raise HTTPException(status_code=400, detail="target_url is required")
    if not req.attest_authorized:
        raise HTTPException(
            status_code=400,
            detail="attest_authorized must be true: you must confirm you are "
            "authorized to test this target.",
        )

    e = Engagement.create(
        target_url=req.target_url,
        title=req.title or "",
        notes=req.notes or "",
        scope_hosts=req.scope_hosts,
        budget_requests=req.budget_requests,
        budget_seconds=req.budget_seconds,
        attested=req.attest_authorized,
        require_exploit_approval=req.require_exploit_approval,
    )
    await _repo.create(e)
    await audit(
        "engagement.created",
        engagement_id=e.id,
        target=e.target_url,
        scope=e.scope_hosts,
    )
    return {
        "engagement": e.to_public(),
        "challenge": e.challenge(),
    }


@router.get("")
async def list_engagements(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    items = await _repo.list(limit=limit, offset=offset)
    total = await _repo.count()
    return {
        "total": total,
        "count": len(items),
        "items": [e.to_public() for e in items],
    }


@router.get("/{engagement_id}")
async def get_engagement(engagement_id: str) -> dict:
    e = await _repo.get(engagement_id)
    if e is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    out = {"engagement": e.to_public()}
    if e.status == EngagementStatus.PENDING_AUTHORIZATION:
        out["challenge"] = e.challenge()
    return out


@router.post("/{engagement_id}/verify")
async def verify_engagement(engagement_id: str) -> dict:
    e = await _repo.get(engagement_id)
    if e is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    if e.status == EngagementStatus.AUTHORIZED:
        return {"engagement": e.to_public(), "verified": True, "detail": "already authorized"}
    if e.status in (EngagementStatus.CLOSED, EngagementStatus.REVOKED):
        raise HTTPException(status_code=409, detail=f"engagement is {e.status.value}")

    verifier = get_verifier()
    result = await verifier.verify(e)

    if result.ok:
        e.status = EngagementStatus.AUTHORIZED
        e.verification_method = result.method
        e.verified_at = time.time()
        await _repo.update(e)
        await audit(
            "engagement.authorized",
            engagement_id=e.id,
            target=e.target_url,
            method=result.method.value if result.method else None,
        )
        return {"engagement": e.to_public(), "verified": True, "detail": result.detail}

    await audit(
        "engagement.verification_failed",
        engagement_id=e.id,
        target=e.target_url,
        detail=result.detail,
    )
    return {
        "engagement": e.to_public(),
        "verified": False,
        "detail": result.detail,
        "challenge": e.challenge(),
    }


@router.post("/{engagement_id}/close")
async def close_engagement(engagement_id: str) -> dict:
    e = await _repo.get(engagement_id)
    if e is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    e.status = EngagementStatus.CLOSED
    e.closed_at = time.time()
    await _repo.update(e)
    await audit("engagement.closed", engagement_id=e.id, target=e.target_url)
    return {"engagement": e.to_public()}
