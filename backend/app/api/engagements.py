"""Engagement endpoints: create, show authorization challenge, verify, list.

This is the authorization gate from spec §8. No scan can run against a host
unless an AUTHORIZED engagement covers it (enforced in app/api/scans.py).
"""
from __future__ import annotations

import time
from typing import Dict


def _parse_headers_blob(blob):
    """Parse 'Name: value' lines into [{'name','value'}]. Returns [] if empty."""
    if not blob:
        return []
    out = []
    for line in blob.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        name, value = name.strip(), value.strip()
        if name and value:
            out.append({"name": name, "value": value})
    return out
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
    # Authenticated scanning: headers of the PRIMARY identity ("Name: value"
    # per line, e.g. Cookie / Authorization). Injected into every scanner so
    # it tests behind the login.
    auth_headers: Optional[str] = None
    # Grey-box: headers of a SECOND identity, as a blob ("Name: value" per line,
    # e.g. a Cookie or Authorization header). Enables true IDOR/BOLA proof by
    # replaying a captured request as another user.
    secondary_auth_headers: Optional[str] = None
    # The operator must attest they are authorized to test this target.
    attest_authorized: bool = False
    # Active exploitation: prove confirmed injections (RCE/SQLi) by running a
    # benign read-only command. Off by default; double-gated with the
    # exploitation approval.
    allow_active_exploit: bool = False
    # Sub-flag: also allow OS command execution through SQLi (sqlmap --os-cmd).
    allow_sql_os_cmd: bool = False
    # Sub-flag: prove a data breach with a small bounded SQLi dump (<=3 rows).
    allow_data_proof: bool = False


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
        allow_active_exploit=req.allow_active_exploit,
        allow_sql_os_cmd=req.allow_sql_os_cmd,
        allow_data_proof=req.allow_data_proof,
        secondary_auth=_parse_headers_blob(req.secondary_auth_headers),
        primary_auth=_parse_headers_blob(req.auth_headers),
    )
    await _repo.create(e)
    await audit(
        "engagement.created",
        engagement_id=e.id,
        target=e.target_url,
        scope=e.scope_hosts,
        status=e.status.value,
    )
    out = {"engagement": e.to_public()}
    # Only surface the ownership-proof challenge when authorization is still
    # pending (i.e. the operator did not attest). Attestation auto-authorizes.
    if e.status == EngagementStatus.PENDING_AUTHORIZATION:
        out["challenge"] = e.challenge()
    return out


async def _engagement_summary(engagement_id: str) -> dict:
    """Per-engagement progress/phase/severity/radar for the list + inspector."""
    from app import coverage_util
    from app.methodology import CATALOG
    from app.orchestrator.runs import RunRepository
    from app.orchestrator.state import EngagementState
    from app.validation import ValidatedFindingRepository

    out = {"progress": 0, "phase": None,
           "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
           "radar": [0, 0, 0, 0, 0, 0]}
    try:
        run = await RunRepository().latest_for_engagement(engagement_id)
        if run:
            out["phase"] = run.phase
        rows = await EngagementState(engagement_id).coverage_rows()
        covered = coverage_util.covered_ids(rows)
        out["radar"] = coverage_util.radar(CATALOG, covered)
        out["progress"] = coverage_util.progress_pct(CATALOG, covered)
        for f in await ValidatedFindingRepository().list(engagement_id):
            if f.status == "false_positive":
                continue
            sev = (f.severity or "").lower()
            if sev in out["severity_counts"]:
                out["severity_counts"][sev] += 1
    except Exception:  # noqa: BLE001 - summary must never break the list
        pass
    return out


@router.get("")
async def list_engagements(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    items = await _repo.list(limit=limit, offset=offset)
    total = await _repo.count()
    out_items = []
    for e in items:
        d = e.to_public()
        d.update(await _engagement_summary(e.id))
        out_items.append(d)
    return {
        "total": total,
        "count": len(items),
        "items": out_items,
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
