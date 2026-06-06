"""Autonomous engagement control: start a run, stop it, read live state."""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException

from app.audit import audit
from app.engagements import EngagementRepository, EngagementStatus
from app.orchestrator.runs import Run, RunRepository, new_run_id
from app.orchestrator.state import EngagementState
from app.scans.storage import JobRepository
from app.queue import get_arq_pool

router = APIRouter(prefix="/api/engagements", tags=["orchestrator"])

_engagements = EngagementRepository()
_runs = RunRepository()
_jobs = JobRepository()


@router.post("/{engagement_id}/run")
async def start_run(engagement_id: str) -> dict:
    e = await _engagements.get(engagement_id)
    if e is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    if e.status != EngagementStatus.AUTHORIZED:
        raise HTTPException(
            status_code=403,
            detail=f"engagement is '{e.status.value}', not 'authorized'. Verify ownership first.",
        )

    # One active run at a time.
    latest = await _runs.latest_for_engagement(engagement_id)
    if latest and latest.status in ("queued", "running"):
        raise HTTPException(status_code=409, detail=f"run {latest.id} already active")

    run = Run(
        id=new_run_id(),
        engagement_id=engagement_id,
        status="queued",
        created_at=time.time(),
    )
    await _runs.create(run)

    pool = await get_arq_pool()
    await pool.enqueue_job("run_engagement", run.id, _job_id=run.id)
    await audit("engagement.run_queued", engagement_id=engagement_id, run_id=run.id)
    return {"run": run.to_public()}


@router.post("/{engagement_id}/stop")
async def stop_run(engagement_id: str) -> dict:
    latest = await _runs.latest_for_engagement(engagement_id)
    if latest is None or latest.status not in ("queued", "running"):
        raise HTTPException(status_code=404, detail="no active run")
    await _runs.request_stop(latest.id)
    # Also try to abort the arq task so a long wait is interrupted promptly.
    try:
        pool = await get_arq_pool()
        await pool.abort_job(latest.id, timeout=5)
    except Exception:  # noqa: BLE001
        pass
    await audit("engagement.run_stop_requested", engagement_id=engagement_id, run_id=latest.id)
    return {"run_id": latest.id, "stop_requested": True}


@router.get("/{engagement_id}/state")
async def engagement_state(engagement_id: str) -> dict:
    e = await _engagements.get(engagement_id)
    if e is None:
        raise HTTPException(status_code=404, detail="engagement not found")

    state = EngagementState(engagement_id)
    run = await _runs.latest_for_engagement(engagement_id)
    assets = await state.assets()
    tech = await state.technologies()
    coverage = await state.coverage_rows()
    cov_summary = await state.coverage_summary()

    # Aggregate findings from this engagement's jobs.
    jobs = await _jobs.list_by_engagement(engagement_id)
    findings = []
    for j in jobs:
        for f in j.findings:
            d = f.to_dict()
            d["job_id"] = j.id
            d["tool"] = j.tool
            findings.append(d)

    return {
        "engagement": e.to_public(),
        "run": run.to_public() if run else None,
        "assets": [
            {"kind": a.kind, "value": a.value, "has_params": a.has_params,
             "is_https": a.is_https, "source": a.source}
            for a in assets
        ],
        "technologies": tech,
        "coverage_summary": cov_summary,
        "coverage": coverage,
        "jobs": [j.to_public() for j in jobs],
        "findings": findings,
        "findings_count": len(findings),
    }
