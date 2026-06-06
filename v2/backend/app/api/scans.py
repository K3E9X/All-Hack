"""REST endpoints for scan jobs (launch wrapper, list jobs, job detail, cancel)."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.scans import get_runner
from app.scans.storage import JobRepository
from app.scans.wrappers import available_wrappers, get_wrapper

router = APIRouter(prefix="/api/scans", tags=["scans"])

_repo = JobRepository()


class ScanRequest(BaseModel):
    tool: str
    target: str
    options: Optional[List[str]] = None
    flow_id: Optional[str] = None


@router.get("/tools")
async def list_tools() -> list:
    """Which wrappers exist and whether their binary is installed."""
    return available_wrappers()


@router.post("", status_code=201)
async def submit_scan(req: ScanRequest) -> dict:
    try:
        wrapper = get_wrapper(req.tool)
    except KeyError:
        raise HTTPException(status_code=400, detail=f"unknown tool: {req.tool}")

    if not wrapper.is_available():
        raise HTTPException(
            status_code=503,
            detail=f"tool '{req.tool}' is not installed in this container",
        )
    if not req.target:
        raise HTTPException(status_code=400, detail="target is required")

    runner = get_runner()
    try:
        job = await runner.submit(
            tool=req.tool,
            target=req.target,
            options=req.options,
            flow_id=req.flow_id,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return job.to_public()


@router.get("")
async def list_jobs(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    items = await _repo.list(limit=limit, offset=offset)
    total = await _repo.count()
    return {
        "total": total,
        "count": len(items),
        "offset": offset,
        "limit": limit,
        "items": [job.to_public() for job in items],
    }


@router.get("/{job_id}")
async def job_detail(job_id: str) -> dict:
    job = await _repo.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job.to_detail()


@router.post("/{job_id}/cancel")
async def cancel_job(job_id: str) -> dict:
    job = await _repo.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")

    runner = get_runner()
    cancelled = await runner.cancel(job_id)
    return {"job_id": job_id, "cancelled": cancelled}


@router.delete("/{job_id}")
async def delete_job(job_id: str) -> dict:
    deleted = await _repo.delete(job_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="job not found")
    return {"job_id": job_id, "deleted": True}
