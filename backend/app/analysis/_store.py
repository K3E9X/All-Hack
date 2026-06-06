"""Shared persistence for the analysis modules.

Each analyzer (logic / JS recon / JWT / access-control) stores its findings as
a synthetic scan job under its own `tool` name, so they flow through the normal
validation -> report -> kill-chain pipeline AND stay cleanly partitioned in the
UI (one tool == one category of test). Re-running an analyzer replaces its
previous synthetic job (idempotent) instead of duplicating findings.
"""
from __future__ import annotations

import time
from typing import List

from app.scans.models import Finding, Job, JobStatus
from app.scans.storage import JobRepository, new_job_id


async def save_analysis_job(
    engagement_id: str, tool: str, findings: List[Finding], *, target: str
) -> None:
    repo = JobRepository()
    await repo.delete_by_tool(engagement_id, tool)
    now = time.time()
    job = Job(
        id=new_job_id(),
        tool=tool,
        target=target,
        args=[],
        status=JobStatus.SUCCEEDED,
        created_at=now,
        started_at=now,
        finished_at=now,
        exit_code=0,
        findings=findings,
        engagement_id=engagement_id,
    )
    await repo.create(job)
