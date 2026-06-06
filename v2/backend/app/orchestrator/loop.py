"""The autonomous engagement loop (spec §4, §13.4 acceptance).

plan -> execute -> wait -> ingest, repeated until coverage saturates, the
budget is hit, or a stop is requested. Runs inside the arq worker as a
long-lived task; the scan jobs it launches run concurrently on the same
worker (max_jobs > 1), so the loop can submit a batch and wait for it.

This is deterministic and fully functional without any LLM; the planner's
optional LLM pass only re-orders the batch.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import List, Optional

from app.audit import audit
from app.engagements import EngagementRepository, EngagementStatus
from app.orchestrator.executor import Executor
from app.orchestrator.planner import Planner
from app.orchestrator.runs import Run, RunRepository
from app.orchestrator.state import EngagementState
from app.scans.models import JobStatus
from app.scans.storage import JobRepository

logger = logging.getLogger("allhack.orchestrator.loop")

# Safety defaults when the engagement sets no budget.
DEFAULT_MAX_JOBS = 200
DEFAULT_MAX_SECONDS = 2 * 60 * 60          # 2 hours
MAX_ITERATIONS = 50
BATCH_SIZE = 8
POLL_INTERVAL = 3.0                        # seconds between job-status polls
ITERATION_WAIT_CAP = 45 * 60               # max wait for one batch to finish

_TERMINAL = {JobStatus.SUCCEEDED.value, JobStatus.FAILED.value, JobStatus.CANCELLED.value}


async def run_engagement_loop(run_id: str) -> dict:
    runs = RunRepository()
    engagements = EngagementRepository()
    jobs_repo = JobRepository()

    run = await runs.get(run_id)
    if run is None:
        return {"run_id": run_id, "status": "missing"}

    engagement = await engagements.get(run.engagement_id)
    if engagement is None:
        await _fail(runs, run, "engagement not found")
        return run.to_public()
    if engagement.status != EngagementStatus.AUTHORIZED:
        await _fail(runs, run, f"engagement is {engagement.status.value}, not authorized")
        return run.to_public()

    state = EngagementState(engagement.id)
    planner = Planner(state)
    executor = Executor(state)

    max_jobs = engagement.budget_requests or DEFAULT_MAX_JOBS
    deadline = time.time() + (engagement.budget_seconds or DEFAULT_MAX_SECONDS)

    run.status = "running"
    run.started_at = time.time()
    await runs.update(run)
    await audit("engagement.run_started", engagement_id=engagement.id, run_id=run.id)

    # Seed the surface: the verified host + the base URL.
    await state.add_asset("host", engagement.target_host, source="engagement")
    await state.add_asset("endpoint", engagement.target_url, source="engagement")

    try:
        for iteration in range(MAX_ITERATIONS):
            if await runs.stop_requested(run.id):
                run.status = "stopped"
                break
            if time.time() > deadline:
                logger.info("[%s] time budget reached", run.id)
                break
            if run.jobs_launched >= max_jobs:
                logger.info("[%s] job budget reached (%d)", run.id, max_jobs)
                break

            batch = await planner.plan(max_tasks=BATCH_SIZE)
            if not batch:
                logger.info("[%s] coverage saturated after %d iterations", run.id, iteration)
                break

            run.iterations = iteration + 1
            run.phase = batch[0].phase
            await runs.update(run)

            # Launch the batch (respecting the remaining job budget).
            launched_ids: List[str] = []
            for task in batch:
                if run.jobs_launched >= max_jobs:
                    break
                job = await executor.launch(task)
                if job is not None:
                    launched_ids.append(job.id)
                    run.jobs_launched += 1
            await runs.update(run)

            if not launched_ids:
                # Everything in the batch was skipped (tool missing); avoid a
                # busy loop by marking and moving on.
                continue

            # Wait for this batch to finish, then ingest.
            finished = await _wait_for_jobs(jobs_repo, launched_ids, runs, run.id)
            for job in finished:
                await executor.ingest(job)

        else:
            logger.info("[%s] hit MAX_ITERATIONS", run.id)

        if run.status != "stopped":
            run.status = "completed"
    except asyncio.CancelledError:
        run.status = "stopped"
        await _finalize(runs, run)
        await audit("engagement.run_cancelled", engagement_id=engagement.id, run_id=run.id)
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("[%s] orchestrator loop crashed", run.id)
        await _fail(runs, run, f"{type(exc).__name__}: {exc}")
        return run.to_public()

    await _finalize(runs, run)
    await audit(
        "engagement.run_finished",
        engagement_id=engagement.id,
        run_id=run.id,
        status=run.status,
        jobs=run.jobs_launched,
        coverage=await state.coverage_summary(),
    )
    return run.to_public()


async def _wait_for_jobs(
    jobs_repo: JobRepository,
    job_ids: List[str],
    runs: RunRepository,
    run_id: str,
) -> list:
    """Poll until all jobs reach a terminal state, the per-batch cap elapses,
    or a stop is requested. Returns the finished Job objects."""
    deadline = time.time() + ITERATION_WAIT_CAP
    pending = set(job_ids)
    finished = []

    while pending and time.time() < deadline:
        if await runs.stop_requested(run_id):
            break
        await asyncio.sleep(POLL_INTERVAL)
        for jid in list(pending):
            job = await jobs_repo.get(jid)
            if job is None:
                pending.discard(jid)
                continue
            if job.status.value in _TERMINAL:
                finished.append(job)
                pending.discard(jid)

    # Pull whatever is left (e.g. cap reached) so we still ingest partials.
    for jid in pending:
        job = await jobs_repo.get(jid)
        if job is not None:
            finished.append(job)
    return finished


async def _finalize(runs: RunRepository, run: Run) -> None:
    run.finished_at = time.time()
    await runs.update(run)


async def _fail(runs: RunRepository, run: Run, error: str) -> None:
    run.status = "failed"
    run.error = error
    run.finished_at = time.time()
    await runs.update(run)
