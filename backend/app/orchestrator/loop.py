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
from app import events
from app.engagements import EngagementRepository, EngagementStatus
from app.orchestrator.approvals import ApprovalRepository, requires_exploit_approval
from app.orchestrator.executor import Executor
from app.orchestrator.planner import Planner
from app.orchestrator.runs import Run, RunRepository
from app.orchestrator.state import EngagementState
from app.methodology import PHASE_EXPLOIT
from app.scans.models import JobStatus
from app.scans.storage import JobRepository
from app.validation import build_chains, validate_engagement

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

    # Bill every LLM call made during this run to the engagement.
    from app.llm.usage import current_engagement
    current_engagement.set(engagement.id)

    state = EngagementState(engagement.id)
    planner = Planner(state)
    executor = Executor(state)

    max_jobs = engagement.budget_requests or DEFAULT_MAX_JOBS
    deadline = time.time() + (engagement.budget_seconds or DEFAULT_MAX_SECONDS)

    approvals = ApprovalRepository()
    need_approval = requires_exploit_approval(engagement)

    run.status = "running"
    run.started_at = time.time()
    await runs.update(run)
    await audit("engagement.run_started", engagement_id=engagement.id, run_id=run.id)
    await events.emit(engagement.id, events.RUN_STARTED, "Autonomous run started",
                      run_id=run.id, target=engagement.target_url)

    # Seed the surface: the verified host + the base URL.
    await state.add_asset("host", engagement.target_host, source="engagement")
    await state.add_asset("endpoint", engagement.target_url, source="engagement")
    # Seed from real captured traffic (proxy): the actual parameterized
    # endpoints the operator exercised - far richer than crawling alone.
    seeded = await _seed_from_proxy(state, engagement)
    if seeded:
        await events.emit(engagement.id, events.ASSET_FOUND,
                          f"Seeded {seeded} endpoint(s) from captured proxy traffic",
                          run_id=run.id, level=events.LEVEL_VERBOSE)

    current_phase: Optional[str] = None
    try:
        for iteration in range(MAX_ITERATIONS):
            if await runs.stop_requested(run.id):
                run.status = "stopped"
                await runs.update(run)
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
            if batch[0].phase != current_phase:
                current_phase = batch[0].phase
                await events.emit(engagement.id, events.PHASE_CHANGED,
                                  f"Phase: {current_phase}", run_id=run.id, phase=current_phase)

            # Human checkpoint before exploitation (spec §11 approval).
            if need_approval and batch[0].phase == PHASE_EXPLOIT:
                approved = await _await_exploit_approval(
                    approvals, runs, engagement.id, run.id, batch
                )
                if not approved:
                    # Stop requested or denied: end the active testing loop.
                    run.status = "stopped"
                    await runs.update(run)
                    break

            # Launch the batch (respecting the remaining job budget).
            launched_ids: List[str] = []
            for task in batch:
                if run.jobs_launched >= max_jobs:
                    break
                job = await executor.launch(task)
                if job is not None:
                    launched_ids.append(job.id)
                    run.jobs_launched += 1
                    await events.emit(
                        engagement.id, events.TASK_LAUNCHED,
                        f"{task.tool} -> {task.asset_value}",
                        run_id=run.id, tool=task.tool, target=task.asset_value,
                        catalog_item=task.catalog_item_id,
                    )
            await runs.update(run)

            if not launched_ids:
                # Everything in the batch was skipped (tool missing); avoid a
                # busy loop by marking and moving on.
                continue

            # Wait for this batch to finish, then ingest.
            finished = await _wait_for_jobs(jobs_repo, launched_ids, runs, run.id)
            new_findings = 0
            for job in finished:
                await executor.ingest(job)
                new_findings += len(job.findings)
            await events.emit(
                engagement.id, events.BATCH_DONE,
                f"Batch done: {len(finished)} jobs, {new_findings} findings",
                run_id=run.id, jobs=len(finished), findings=new_findings,
            )

        else:
            logger.info("[%s] hit MAX_ITERATIONS", run.id)

        # Validation phase: confirm findings with safe PoC, then build chains.
        # Always run it (even on stop) so partial results are still validated.
        run.phase = "validation"
        await runs.update(run)
        await events.emit(engagement.id, events.PHASE_CHANGED, "Phase: validation",
                          run_id=run.id, phase="validation")
        try:
            # Logic analysis (IDOR/CSRF) over any traffic captured via the proxy.
            # Runs before validation so its findings get validated + reported too.
            from app.analysis import analyze_logic
            await analyze_logic(engagement.id)
            stats = await validate_engagement(engagement.id)
            chains = await build_chains(engagement.id)
            await audit(
                "engagement.validated",
                engagement_id=engagement.id, run_id=run.id, stats=stats,
            )
            await events.emit(engagement.id, events.VALIDATED,
                              f"Validated: {stats.get('confirmed',0)} confirmed, "
                              f"{stats.get('false_positive',0)} false positive",
                              run_id=run.id, stats=stats)
            if chains:
                await events.emit(engagement.id, events.CHAIN_BUILT,
                                  f"{len(chains)} kill-chain(s) identified",
                                  run_id=run.id, count=len(chains))
        except Exception:  # noqa: BLE001 - validation must not fail the run
            logger.exception("[%s] validation phase error", run.id)

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
    await events.emit(engagement.id, events.RUN_FINISHED,
                      f"Run {run.status}", run_id=run.id, status=run.status,
                      jobs=run.jobs_launched)
    return run.to_public()


async def _seed_from_proxy(state: "EngagementState", engagement) -> int:
    """Add in-scope captured proxy requests as endpoint assets. Endpoints with
    query parameters unlock the param-gated tests (sqlmap/dalfox/nuclei-dast)
    against the real surface the operator exercised."""
    from urllib.parse import urlparse
    from app.proxy import FlowRepository

    try:
        flows = await FlowRepository().list_flows(limit=1000)
    except Exception:  # noqa: BLE001
        return 0

    seen = set()
    count = 0
    for f in flows:
        host = (urlparse(f.url).hostname or "").lower()
        if not engagement.host_in_scope(host):
            continue
        # Normalize (drop fragment); de-dupe identical URLs.
        if f.url in seen:
            continue
        seen.add(f.url)
        await state.add_asset("endpoint", f.url, source="proxy")
        count += 1
        if count >= 500:
            break
    return count


async def _await_exploit_approval(
    approvals: "ApprovalRepository",
    runs: RunRepository,
    engagement_id: str,
    run_id: str,
    batch,
) -> bool:
    """Create an approval request for the exploitation batch and block until a
    human approves/denies it (or the run is stopped). Returns True to proceed."""
    existing = await approvals.pending_for_run(run_id)
    if existing is None:
        tools = sorted({t.tool for t in batch})
        targets = sorted({t.asset_value for t in batch})[:10]
        appr = await approvals.create(
            engagement_id, run_id,
            summary=f"Approve exploitation phase: {', '.join(tools)} on {len(targets)} target(s)",
            tools=tools, targets=targets,
        )
        await events.emit(engagement_id, events.APPROVAL_REQUIRED,
                          "Exploitation requires approval", run_id=run_id,
                          approval_id=appr.id, tools=tools, targets=targets)
    # Poll until resolved or stopped.
    while True:
        if await runs.stop_requested(run_id):
            return False
        decision = await approvals.decision_for_run(run_id)
        if decision == "approved":
            await events.emit(engagement_id, events.APPROVAL_RESOLVED,
                              "Exploitation approved", run_id=run_id, decision="approved")
            return True
        if decision == "denied":
            await events.emit(engagement_id, events.APPROVAL_RESOLVED,
                              "Exploitation denied", run_id=run_id, decision="denied")
            return False
        await asyncio.sleep(POLL_INTERVAL)


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
