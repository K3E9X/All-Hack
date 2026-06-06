"""arq worker: picks scan jobs off Redis and executes the wrapper subprocess.

Runs as a separate container (see the 'worker' service in docker-compose). The
FastAPI process only enqueues; this process is the only one that actually
spawns nuclei/sqlmap/ffuf/etc.

Cancellation: the API calls arq.connections.ArqRedis.abort_job(job_id). arq
sends an asyncio.CancelledError into the task; we catch it and SIGTERM the
subprocess in finally so the binary releases its resources cleanly.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from arq import cron  # noqa: F401  (kept for future scheduled tasks)

from app import db
from app.queue import close_arq_pool, get_arq_pool  # noqa: F401
from app.queue import redis_settings as _redis_settings
import app.audit  # noqa: F401  - register schema
import app.engagements.storage  # noqa: F401  - register schema
import app.orchestrator.state  # noqa: F401  - register schema
import app.orchestrator.runs  # noqa: F401  - register schema
import app.proxy.storage  # noqa: F401  - register schema
import app.scans.storage  # noqa: F401  - register schema

from app.config import settings
from app.orchestrator.loop import run_engagement_loop
from app.scans.models import Finding, Job, JobStatus
from app.scans.storage import JobRepository
from app.scans.wrappers import get_wrapper

logger = logging.getLogger("allhack.worker")

# Same caps as the in-process Runner had.
MAX_STREAM_BYTES = 1 * 1024 * 1024  # 1 MiB


# -----------------------------------------------------------------------------
# Task implementation
# -----------------------------------------------------------------------------

async def run_scan(ctx: Dict[str, Any], job_id: str) -> Dict[str, Any]:
    """arq task. Load the job from Postgres, run the wrapper, persist results.

    Returns a tiny status dict (arq stores it as the job result).
    """
    repo = JobRepository()
    job = await repo.get(job_id)
    if job is None:
        logger.error("run_scan: job %s not found in DB", job_id)
        return {"job_id": job_id, "status": "missing"}

    wrapper = get_wrapper(job.tool)
    cmd = wrapper.build_command(job.target, job.args)

    job.status = JobStatus.RUNNING
    job.started_at = time.time()
    await repo.update(job)
    logger.info("[%s] %s %s", job.id, job.tool, cmd)

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    proc: Optional[asyncio.subprocess.Process] = None

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            await asyncio.wait_for(
                _pump_streams(proc, stdout_buf, stderr_buf),
                timeout=wrapper.timeout_seconds,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            job.status = JobStatus.FAILED
            job.error = f"timeout after {wrapper.timeout_seconds}s"
            job.exit_code = -1
            job.finished_at = time.time()
            job.stdout = bytes(stdout_buf)
            job.stderr = bytes(stderr_buf)
            await repo.update(job)
            return {"job_id": job_id, "status": job.status.value}

        exit_code = await proc.wait()

    except asyncio.CancelledError:
        # arq.abort_job() lands here. SIGTERM the subprocess then re-raise so
        # arq marks the task as aborted.
        if proc is not None and proc.returncode is None:
            try:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            except ProcessLookupError:
                pass
        job.status = JobStatus.CANCELLED
        job.finished_at = time.time()
        job.stdout = bytes(stdout_buf)
        job.stderr = bytes(stderr_buf)
        await repo.update(job)
        raise

    except FileNotFoundError as exc:
        job.status = JobStatus.FAILED
        job.error = f"binary not found: {exc.filename}"
        job.finished_at = time.time()
        await repo.update(job)
        return {"job_id": job_id, "status": job.status.value}

    except Exception as exc:  # noqa: BLE001
        logger.exception("[%s] worker crashed", job.id)
        job.status = JobStatus.FAILED
        job.error = f"{type(exc).__name__}: {exc}"
        job.finished_at = time.time()
        job.stdout = bytes(stdout_buf)
        job.stderr = bytes(stderr_buf)
        await repo.update(job)
        return {"job_id": job_id, "status": job.status.value}

    # Normal completion.
    try:
        result = wrapper.parse(bytes(stdout_buf), bytes(stderr_buf), exit_code, job.target)
        findings: List[Finding] = result.findings
    except Exception as exc:  # noqa: BLE001
        logger.exception("[%s] parse failed", job.id)
        findings = []
        job.error = f"parse error: {type(exc).__name__}: {exc}"

    job.stdout = bytes(stdout_buf)
    job.stderr = bytes(stderr_buf)
    job.exit_code = exit_code
    job.finished_at = time.time()
    job.findings = findings
    job.status = JobStatus.SUCCEEDED
    await repo.update(job)

    logger.info(
        "[%s] done in %.1fs exit=%s findings=%d",
        job.id,
        (job.finished_at - job.started_at) if job.started_at else 0.0,
        exit_code,
        len(findings),
    )
    return {"job_id": job_id, "status": job.status.value, "findings": len(findings)}


async def run_engagement(ctx: Dict[str, Any], run_id: str) -> Dict[str, Any]:
    """arq task: drive the autonomous plan->execute->ingest loop for a run.

    Long-lived. The scan sub-jobs it launches run concurrently on this same
    worker (max_jobs > 1), so the loop can submit a batch and await it.
    """
    return await run_engagement_loop(run_id)


async def _pump_streams(
    proc: asyncio.subprocess.Process,
    stdout_buf: bytearray,
    stderr_buf: bytearray,
) -> None:
    assert proc.stdout is not None and proc.stderr is not None

    async def pump(reader: asyncio.StreamReader, buf: bytearray) -> None:
        while True:
            chunk = await reader.read(16 * 1024)
            if not chunk:
                return
            buf.extend(chunk)
            if len(buf) > MAX_STREAM_BYTES:
                # Drop oldest data; keep recent tail.
                del buf[: len(buf) - MAX_STREAM_BYTES]

    await asyncio.gather(pump(proc.stdout, stdout_buf), pump(proc.stderr, stderr_buf))


# -----------------------------------------------------------------------------
# arq lifecycle hooks
# -----------------------------------------------------------------------------

async def startup(ctx: Dict[str, Any]) -> None:
    await db.init_db()
    logger.info("worker startup: Postgres pool ready")


async def shutdown(ctx: Dict[str, Any]) -> None:
    await db.close_pool()


class WorkerSettings:
    """Used by: arq app.workers.WorkerSettings"""
    functions = [run_scan, run_engagement]
    redis_settings = _redis_settings()
    on_startup = startup
    on_shutdown = shutdown
    # Must be > 1: the long-lived run_engagement task occupies one slot while
    # the scan sub-jobs it launches need other slots to actually execute.
    max_jobs = 8
    # arq retries failed jobs by default; we never want that for pentest
    # commands (a flaky network would re-run sqlmap five times). Disable.
    max_tries = 1
    # The orchestrator loop can run for a long time; raise the per-task ceiling.
    job_timeout = 3 * 60 * 60
