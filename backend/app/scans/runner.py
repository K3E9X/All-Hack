"""Job submission front-end.

Before Phase 1-E the runner spawned subprocesses in the same FastAPI process
via asyncio.create_task. Now scans are queued on Redis and executed by the
arq worker container (app.workers.run_scan). This module keeps the same
public API (`submit`, `cancel`) so existing endpoints keep working unchanged.
"""
from __future__ import annotations

import logging
import time
from typing import List, Optional

from app.scans.models import Job, JobStatus
from app.scans.storage import JobRepository, new_job_id
from app.scans.wrappers import get_wrapper
from app.queue import get_arq_pool

logger = logging.getLogger("allhack.scans.runner")


class Runner:
    def __init__(self) -> None:
        self.repo = JobRepository()

    async def submit(
        self,
        tool: str,
        target: str,
        options: Optional[List[str]] = None,
        flow_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        catalog_item_id: Optional[str] = None,
    ) -> Job:
        wrapper = get_wrapper(tool)  # raises KeyError for unknown tools
        if not wrapper.is_available():
            raise RuntimeError(f"tool '{tool}' is not installed in this container")

        options = list(options or [])
        job = Job(
            id=new_job_id(),
            tool=tool,
            target=target,
            args=options,
            status=JobStatus.QUEUED,
            created_at=time.time(),
            flow_id=flow_id,
            engagement_id=engagement_id,
            catalog_item_id=catalog_item_id,
        )
        await self.repo.create(job)

        pool = await get_arq_pool()
        # Reuse our own job ID as the arq job ID so cancel can target it.
        await pool.enqueue_job("run_scan", job.id, _job_id=job.id)
        logger.info("[%s] enqueued (%s on %s)", job.id, tool, target)
        return job

    async def cancel(self, job_id: str) -> bool:
        """Ask the worker to abort the job. arq sends a CancelledError to the
        task; app.workers.run_scan catches it, SIGTERMs the subprocess and
        marks the job as cancelled."""
        pool = await get_arq_pool()
        try:
            return bool(await pool.abort_job(job_id, timeout=5))
        except Exception:  # noqa: BLE001
            logger.exception("cancel failed for %s", job_id)
            return False


_runner: Optional[Runner] = None


def get_runner() -> Runner:
    global _runner
    if _runner is None:
        _runner = Runner()
    return _runner
