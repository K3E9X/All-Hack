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
from urllib.parse import urlparse

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

        if engagement_id:
            # ----- authorization gate (EVERY autonomous/exploit submission) -----
            # The REST endpoint checks this, but the orchestrator and the exploit
            # modules call submit() directly. Enforcing it here closes the hole:
            # the engagement must be authorized and the target host in scope.
            # Discovered subdomains (subfinder/gau) are never auto-trusted.
            from app.engagements.models import EngagementStatus
            from app.engagements.storage import EngagementRepository

            eng = await EngagementRepository().get(engagement_id)
            if eng is None:
                raise RuntimeError(f"engagement {engagement_id} not found")
            if eng.status != EngagementStatus.AUTHORIZED:
                raise RuntimeError(
                    f"engagement {engagement_id} is '{eng.status.value}', not authorized"
                )
            host = _host_of(target)
            if not eng.host_in_scope(host):
                try:
                    from app.audit import audit
                    await audit("scan.blocked_out_of_scope", engagement_id=engagement_id,
                                tool=tool, target=target, target_host=host,
                                scope=eng.scope_hosts)
                except Exception:  # noqa: BLE001
                    pass
                raise RuntimeError(
                    f"target host '{host}' is not in engagement scope {eng.scope_hosts}"
                )

            # Authenticated scanning: inject the engagement's primary-identity
            # headers as tool-specific flags so the scanner tests behind the login.
            try:
                from app.scans.auth import auth_args
                if eng.primary_auth:
                    options = auth_args(tool, eng.primary_auth) + options
            except Exception:  # noqa: BLE001 - never block a scan on auth wiring
                logger.exception("auth injection failed for %s", tool)

            # WAF-aware exploitation: if a WAF was fingerprinted, prepend
            # evasion/throttle options so active tools adapt.
            try:
                from app.orchestrator.state import EngagementState
                from app.scans.waf import is_waf_tech, waf_args

                techs = await EngagementState(engagement_id).technologies()
                if is_waf_tech(techs):
                    options = waf_args(tool) + options
            except Exception:  # noqa: BLE001 - never block a scan on WAF wiring
                logger.exception("waf adaptation failed for %s", tool)

        # Blind-XSS OOB: fire dalfox blind payloads at a configured interactsh
        # server (confirmed server-side).
        try:
            import os
            from app.scans.waf import blind_args
            oob = os.environ.get("INTERACTSH_SERVER", "").strip()
            extra = blind_args(tool, oob)
            if extra:
                options = extra + options
        except Exception:  # noqa: BLE001
            logger.exception("oob wiring failed for %s", tool)
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


def _host_of(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    return target.split("/", 1)[0].split(":", 1)[0].lower()


_runner: Optional[Runner] = None


def get_runner() -> Runner:
    global _runner
    if _runner is None:
        _runner = Runner()
    return _runner
