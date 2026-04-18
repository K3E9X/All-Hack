"""Async runner that executes wrapper commands and updates the Job in SQLite.

Each job runs in its own asyncio task. stdout and stderr are streamed into
memory (capped) so we can store them for inspection. When the process ends,
we hand the raw bytes to the wrapper's `parse()` method and persist the
findings.

Concurrency: jobs run in parallel; users can cancel from the API.
"""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

from app.config import settings
from app.scans.models import Finding, Job, JobStatus
from app.scans.storage import JobRepository, init_jobs_schema, new_job_id
from app.scans.wrappers import get_wrapper

logger = logging.getLogger("allhack.scans.runner")

# Max bytes we keep in memory for stdout/stderr. Past this we drop older data.
MAX_STREAM_BYTES = 1 * 1024 * 1024  # 1 MiB


class Runner:
    def __init__(self, db_path: Path) -> None:
        self.repo = JobRepository(db_path)
        self._tasks: Dict[str, asyncio.Task] = {}
        self._processes: Dict[str, asyncio.subprocess.Process] = {}

    async def submit(
        self,
        tool: str,
        target: str,
        options: Optional[List[str]] = None,
        flow_id: Optional[str] = None,
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
        )
        await self.repo.create(job)

        task = asyncio.create_task(self._run(job))
        self._tasks[job.id] = task
        task.add_done_callback(lambda _t, jid=job.id: self._tasks.pop(jid, None))
        return job

    async def cancel(self, job_id: str) -> bool:
        proc = self._processes.get(job_id)
        if proc is None:
            return False
        try:
            proc.terminate()
        except ProcessLookupError:
            return False
        return True

    async def _run(self, job: Job) -> None:
        wrapper = get_wrapper(job.tool)
        cmd = wrapper.build_command(job.target, job.args)

        job.status = JobStatus.RUNNING
        job.started_at = time.time()
        await self.repo.update(job)
        logger.info("[%s] %s %s", job.id, job.tool, cmd)

        stdout_buf = bytearray()
        stderr_buf = bytearray()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._processes[job.id] = proc

            try:
                await asyncio.wait_for(
                    self._pump_streams(proc, stdout_buf, stderr_buf),
                    timeout=wrapper.timeout_seconds,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise

            exit_code = await proc.wait()
        except FileNotFoundError as exc:
            job.status = JobStatus.FAILED
            job.error = f"binary not found: {exc.filename}"
            job.finished_at = time.time()
            await self.repo.update(job)
            return
        except asyncio.TimeoutError:
            job.status = JobStatus.FAILED
            job.error = f"timeout after {wrapper.timeout_seconds}s"
            job.exit_code = -1
            job.finished_at = time.time()
            job.stdout = bytes(stdout_buf)
            job.stderr = bytes(stderr_buf)
            await self.repo.update(job)
            return
        except Exception as exc:  # noqa: BLE001
            job.status = JobStatus.FAILED
            job.error = f"{type(exc).__name__}: {exc}"
            job.finished_at = time.time()
            job.stdout = bytes(stdout_buf)
            job.stderr = bytes(stderr_buf)
            await self.repo.update(job)
            logger.exception("[%s] runner crashed", job.id)
            return
        finally:
            self._processes.pop(job.id, None)

        # Process finished normally. Let the wrapper turn output into findings.
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
        # Many scanners exit non-zero when they find issues (e.g. dalfox). Still a success
        # from our perspective; only raise FAILED if we could not run the command at all.
        job.status = JobStatus.SUCCEEDED
        await self.repo.update(job)
        logger.info(
            "[%s] done in %.1fs exit=%s findings=%d",
            job.id,
            (job.finished_at - job.started_at) if job.started_at else 0.0,
            exit_code,
            len(findings),
        )

    async def _pump_streams(
        self,
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
                    # Drop oldest data but keep recent tail.
                    del buf[: len(buf) - MAX_STREAM_BYTES]

        await asyncio.gather(pump(proc.stdout, stdout_buf), pump(proc.stderr, stderr_buf))


_runner: Optional[Runner] = None


def get_runner() -> Runner:
    global _runner
    if _runner is None:
        init_jobs_schema(settings.sqlite_path)
        _runner = Runner(settings.sqlite_path)
    return _runner
