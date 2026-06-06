"""Executor agent (spec §4.1).

Turns a planner Task into a real wrapper job (via the queue), and ingests a
finished job's findings back into the engagement state so later planning sees
the expanded surface:

  * httpx / whatweb  -> fingerprints (drive tech-gated catalog items)
  * katana / gau / ffuf -> new endpoint assets (drive param-gated items)

The executor never shells out itself; it goes through the same Runner /
arq queue as manual scans, so the authorization model and sandboxing are
identical.
"""
from __future__ import annotations

import logging
from typing import List, Optional
from urllib.parse import urlparse

from app.scans import Job, get_runner
from app.orchestrator.planner import Task
from app.orchestrator.state import EngagementState

logger = logging.getLogger("allhack.orchestrator.executor")


class Executor:
    def __init__(self, state: EngagementState) -> None:
        self.state = state
        self.runner = get_runner()

    async def launch(self, task: Task) -> Optional[Job]:
        """Submit a task as a job and mark coverage 'running'. Returns the job
        or None if the tool isn't available."""
        try:
            job = await self.runner.submit(
                tool=task.tool,
                target=task.asset_value,
                options=task.options,
                engagement_id=self.state.engagement_id,
                catalog_item_id=task.catalog_item_id,
            )
        except (RuntimeError, KeyError) as exc:
            logger.warning("skip task %s: %s", task.key, exc)
            await self.state.mark_coverage(task.catalog_item_id, task.asset_value, "skipped")
            return None

        await self.state.mark_coverage(
            task.catalog_item_id, task.asset_value, "running", job_id=job.id
        )
        return job

    async def ingest(self, job: Job) -> None:
        """Fold a finished job's findings into the engagement state."""
        status = "done" if job.status.value in ("succeeded",) else "error"
        if job.catalog_item_id:
            await self.state.mark_coverage(
                job.catalog_item_id, job.target, status, job_id=job.id
            )

        for f in job.findings:
            await self._ingest_finding(job, f)

    async def _ingest_finding(self, job: Job, finding) -> None:
        tool = job.tool
        meta = finding.metadata or {}

        # Fingerprints from probe/fingerprint tools.
        if tool == "whatweb":
            plugin = meta.get("plugin")
            if plugin:
                await self.state.add_fingerprint(plugin, source="whatweb")
        elif tool == "httpx":
            for t in meta.get("tech") or []:
                await self.state.add_fingerprint(str(t), source="httpx")
            if meta.get("server"):
                await self.state.add_fingerprint(str(meta["server"]), source="httpx")
        elif tool == "wpscan":
            await self.state.add_fingerprint("wordpress", source="wpscan")

        # New endpoint assets from crawl / archive / content-discovery tools.
        if tool in ("katana", "gau"):
            url = finding.target
            if _looks_like_http_url(url):
                await self.state.add_asset("endpoint", url, source=tool)
        elif tool == "ffuf":
            url = finding.target
            if _looks_like_http_url(url):
                await self.state.add_asset("endpoint", url, source="ffuf")
        elif tool == "subfinder":
            host = finding.target
            if host:
                # New subdomains become host assets (scope gate still applies
                # when an actual scan is submitted against them).
                await self.state.add_asset("host", host, source="subfinder")


def _looks_like_http_url(value: str) -> bool:
    if not value or "://" not in value:
        return False
    scheme = urlparse(value).scheme
    return scheme in ("http", "https")
