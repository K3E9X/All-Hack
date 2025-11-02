"""Utilities to invoke external tooling during scans."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


class ExternalToolHookRunner:
    """Run configured shell commands after specific scan phases."""

    def __init__(self, hooks: Optional[Iterable[Dict[str, Any]]] = None):
        self.hooks = list(hooks or [])

    async def run_phase_hooks(self, phase: str, context: Dict[str, Any]) -> None:
        matching_hooks = [hook for hook in self.hooks if hook.get("phase") == phase]
        if not matching_hooks:
            return

        logger.info("Running %s external hook(s) for phase %s", len(matching_hooks), phase)
        await asyncio.gather(
            *[
                self._run_hook(hook, context)
                for hook in matching_hooks
            ],
            return_exceptions=True,
        )

    async def _run_hook(self, hook: Dict[str, Any], context: Dict[str, Any]) -> None:
        command = hook.get("command")
        if not command:
            return

        timeout = int(hook.get("timeout", 300))
        env = os.environ.copy()
        env["SCAN_CONTEXT"] = json.dumps(context, default=str)

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                process.kill()
                logger.warning("External hook timed out: %s", command)
                return

            if stdout:
                logger.debug("Hook output (%s): %s", command, stdout.decode(errors="ignore"))
            if stderr:
                logger.debug("Hook error (%s): %s", command, stderr.decode(errors="ignore"))

        except Exception as exc:  # pragma: no cover - defensive
            logger.error("External hook failed (%s): %s", command, exc)

