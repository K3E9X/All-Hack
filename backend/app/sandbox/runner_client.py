"""Client for the isolated sandbox runner.

The backend never executes untrusted code itself and never talks to Docker to
arrange it - handing the backend a Docker socket would trade "untrusted code
runs in a container" for "the service holding every API key can take the host",
which is a worse deal. Instead it POSTs the code to a service on a private
network and reads the result back.

Two refusals live here, and both are deliberate:

  * If the runner reports its egress was never locked, no work is sent. A
    sandbox that silently allows the whole internet looks identical to a
    working one right up until a trojaned PoC uses it.
  * If the caller passes no scope, nothing is sent. "Run this anywhere" is
    never what an engagement means.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

import httpx

logger = logging.getLogger("syphax.sandbox.runner_client")

RUNNER_URL = os.environ.get("SANDBOX_RUNNER_URL", "http://sandbox-runner:8090")
CONNECT_TIMEOUT = 5.0

LANGUAGES = {"python", "bash", "javascript"}


class SandboxUnavailable(RuntimeError):
    """The runner is absent, unhealthy, or its egress was never pinned."""


@dataclass
class SandboxResult:
    exit_code: Optional[int]
    timed_out: bool
    duration_s: float
    stdout: str
    stderr: str
    scope_hosts: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_s": self.duration_s,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "scope_hosts": self.scope_hosts,
        }


async def health() -> Dict[str, Any]:
    """Runner status, including whether its egress policy actually applied."""
    async with httpx.AsyncClient(timeout=CONNECT_TIMEOUT) as client:
        resp = await client.get(f"{RUNNER_URL}/health")
        resp.raise_for_status()
        return resp.json() or {}


async def is_available() -> bool:
    try:
        return bool((await health()).get("status") == "ok")
    except Exception as exc:  # noqa: BLE001 - absent runner is a normal state
        logger.debug("sandbox runner unavailable: %s", exc)
        return False


async def run_poc(code: str, *, language: str = "python",
                  scope_hosts: Sequence[str], argv: Optional[Sequence[str]] = None,
                  timeout: int = 60) -> SandboxResult:
    """Execute an approved PoC in the isolated runner.

    Everything upstream - inspection, operator review, approval - has already
    happened. This is the last hop, and it still refuses two things.
    """
    if language not in LANGUAGES:
        raise ValueError(f"language must be one of {sorted(LANGUAGES)}")
    if not (code or "").strip():
        raise ValueError("empty code")

    hosts = [h for h in (scope_hosts or []) if (h or "").strip()]
    if not hosts:
        # Without a scope there is nothing to pin egress to, and "run this
        # against anything" is never what an engagement authorises.
        raise ValueError("scope_hosts is required: refusing to run with no scope")

    try:
        status = await health()
    except Exception as exc:  # noqa: BLE001
        raise SandboxUnavailable(
            f"sandbox runner not reachable at {RUNNER_URL}: {exc}") from exc

    if not status.get("egress_locked"):
        raise SandboxUnavailable(
            "sandbox runner started without an egress policy - refusing to run "
            "untrusted code with unrestricted outbound access")

    payload = {"code": code, "language": language, "timeout": int(timeout),
               "argv": [str(a) for a in (argv or [])], "scope_hosts": hosts}

    # Generous read timeout: the PoC's own timeout is enforced runner-side, and
    # cutting the HTTP call early would lose the output we came for.
    async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout + 30, connect=CONNECT_TIMEOUT)) as client:
        resp = await client.post(f"{RUNNER_URL}/v1/run", json=payload)
        resp.raise_for_status()
        data = resp.json() or {}

    return SandboxResult(
        exit_code=data.get("exit_code"),
        timed_out=bool(data.get("timed_out")),
        duration_s=float(data.get("duration_s") or 0.0),
        stdout=str(data.get("stdout") or ""),
        stderr=str(data.get("stderr") or ""),
        scope_hosts=list(data.get("scope_hosts") or hosts),
    )
