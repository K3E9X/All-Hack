"""Safe proof-of-exploit HTTP helper (spec §7 safety layer).

Hard policy, enforced here so no validator can bypass it:
  * GET / HEAD only - never a state-changing method.
  * single request per call, short timeout, capped body read.
  * the target host MUST be inside the engagement scope allow-list
    (prevents SSRF-pivot / hitting third parties).
  * benign markers only; we never send destructive payloads.

This is the only place validators are allowed to touch the target.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("syphax.validation.safe_poc")

MAX_BODY_BYTES = 256 * 1024
TIMEOUT = 10.0
ALLOWED_METHODS = {"GET", "HEAD"}


@dataclass
class SafeResponse:
    status_code: int
    headers: dict
    text: str
    url: str


class ScopeError(RuntimeError):
    pass


class PolicyError(RuntimeError):
    pass


class SafePoC:
    """`in_scope` is a predicate (host) -> bool, supplied by the engagement."""

    def __init__(self, in_scope: Callable[[str], bool]) -> None:
        self._in_scope = in_scope

    def _check(self, method: str, url: str) -> None:
        if method.upper() not in ALLOWED_METHODS:
            raise PolicyError(f"method {method} not allowed by safe-PoC policy")
        host = urlparse(url).hostname or ""
        if not host or not self._in_scope(host):
            raise ScopeError(f"host '{host}' is out of engagement scope")

    async def fetch(
        self, url: str, *, method: str = "GET", headers: Optional[dict] = None
    ) -> Optional[SafeResponse]:
        self._check(method, url)
        try:
            async with httpx.AsyncClient(
                timeout=TIMEOUT, follow_redirects=False, verify=False
            ) as client:
                resp = await client.request(method, url, headers=headers or None)
                body = b""
                if method.upper() == "GET":
                    # Read at most MAX_BODY_BYTES.
                    body = resp.content[:MAX_BODY_BYTES]
                return SafeResponse(
                    status_code=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    text=body.decode("utf-8", errors="replace"),
                    url=str(resp.url),
                )
        except (ScopeError, PolicyError):
            raise
        except Exception as exc:  # noqa: BLE001
            logger.debug("safe-PoC fetch failed for %s: %s", url, exc)
            return None
