"""POST /api/sandbox/run - re-run a PoC, safely.

Guardrails (HANDOFF section 6):
  * the engagement must be AUTHORIZED and the target IN SCOPE (refused otherwise);
  * read-only only: HTTP PoCs go through the SafePoC channel (GET/HEAD, in-scope,
    capped body) - state-changing methods are refused;
  * arbitrary code PoCs (python/javascript) require a dedicated isolated,
    egress-scoped container which is not enabled here, so they are refused
    rather than executed unsafely.
"""
from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.audit import audit
from app.engagements import EngagementRepository, EngagementStatus
from app.sandbox_util import parse_poc
from app.validation.safe_poc import PolicyError, SafePoC, ScopeError

router = APIRouter(tags=["sandbox"])

_engagements = EngagementRepository()
_SAFE_METHODS = {"GET", "HEAD"}


class SandboxRequest(BaseModel):
    type: str           # curl | http-raw | python | javascript
    target: str = ""
    code: str = ""
    engagement_id: str


@router.post("/api/sandbox/run")
async def run(req: SandboxRequest) -> Dict[str, Any]:
    eng = await _engagements.get(req.engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    if eng.status != EngagementStatus.AUTHORIZED:
        raise HTTPException(status_code=403, detail="engagement is not authorized")

    if req.type in ("python", "javascript"):
        await audit("sandbox.refused_code", engagement_id=eng.id, type=req.type)
        return {"verdict": "skipped", "code": None, "time_ms": 0, "req": "", "resp": "",
                "result": (f"{req.type} PoCs need the isolated code-runner container, "
                           "which is not enabled in this deployment. Use a curl or "
                           "http-raw PoC for safe in-scope replay.")}

    method, url, headers = parse_poc(req.type, req.code, req.target)
    if not url:
        raise HTTPException(status_code=400, detail="no target URL found in the PoC")
    if method.upper() not in _SAFE_METHODS:
        await audit("sandbox.refused_method", engagement_id=eng.id, method=method, url=url)
        return {"verdict": "refused", "code": None, "time_ms": 0,
                "req": f"{method} {url}", "resp": "",
                "result": f"Refused: {method} is state-changing. The sandbox is "
                          "read-only (GET/HEAD only)."}

    safe = SafePoC(in_scope=eng.host_in_scope)
    started = time.time()
    try:
        resp = await safe.fetch(url, method=method.upper(), headers=headers or None)
    except ScopeError:
        await audit("sandbox.refused_scope", engagement_id=eng.id, url=url)
        return {"verdict": "refused", "code": None, "time_ms": 0,
                "req": f"{method} {url}", "resp": "",
                "result": "Refused: target is out of the engagement scope."}
    except PolicyError as exc:
        return {"verdict": "refused", "code": None, "time_ms": 0,
                "req": f"{method} {url}", "resp": "", "result": f"Refused: {exc}"}
    elapsed = int((time.time() - started) * 1000)

    if resp is None:
        return {"verdict": "error", "code": None, "time_ms": elapsed,
                "req": f"{method} {url}", "resp": "", "result": "target not reachable"}

    await audit("sandbox.run", engagement_id=eng.id, method=method, url=url,
                status=resp.status_code)
    hdrs = "\n".join(f"{k}: {v}" for k, v in list(resp.headers.items())[:30])
    body = resp.text[:4000]
    req_repr = f"{method} {url}\n" + "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    return {
        "verdict": "executed" if resp.status_code < 400 else "executed (error status)",
        "code": resp.status_code,
        "time_ms": elapsed,
        "req": req_repr.strip(),
        "resp": f"HTTP {resp.status_code}\n{hdrs}\n\n{body}",
        "result": f"in-scope read-only request completed (HTTP {resp.status_code})",
    }
