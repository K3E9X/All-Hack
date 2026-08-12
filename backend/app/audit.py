"""Append-only audit log (spec §8).

Every security-relevant action - engagement created/authorized, scan
submitted, scan blocked by the scope gate - lands here. The table is
insert-only by convention: no code path updates or deletes rows, so it
stays defensible as a record of who tested what, when, under which proof.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from app import db

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    ts          DOUBLE PRECISION NOT NULL,
    action      TEXT NOT NULL,
    engagement_id TEXT,
    detail_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts            ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_engagement    ON audit_log(engagement_id);
CREATE INDEX IF NOT EXISTS idx_audit_action        ON audit_log(action);
"""

db.register_schema(SCHEMA_SQL)


async def audit(action: str, *, engagement_id: Optional[str] = None, **detail: Any) -> None:
    """Record one audit event. Never raises into the caller - audit failure
    must not break the action being audited (but it is logged)."""
    try:
        async with db.acquire() as conn:
            await conn.execute(
                "INSERT INTO audit_log (ts, action, engagement_id, detail_json) "
                "VALUES ($1, $2, $3, $4)",
                time.time(),
                action,
                engagement_id,
                json.dumps(detail, default=str) if detail else None,
            )
    except Exception:  # noqa: BLE001
        import logging

        logging.getLogger("syphax.audit").exception("audit write failed: %s", action)


async def list_events(
    *, engagement_id: Optional[str] = None, limit: int = 200, offset: int = 0
) -> List[Dict[str, Any]]:
    where = ""
    params: List[Any] = []
    if engagement_id:
        where = "WHERE engagement_id = $1"
        params.append(engagement_id)
        params.extend([limit, offset])
        sql = f"SELECT * FROM audit_log {where} ORDER BY ts DESC LIMIT $2 OFFSET $3"
    else:
        params.extend([limit, offset])
        sql = "SELECT * FROM audit_log ORDER BY ts DESC LIMIT $1 OFFSET $2"

    async with db.acquire() as conn:
        rows = await conn.fetch(sql, *params)

    out = []
    for r in rows:
        detail = {}
        if r["detail_json"]:
            try:
                detail = json.loads(r["detail_json"])
            except json.JSONDecodeError:
                detail = {"_raw": r["detail_json"]}
        out.append(
            {
                "id": r["id"],
                "ts": r["ts"],
                "action": r["action"],
                "engagement_id": r["engagement_id"],
                "detail": detail,
            }
        )
    return out
