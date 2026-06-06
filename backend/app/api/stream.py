"""WebSocket live event stream for an engagement (spec §10).

Tails the append-only `events` table and pushes new rows to the browser.
Polling Postgres (every ~1s) instead of Redis pub/sub keeps the worker->API
hop trivial and lets a client backfill from any event id on reconnect.
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app import events as events_log

router = APIRouter(tags=["stream"])

logger = logging.getLogger("allhack.stream")

POLL_INTERVAL = 1.0


@router.websocket("/ws/engagements/{engagement_id}/stream")
async def engagement_stream(websocket: WebSocket, engagement_id: str) -> None:
    await websocket.accept()
    # Allow the client to resume from a known id: ?after=<id>
    try:
        after_id = int(websocket.query_params.get("after", "0"))
    except (TypeError, ValueError):
        after_id = 0

    try:
        while True:
            events = await events_log.list_since(engagement_id, after_id, limit=200)
            for ev in events:
                await websocket.send_json(ev)
                after_id = ev["id"]
            await asyncio.sleep(POLL_INTERVAL)
    except WebSocketDisconnect:
        return
    except Exception:  # noqa: BLE001
        logger.exception("stream error for engagement %s", engagement_id)
        try:
            await websocket.close()
        except Exception:  # noqa: BLE001
            pass
