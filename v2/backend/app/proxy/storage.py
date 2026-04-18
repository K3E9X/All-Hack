"""SQLite schema and data access for captured HTTP flows.

We keep two paths into the database on purpose:

  - `init_schema()`           - synchronous, run at startup and from the addon.
  - async `FlowRepository`    - used by the FastAPI endpoints (aiosqlite).
  - `insert_flow_sync()`      - called by the mitmproxy addon (stdlib sqlite3).

SQLite is opened in WAL mode so the addon process and the API process can
read/write concurrently without blocking each other.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id                     TEXT PRIMARY KEY,
    timestamp              REAL NOT NULL,
    duration_ms            INTEGER,
    method                 TEXT NOT NULL,
    scheme                 TEXT,
    host                   TEXT NOT NULL,
    port                   INTEGER,
    path                   TEXT NOT NULL,
    url                    TEXT NOT NULL,
    request_headers_json   TEXT,
    request_body           BLOB,
    request_content_type   TEXT,
    request_size           INTEGER,
    status_code            INTEGER,
    response_headers_json  TEXT,
    response_body          BLOB,
    response_content_type  TEXT,
    response_size          INTEGER,
    tag                    TEXT
);

CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_flows_host      ON flows(host);
CREATE INDEX IF NOT EXISTS idx_flows_status    ON flows(status_code);
"""


def init_schema(db_path: Path) -> None:
    """Create the schema and enable WAL. Safe to call from any process."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


# ----- sync path (mitmproxy addon) -----

def insert_flow_sync(db_path: Path, row: Dict[str, Any]) -> None:
    """Insert a single captured flow. Called from the mitmproxy process."""
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            """
            INSERT OR REPLACE INTO flows (
                id, timestamp, duration_ms, method, scheme, host, port, path, url,
                request_headers_json, request_body, request_content_type, request_size,
                status_code,
                response_headers_json, response_body, response_content_type, response_size,
                tag
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["id"],
                row["timestamp"],
                row.get("duration_ms"),
                row["method"],
                row.get("scheme"),
                row["host"],
                row.get("port"),
                row["path"],
                row["url"],
                row.get("request_headers_json"),
                row.get("request_body"),
                row.get("request_content_type"),
                row.get("request_size"),
                row.get("status_code"),
                row.get("response_headers_json"),
                row.get("response_body"),
                row.get("response_content_type"),
                row.get("response_size"),
                row.get("tag"),
            ),
        )
        conn.commit()
    finally:
        conn.close()


# ----- async path (FastAPI endpoints) -----

MAX_BODY_PREVIEW = 256 * 1024  # bytes returned by /requests/{id}


@dataclass
class FlowSummary:
    id: str
    timestamp: float
    method: str
    host: str
    path: str
    url: str
    status_code: Optional[int]
    response_size: Optional[int]
    duration_ms: Optional[int]
    request_content_type: Optional[str]
    response_content_type: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


class FlowRepository:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    @asynccontextmanager
    async def _connect(self) -> AsyncIterator[aiosqlite.Connection]:
        # aiosqlite.connect() is both awaitable and a context manager; using
        # `async with await ...` would start its background thread twice and
        # raise "threads can only be started once" on subsequent calls. Own
        # the lifecycle here and close explicitly.
        conn = await aiosqlite.connect(str(self.db_path))
        try:
            await conn.execute("PRAGMA journal_mode=WAL;")
            conn.row_factory = aiosqlite.Row
            yield conn
        finally:
            await conn.close()

    async def list_flows(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
        host: Optional[str] = None,
        method: Optional[str] = None,
        status_min: Optional[int] = None,
        status_max: Optional[int] = None,
        search: Optional[str] = None,
    ) -> List[FlowSummary]:
        where: List[str] = []
        params: List[Any] = []

        if host:
            where.append("host = ?")
            params.append(host)
        if method:
            where.append("method = ?")
            params.append(method.upper())
        if status_min is not None:
            where.append("status_code >= ?")
            params.append(status_min)
        if status_max is not None:
            where.append("status_code <= ?")
            params.append(status_max)
        if search:
            where.append("url LIKE ?")
            params.append(f"%{search}%")

        where_sql = f" WHERE {' AND '.join(where)}" if where else ""
        params.extend([limit, offset])

        sql = (
            "SELECT id, timestamp, method, host, path, url, status_code, "
            "response_size, duration_ms, request_content_type, response_content_type "
            f"FROM flows{where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        )

        async with self._connect() as conn:
            cursor = await conn.execute(sql, params)
            rows = await cursor.fetchall()

        return [FlowSummary(**dict(row)) for row in rows]

    async def count_flows(self) -> int:
        async with self._connect() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM flows")
            (n,) = await cursor.fetchone()
            return int(n)

    async def list_hosts(self) -> List[Dict[str, Any]]:
        async with self._connect() as conn:
            cursor = await conn.execute(
                "SELECT host, COUNT(*) AS count FROM flows GROUP BY host ORDER BY count DESC"
            )
            rows = await cursor.fetchall()
        return [{"host": row["host"], "count": row["count"]} for row in rows]

    async def get_flow(self, flow_id: str) -> Optional[Dict[str, Any]]:
        async with self._connect() as conn:
            cursor = await conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,))
            row = await cursor.fetchone()
        if row is None:
            return None

        data = dict(row)

        # Parse JSON headers
        data["request_headers"] = _safe_json(data.pop("request_headers_json"))
        data["response_headers"] = _safe_json(data.pop("response_headers_json"))

        # Decode body preview (text if it looks like text, else hex note)
        data["request_body_preview"] = _body_preview(
            data.pop("request_body"), data.get("request_content_type")
        )
        data["response_body_preview"] = _body_preview(
            data.pop("response_body"), data.get("response_content_type")
        )

        return data

    async def delete_all(self) -> int:
        async with self._connect() as conn:
            cursor = await conn.execute("DELETE FROM flows")
            await conn.commit()
            return cursor.rowcount or 0


def _safe_json(raw: Optional[str]) -> List[List[str]]:
    if not raw:
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return []


def _body_preview(body: Optional[bytes], content_type: Optional[str]) -> Dict[str, Any]:
    """Return a safe, size-capped view of a body for the UI."""
    if body is None:
        return {"present": False, "size": 0}

    size = len(body)
    truncated = size > MAX_BODY_PREVIEW
    view = body[:MAX_BODY_PREVIEW]

    is_text = False
    if content_type:
        lower = content_type.lower()
        is_text = (
            lower.startswith("text/")
            or "json" in lower
            or "xml" in lower
            or "javascript" in lower
            or "html" in lower
            or "form-urlencoded" in lower
        )

    if is_text:
        try:
            return {
                "present": True,
                "size": size,
                "truncated": truncated,
                "encoding": "text",
                "text": view.decode("utf-8", errors="replace"),
            }
        except Exception:
            pass

    # Fallback: hex for the first few KB.
    hex_cap = 8 * 1024
    return {
        "present": True,
        "size": size,
        "truncated": truncated,
        "encoding": "hex",
        "hex": view[:hex_cap].hex(),
        "hex_truncated": size > hex_cap,
    }
