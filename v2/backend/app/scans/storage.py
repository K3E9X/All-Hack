"""Persistence for scan jobs. Shares the SQLite file with the proxy capture."""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator, List, Optional

import aiosqlite

from app.scans.models import Finding, Job, JobStatus, findings_from_json, findings_to_json

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id             TEXT PRIMARY KEY,
    tool           TEXT NOT NULL,
    target         TEXT NOT NULL,
    args_json      TEXT NOT NULL,
    status         TEXT NOT NULL,
    created_at     REAL NOT NULL,
    started_at     REAL,
    finished_at    REAL,
    exit_code      INTEGER,
    stdout         BLOB,
    stderr         BLOB,
    findings_json  TEXT,
    flow_id        TEXT,
    error          TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status  ON jobs(status);
"""


def init_jobs_schema(db_path: Path) -> None:
    """Create the `jobs` table. Safe to call repeatedly."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


class JobRepository:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    @asynccontextmanager
    async def _connect(self) -> AsyncIterator[aiosqlite.Connection]:
        # aiosqlite's connect() returns an awaitable-and-context-manager. If we
        # both `await` it here AND wrap it in an `async with` at the call site,
        # aiosqlite's background thread gets `.start()` twice, raising
        # "threads can only be started once". Use this helper as the single
        # async context manager and call sites do `async with self._connect()`.
        conn = await aiosqlite.connect(str(self.db_path))
        try:
            await conn.execute("PRAGMA journal_mode=WAL;")
            conn.row_factory = aiosqlite.Row
            yield conn
        finally:
            await conn.close()

    async def create(self, job: Job) -> None:
        async with self._connect() as conn:
            await conn.execute(
                """
                INSERT INTO jobs (
                    id, tool, target, args_json, status, created_at, started_at,
                    finished_at, exit_code, stdout, stderr, findings_json, flow_id, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job.id,
                    job.tool,
                    job.target,
                    json.dumps(job.args),
                    job.status.value,
                    job.created_at,
                    job.started_at,
                    job.finished_at,
                    job.exit_code,
                    job.stdout,
                    job.stderr,
                    findings_to_json(job.findings),
                    job.flow_id,
                    job.error,
                ),
            )
            await conn.commit()

    async def update(self, job: Job) -> None:
        async with self._connect() as conn:
            await conn.execute(
                """
                UPDATE jobs SET
                    status = ?,
                    started_at = ?,
                    finished_at = ?,
                    exit_code = ?,
                    stdout = ?,
                    stderr = ?,
                    findings_json = ?,
                    error = ?
                WHERE id = ?
                """,
                (
                    job.status.value,
                    job.started_at,
                    job.finished_at,
                    job.exit_code,
                    job.stdout,
                    job.stderr,
                    findings_to_json(job.findings),
                    job.error,
                    job.id,
                ),
            )
            await conn.commit()

    async def get(self, job_id: str) -> Optional[Job]:
        async with self._connect() as conn:
            cursor = await conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
            row = await cursor.fetchone()
        return _row_to_job(row) if row else None

    async def list(self, *, limit: int = 100, offset: int = 0) -> List[Job]:
        async with self._connect() as conn:
            cursor = await conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            rows = await cursor.fetchall()
        return [_row_to_job(row) for row in rows]

    async def count(self) -> int:
        async with self._connect() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM jobs")
            (n,) = await cursor.fetchone()
            return int(n)

    async def delete(self, job_id: str) -> bool:
        async with self._connect() as conn:
            cursor = await conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
            await conn.commit()
            return (cursor.rowcount or 0) > 0


def _row_to_job(row) -> Job:
    try:
        args = json.loads(row["args_json"] or "[]")
    except json.JSONDecodeError:
        args = []
    return Job(
        id=row["id"],
        tool=row["tool"],
        target=row["target"],
        args=args,
        status=JobStatus(row["status"]),
        created_at=row["created_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        exit_code=row["exit_code"],
        stdout=row["stdout"] or b"",
        stderr=row["stderr"] or b"",
        findings=findings_from_json(row["findings_json"]),
        flow_id=row["flow_id"],
        error=row["error"],
    )


def new_job_id() -> str:
    return f"job_{int(time.time()*1000)}"
