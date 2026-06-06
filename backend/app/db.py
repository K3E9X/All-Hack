"""Postgres connection helpers.

Two code paths share the same DATABASE_URL:

  - async `get_pool()` / `acquire()` for FastAPI endpoints and the arq worker
    (asyncpg pool).
  - sync `sync_connect()` for the mitmproxy addon, which runs in its own
    non-asyncio process and writes a flow per response.

Schema bootstrap is centralised here: every domain module exposes a
`SCHEMA_SQL` string and registers it via `register_schema()` so that
`init_db()` can run them in order at startup.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator, List, Optional

import asyncpg

from app.config import settings

_pool: Optional[asyncpg.Pool] = None
_schemas: List[str] = []


def register_schema(sql: str) -> None:
    """Register a CREATE TABLE ... block to run at startup. Idempotent."""
    if sql not in _schemas:
        _schemas.append(sql)


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            dsn=settings.database_url,
            min_size=1,
            max_size=10,
            command_timeout=60,
        )
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


@asynccontextmanager
async def acquire() -> AsyncIterator[asyncpg.Connection]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        yield conn


async def init_db() -> None:
    """Run every registered schema. Safe to call repeatedly."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        for sql in _schemas:
            await conn.execute(sql)


# ----- sync path for processes that are not asyncio-native -----

def sync_connect():
    """Return a sync psycopg3 connection. Caller is responsible for closing."""
    import psycopg
    return psycopg.connect(settings.database_url, autocommit=False)
