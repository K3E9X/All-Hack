"""Shared arq/Redis pool helpers.

Kept in its own module so both the API side (app.scans.runner,
app.api.orchestrator) and the worker (app.workers) can import the pool
without creating an import cycle (workers imports the orchestrator loop,
which imports the runner, which needs the pool).
"""
from __future__ import annotations

from typing import Optional

from arq.connections import ArqRedis, RedisSettings, create_pool

from app.config import settings

_arq_pool: Optional[ArqRedis] = None


def redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(settings.redis_url)


async def get_arq_pool() -> ArqRedis:
    """Return the shared arq pool, creating it on first use."""
    global _arq_pool
    if _arq_pool is None:
        _arq_pool = await create_pool(redis_settings())
    return _arq_pool


async def close_arq_pool() -> None:
    global _arq_pool
    if _arq_pool is not None:
        await _arq_pool.close()
        _arq_pool = None
