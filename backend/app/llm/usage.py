"""LLM token / cost accounting.

Every chat() call records its token usage against the engagement that is
currently in scope (set via the `current_engagement` contextvar by the
orchestrator loop and the per-request API handlers). Cost is taken from the
provider response when present (OpenRouter can return `usage.cost`), otherwise
estimated from configurable per-model pricing (default 0, so free models read
as $0 while still showing tokens).
"""
from __future__ import annotations

import contextvars
import logging
import time
from typing import Any, Dict, Optional

from app import db
from app.config import settings

logger = logging.getLogger("syphax.llm.usage")

# Set by the loop / API handlers so chat() knows what to bill.
current_engagement: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_engagement", default=None
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS llm_usage (
    id                BIGSERIAL PRIMARY KEY,
    engagement_id     TEXT,
    ts                DOUBLE PRECISION NOT NULL,
    role              TEXT,
    model             TEXT,
    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd          DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_llm_usage_engagement ON llm_usage(engagement_id);
"""

db.register_schema(SCHEMA_SQL)


def _price_map() -> Dict[str, tuple]:
    """Parse LLM_PRICING from settings: 'model=in/out,model2=in/out' where
    in/out are USD per 1M tokens. Returns {model: (in_per_1m, out_per_1m)}."""
    raw = getattr(settings, "llm_pricing", "") or ""
    out: Dict[str, tuple] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        model, rates = entry.split("=", 1)
        try:
            inp, outp = rates.split("/", 1)
            out[model.strip()] = (float(inp), float(outp))
        except ValueError:
            continue
    return out


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    rates = _price_map().get(model)
    if not rates:
        return 0.0
    inp, outp = rates
    return (prompt_tokens / 1_000_000) * inp + (completion_tokens / 1_000_000) * outp


async def record(
    *,
    role: Optional[str],
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    cost_usd: Optional[float] = None,
) -> None:
    """Record one LLM call's usage against the current engagement (best-effort)."""
    engagement_id = current_engagement.get()
    if cost_usd is None:
        cost_usd = estimate_cost(model, prompt_tokens, completion_tokens)
    try:
        async with db.acquire() as conn:
            await conn.execute(
                "INSERT INTO llm_usage (engagement_id, ts, role, model, "
                "prompt_tokens, completion_tokens, cost_usd) VALUES ($1,$2,$3,$4,$5,$6,$7)",
                engagement_id, time.time(), role, model,
                int(prompt_tokens), int(completion_tokens), float(cost_usd),
            )
    except Exception:  # noqa: BLE001
        logger.exception("llm usage record failed for model %s", model)


async def summary(engagement_id: str) -> Dict[str, Any]:
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS calls, "
            "COALESCE(SUM(prompt_tokens),0) AS prompt, "
            "COALESCE(SUM(completion_tokens),0) AS completion, "
            "COALESCE(SUM(cost_usd),0) AS cost "
            "FROM llm_usage WHERE engagement_id=$1",
            engagement_id,
        )
    return {
        "calls": int(row["calls"]),
        "prompt_tokens": int(row["prompt"]),
        "completion_tokens": int(row["completion"]),
        "total_tokens": int(row["prompt"]) + int(row["completion"]),
        "cost_usd": round(float(row["cost"]), 4),
    }
