"""FastAPI entrypoint for All-Hack.

Storage is Postgres (asyncpg pool, shared by the API and the arq worker).
The mitmproxy addon writes flows synchronously via psycopg using the same
DATABASE_URL.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Importing the storage modules registers their CREATE TABLE statements with
# app.db; init_db() then runs them all in lifespan startup.
import app.audit  # noqa: F401
import app.events  # noqa: F401
import app.llm.usage  # noqa: F401
import app.engagements.storage  # noqa: F401
import app.orchestrator.state  # noqa: F401
import app.orchestrator.runs  # noqa: F401
import app.orchestrator.approvals  # noqa: F401
import app.proxy.storage  # noqa: F401
import app.scans.storage  # noqa: F401
import app.validation.storage  # noqa: F401

from app import db
from app.api.audit import router as audit_router
from app.api.dashboard import router as dashboard_router
from app.api.engagements import router as engagements_router
from app.api.llm import router as llm_router
from app.api.methodology import router as methodology_router
from app.api.orchestrator import router as orchestrator_router
from app.api.proxy import router as proxy_router
from app.api.reports import router as reports_router
from app.api.scans import router as scans_router
from app.api.stream import router as stream_router
from app.config import settings
from app.llm import LLMError, get_llm, get_router, iter_roles


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    await db.init_db()
    yield
    await db.close_pool()


app = FastAPI(title="allhack v2", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/api/config")
async def config() -> dict:
    llm = get_llm()
    return {
        "llm_configured": llm.configured,
        "llm_model": llm.model,
        "llm_fallback_models": llm.fallback_models,
        "llm_roles": get_router().status(),
        "mitm_port": settings.mitm_port,
        "data_dir": str(settings.data_dir),
    }


@app.post("/api/llm/ping")
async def llm_ping(role: str = "planner") -> dict:
    """Sanity-check the LLM client for a given role.

    `role` is one of: planner, executor, validator. Defaults to planner.
    Unknown roles fall back to the legacy single-client behaviour (the
    OpenRouter default) so the Phase 0-3 UI keeps working unmodified.
    """
    if role in iter_roles():
        llm = get_router().get(role)
    else:
        llm = get_llm()
    try:
        reply = await llm.chat(
            [
                {"role": "system", "content": "Respond with only the word: pong"},
                {"role": "user", "content": "ping"},
            ],
            temperature=0.0,
            max_tokens=16,
        )
    except LLMError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "role": role,
        "primary_model": llm.model,
        "model_used": llm.last_used_model or llm.model,
        "fallback_used": (llm.last_used_model or llm.model) != llm.model,
        "reply": reply.strip(),
    }


app.include_router(engagements_router)
app.include_router(orchestrator_router)
app.include_router(proxy_router)
app.include_router(scans_router)
app.include_router(llm_router)
app.include_router(audit_router)
app.include_router(methodology_router)
app.include_router(reports_router)
app.include_router(stream_router)
app.include_router(dashboard_router)
