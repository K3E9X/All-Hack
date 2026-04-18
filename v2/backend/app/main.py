"""FastAPI entrypoint for v2.

Phase 0: health, config, LLM ping.
Phase 1: MITM proxy capture + flow inspection (see app/api/proxy.py).
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.api.llm import router as llm_router
from app.api.proxy import router as proxy_router
from app.api.scans import router as scans_router
from app.config import settings
from app.llm import LLMError, get_llm
from app.proxy import init_schema
from app.scans import init_jobs_schema


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    # Make sure the shared SQLite DB exists before the addon or the API touches it.
    init_schema(settings.sqlite_path)
    init_jobs_schema(settings.sqlite_path)
    yield


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
        "mitm_port": settings.mitm_port,
        "data_dir": str(settings.data_dir),
    }


@app.post("/api/llm/ping")
async def llm_ping() -> dict:
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
    return {"model": llm.model, "reply": reply.strip()}


app.include_router(proxy_router)
app.include_router(scans_router)
app.include_router(llm_router)
