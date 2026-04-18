"""FastAPI entrypoint for v2.

Phase 0 scope: health endpoint, config introspection, LLM ping.
Subsequent phases will add: /api/proxy (MITM session mgmt), /api/scans (wrappers),
/api/llm (analysis/suggestion helpers), /ws/proxy (live request stream).
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.llm import get_llm, LLMError

app = FastAPI(title="allhack v2", version="2.0.0")

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
    """Non-sensitive config view used by the frontend for status indicators."""
    llm = get_llm()
    return {
        "llm_configured": llm.configured,
        "llm_model": llm.model,
        "mitm_port": settings.mitm_port,
        "data_dir": str(settings.data_dir),
    }


@app.post("/api/llm/ping")
async def llm_ping() -> dict:
    """Sanity check: ask the LLM to respond with a fixed string."""
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
