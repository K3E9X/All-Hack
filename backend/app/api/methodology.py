"""Read-only view of the test catalog (the methodology engine's data)."""
from __future__ import annotations

from fastapi import APIRouter

from app.methodology import CATALOG, PHASE_ORDER

router = APIRouter(prefix="/api/methodology", tags=["methodology"])


@router.get("/catalog")
async def catalog() -> dict:
    return {
        "phases": PHASE_ORDER,
        "count": len(CATALOG),
        "items": [i.to_dict() for i in CATALOG],
    }
