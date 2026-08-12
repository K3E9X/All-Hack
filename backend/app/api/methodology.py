"""Read-only view of the test catalog (the methodology engine's data)."""
from __future__ import annotations

from fastapi import APIRouter

from app.methodology import CATALOG, PHASE_ORDER

router = APIRouter(prefix="/api/methodology", tags=["methodology"])


@router.get("/catalog")
async def catalog() -> dict:
    """Every test the engine can run, grouped the same way the coverage view
    groups them so the two screens stay consistent."""
    from app.coverage_util import catalog_entries

    return {
        "phases": PHASE_ORDER,
        "count": len(CATALOG),
        "items": catalog_entries(CATALOG),
    }
