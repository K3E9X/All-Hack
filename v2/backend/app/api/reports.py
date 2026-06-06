"""Report endpoints: Markdown, printable HTML, and JSON metadata."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse

from app.reporting import build_report

router = APIRouter(prefix="/api/engagements", tags=["reports"])


@router.get("/{engagement_id}/report.md", response_class=PlainTextResponse)
async def report_markdown(engagement_id: str) -> PlainTextResponse:
    try:
        report = await build_report(engagement_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="engagement not found")
    return PlainTextResponse(
        report["markdown"],
        headers={"Content-Disposition": f'attachment; filename="report-{engagement_id}.md"'},
    )


@router.get("/{engagement_id}/report.html", response_class=HTMLResponse)
async def report_html(engagement_id: str) -> HTMLResponse:
    try:
        report = await build_report(engagement_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="engagement not found")
    return HTMLResponse(report["html"])


@router.get("/{engagement_id}/report.json")
async def report_json(engagement_id: str) -> dict:
    try:
        report = await build_report(engagement_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="engagement not found")
    return {"meta": report["meta"], "markdown": report["markdown"]}
