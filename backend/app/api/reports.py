"""
Report Generation API

Endpoints for generating vulnerability reports in various formats.
"""

import os
import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.services.report_generator import generate_latex_report, LaTeXReportGenerator, ReportConfig

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])


class Finding(BaseModel):
    """Vulnerability finding model"""
    title: str
    severity: str = "medium"
    category: str = "Unknown"
    description: str = ""
    url: str = ""
    affected_parameter: str = ""
    payload: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    references: List[str] = []


class ReportRequest(BaseModel):
    """Request model for report generation"""
    scan_id: str
    target: str
    findings: List[Finding]
    title: str = "Penetration Testing Report"
    author: str = "All-Hack Security Scanner"
    company: str = ""
    classification: str = "CONFIDENTIAL"
    mode: str = "automated"
    depth: str = "balanced"


class ReportResponse(BaseModel):
    """Response model for report generation"""
    success: bool
    tex_path: Optional[str] = None
    pdf_path: Optional[str] = None
    message: str = ""


@router.post("/generate", response_model=ReportResponse)
async def generate_report(request: ReportRequest):
    """
    Generate a LaTeX vulnerability report.

    Returns paths to the generated .tex and .pdf files.
    """
    try:
        # Convert findings to dict
        findings_data = [f.dict() for f in request.findings]

        # Config
        config = {
            'title': request.title,
            'author': request.author,
            'company': request.company,
            'classification': request.classification,
            'mode': request.mode,
            'depth': request.depth,
        }

        # Generate report
        result = generate_latex_report(
            scan_id=request.scan_id,
            target=request.target,
            findings=findings_data,
            config=config
        )

        return ReportResponse(
            success=True,
            tex_path=result.get('tex_path'),
            pdf_path=result.get('pdf_path'),
            message="Report generated successfully"
        )

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/download/{filename}")
async def download_report(filename: str):
    """
    Download a generated report file.

    Supports both .tex and .pdf files.
    """
    import tempfile

    # Security: validate filename
    if not filename.endswith(('.tex', '.pdf')):
        raise HTTPException(status_code=400, detail="Invalid file type")

    if '..' in filename or '/' in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    filepath = os.path.join(tempfile.gettempdir(), filename)

    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")

    media_type = "application/pdf" if filename.endswith('.pdf') else "application/x-tex"

    return FileResponse(
        filepath,
        media_type=media_type,
        filename=filename
    )


@router.post("/generate-from-scan/{scan_id}", response_model=ReportResponse)
async def generate_report_from_scan(scan_id: str, background_tasks: BackgroundTasks):
    """
    Generate a report from an existing scan.

    Retrieves scan data and findings from the database.
    """
    try:
        # Import here to avoid circular imports
        from app.persistence.scan_storage import get_scan_storage

        storage = get_scan_storage()

        # Get scan data
        scan = await storage.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get findings
        findings = await storage.get_findings(scan_id)

        # Convert to dict format
        findings_data = []
        for f in findings:
            findings_data.append({
                'title': f.title,
                'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                'category': f.category.value if hasattr(f.category, 'value') else str(f.category),
                'description': f.description,
                'url': f.affected_url,
                'affected_parameter': f.affected_parameter or '',
                'payload': f.payload or '',
                'evidence': f.proof_of_concept or '',
                'remediation': f.remediation or '',
                'cwe_id': f.cwe_id or '',
                'owasp_category': f.owasp_category or '',
                'references': f.references or [],
            })

        # Generate report
        result = generate_latex_report(
            scan_id=scan_id,
            target=scan.target_url,
            findings=findings_data,
            config={
                'mode': scan.mode,
                'depth': scan.scan_depth,
            }
        )

        return ReportResponse(
            success=True,
            tex_path=result.get('tex_path'),
            pdf_path=result.get('pdf_path'),
            message=f"Report generated for scan {scan_id}"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report generation from scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates")
async def list_templates():
    """
    List available report templates.
    """
    return {
        "templates": [
            {
                "id": "standard",
                "name": "Standard Report",
                "description": "Full penetration testing report with all sections"
            },
            {
                "id": "executive",
                "name": "Executive Summary",
                "description": "High-level summary for management"
            },
            {
                "id": "technical",
                "name": "Technical Report",
                "description": "Detailed technical findings with PoCs"
            }
        ]
    }
