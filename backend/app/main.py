"""
Advanced Pentest Tool - FastAPI Backend
"""
import logging
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from app.config import settings
from app.models import ScanRequest, ScanResult, ScanProgress, PlaybookRequest, PlaybookRun
from app.scanner_orchestrator import ScanOrchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global orchestrator instance
orchestrator = ScanOrchestrator()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan events"""
    logger.info("Starting Advanced Pentest Tool API")
    yield
    logger.info("Shutting down Advanced Pentest Tool API")

# Create FastAPI app
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="Advanced automated web application penetration testing tool",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Advanced Pentest Tool API",
        "version": settings.API_VERSION,
        "status": "running"
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.post(f"{settings.API_PREFIX}/scans", response_model=dict)
async def create_scan(scan_request: ScanRequest):
    """
    Start a new security scan

    **Scan Modes:**
    - `black_box`: External testing without authentication
    - `grey_box`: Testing with credentials and partial knowledge

    **Important:** Only use this tool on applications you own or have explicit permission to test.
    """
    try:
        logger.info(f"Received scan request for: {scan_request.target_url}")

        # Validate URL
        if not scan_request.target_url:
            raise HTTPException(status_code=400, detail="Target URL is required")

        # Start the scan
        scan_id = await orchestrator.start_scan(scan_request)

        return {
            "scan_id": scan_id,
            "message": "Scan started successfully",
            "target_url": scan_request.target_url,
            "mode": scan_request.mode
        }

    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get(f"{settings.API_PREFIX}/scans/{{scan_id}}", response_model=ScanResult)
async def get_scan_result(scan_id: str):
    """
    Get scan results by scan ID

    Returns the complete scan results including:
    - Discovered vulnerabilities
    - Security misconfigurations
    - Discovered endpoints
    - Detected technologies
    """
    result = orchestrator.get_scan_result(scan_id)

    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    return result

@app.get(f"{settings.API_PREFIX}/scans/{{scan_id}}/status")
async def get_scan_status(scan_id: str):
    """Get scan status"""
    result = orchestrator.get_scan_result(scan_id)

    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    progress = 0.0
    if result.status == "reconnaissance":
        progress = 25.0
    elif result.status == "owasp_scanning":
        progress = 50.0
    elif result.status == "access_control_testing":
        progress = 75.0
    elif result.status == "misconfiguration_scanning":
        progress = 90.0
    elif result.status == "completed":
        progress = 100.0

    return {
        "scan_id": scan_id,
        "status": result.status,
        "progress": progress,
        "current_phase": result.status,
        "vulnerabilities_found": len(result.vulnerabilities),
        "misconfigurations_found": len(result.misconfigurations),
        "recent_events": [event.model_dump() for event in (result.timeline[-5:] if result.timeline else [])]
    }


@app.post(f"{settings.API_PREFIX}/playbooks", response_model=PlaybookRun)
async def create_playbook(playbook: PlaybookRequest):
    """Start a playbook consisting of multiple scans."""
    run = await orchestrator.start_playbook(playbook)
    return run


@app.get(f"{settings.API_PREFIX}/playbooks/{{playbook_id}}")
async def get_playbook(playbook_id: str):
    run = orchestrator.get_playbook(playbook_id)
    if not run:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return run


@app.get(f"{settings.API_PREFIX}/scans/{{scan_id}}/report")
async def download_report(scan_id: str):
    try:
        report = orchestrator.generate_report(scan_id)
        return report
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get(f"{settings.API_PREFIX}/scans/compare")
async def compare_scans(scan_a: str = Query(...), scan_b: str = Query(...)):
    try:
        comparison = orchestrator.compare_scans(scan_a, scan_b)
        return comparison
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

@app.get(f"{settings.API_PREFIX}/scans/{{scan_id}}/vulnerabilities")
async def get_vulnerabilities(scan_id: str, severity: str = None):
    """Get vulnerabilities for a scan, optionally filtered by severity"""
    result = orchestrator.get_scan_result(scan_id)

    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulnerabilities = result.vulnerabilities

    if severity:
        vulnerabilities = [v for v in vulnerabilities if v.severity.value == severity.lower()]

    return {
        "scan_id": scan_id,
        "total": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }

@app.get(f"{settings.API_PREFIX}/scans/{{scan_id}}/misconfigurations")
async def get_misconfigurations(scan_id: str):
    """Get security misconfigurations for a scan"""
    result = orchestrator.get_scan_result(scan_id)

    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_id,
        "total": len(result.misconfigurations),
        "misconfigurations": result.misconfigurations
    }

@app.get(f"{settings.API_PREFIX}/scans/{{scan_id}}/summary")
async def get_scan_summary(scan_id: str):
    """Get scan summary with statistics"""
    result = orchestrator.get_scan_result(scan_id)

    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_id,
        "target_url": result.target_url,
        "mode": result.mode,
        "status": result.status,
        "start_time": result.start_time,
        "end_time": result.end_time,
        "scan_duration": result.scan_duration,
        "statistics": {
            "total_vulnerabilities": len(result.vulnerabilities),
            "total_misconfigurations": len(result.misconfigurations),
            "total_endpoints": len(result.discovered_endpoints),
            "total_technologies": len(result.detected_technologies),
            "total_requests": result.total_requests,
            "vulnerabilities_by_severity": result.vulnerabilities_by_severity
        }
    }

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
