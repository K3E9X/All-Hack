"""
Advanced Pentest Tool - FastAPI Backend
"""
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from app.config import settings
from app.intelligent_agent import IntelligentPentestAgent, ConfidenceLevel
from app.vuln_enrichment import VulnerabilityEnrichmentSystem
from app.autonomous_exploiter import get_exploiter, AutonomousExploiter
from app.unified_scanner import get_unified_scanner, UnifiedScanner
from app.models import ScanRequest, ScanResult, ScanProgress
from app.ai_enhanced_orchestrator import AIEnhancedScanOrchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global orchestrator instance (AI-Enhanced)
orchestrator = AIEnhancedScanOrchestrator()

# Intelligent Pentest Agent
intelligent_agent = IntelligentPentestAgent()

# Vulnerability Enrichment System
vuln_enrichment = VulnerabilityEnrichmentSystem()

# Frontend static files path
FRONTEND_DIST = Path(__file__).parent.parent.parent / "frontend" / "dist"

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
    allow_origins=settings.cors_origins,  # Use property to parse comma-separated string
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api")
async def api_info():
    """API info endpoint"""
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

@app.post(f"{settings.API_PREFIX}/scans/{{scan_id}}/stop")
async def stop_scan(scan_id: str):
    """Stop a running scan and return partial results"""
    success = orchestrator.stop_scan(scan_id)

    if not success:
        raise HTTPException(status_code=404, detail="Scan not found or already completed")

    return {
        "scan_id": scan_id,
        "message": "Stop request sent. Scan will stop after current phase completes.",
        "status": "stopping"
    }

# TODO: Playbook functionality not yet implemented
# @app.post(f"{settings.API_PREFIX}/playbooks")
# async def create_playbook(playbook: PlaybookRequest):
#     """Start a playbook consisting of multiple scans."""
#     run = await orchestrator.start_playbook(playbook)
#     return run
#
#
# @app.get(f"{settings.API_PREFIX}/playbooks/{{playbook_id}}")
# async def get_playbook(playbook_id: str):
#     run = orchestrator.get_playbook(playbook_id)
#     if not run:
#         raise HTTPException(status_code=404, detail="Playbook not found")
#     return run


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

# ========== CHAT INTERFACE (WEBSOCKET) ==========

@app.websocket("/ws/chat/{scan_id}")
async def websocket_chat(websocket: WebSocket, scan_id: str):
    """
    💬 Real-time chat with scan results (WebSocket)

    Connect to this endpoint to chat about scan results in real-time.

    Example (JavaScript):
    ```javascript
    const ws = new WebSocket('ws://localhost:8000/ws/chat/scan_123');
    ws.onmessage = (event) => console.log(event.data);
    ws.send('What are the critical vulnerabilities?');
    ```
    """
    from app.intelligence import get_chat_agent
    import json

    # Accept WebSocket connection
    await websocket.accept()

    try:
        # Get scan result
        scan_result = orchestrator.get_scan_result(scan_id)
        if not scan_result:
            await websocket.send_text(json.dumps({
                "type": "error",
                "content": f"Scan {scan_id} not found"
            }))
            await websocket.close()
            return

        # Get chat agent
        agent = await get_chat_agent()
        if not agent.available:
            await websocket.send_text(json.dumps({
                "type": "error",
                "content": "Chat agent not available. Install Ollama: https://ollama.ai"
            }))
            await websocket.close()
            return

        # Create or get chat session
        session = agent.get_session(scan_id)
        if not session:
            session = agent.create_session(scan_id, scan_result)

        # Send welcome message
        await websocket.send_text(json.dumps({
            "type": "system",
            "content": f"💬 Chat session started for scan {scan_id}\n\nAsk me anything about the scan results!"
        }))

        # Chat loop
        while True:
            # Receive message from client
            data = await websocket.receive_text()

            try:
                message_data = json.loads(data)
                user_message = message_data.get("message", "")
            except json.JSONDecodeError:
                # Plain text message
                user_message = data

            if not user_message:
                continue

            # Echo user message
            await websocket.send_text(json.dumps({
                "type": "user",
                "content": user_message
            }))

            # Stream assistant response
            async for chunk in agent.chat(scan_id, user_message, stream=True):
                await websocket.send_text(json.dumps({
                    "type": "assistant_chunk",
                    "content": chunk
                }))

            # Send completion marker
            await websocket.send_text(json.dumps({
                "type": "assistant_complete"
            }))

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        try:
            await websocket.send_text(json.dumps({
                "type": "error",
                "content": f"Error: {str(e)}"
            }))
        except:
            pass
    finally:
        try:
            await websocket.close()
        except:
            pass

@app.post(f"{settings.API_PREFIX}/chat/{{scan_id}}/session")
async def create_chat_session(scan_id: str):
    """
    Create a new chat session for a scan

    Returns session info.
    """
    from app.intelligence import get_chat_agent

    scan_result = orchestrator.get_scan_result(scan_id)
    if not scan_result:
        raise HTTPException(status_code=404, detail="Scan not found")

    agent = await get_chat_agent()
    if not agent.available:
        raise HTTPException(
            status_code=503,
            detail="Chat agent not available. Install Ollama: https://ollama.ai"
        )

    # Create session
    session = agent.create_session(scan_id, scan_result)

    return {
        "scan_id": scan_id,
        "session_created": session.created_at.isoformat(),
        "websocket_url": f"ws://localhost:8000/ws/chat/{scan_id}",
        "note": "Connect to websocket_url to start chatting"
    }

@app.post(f"{settings.API_PREFIX}/chat/{{scan_id}}/message")
async def send_chat_message(scan_id: str, message: str = Query(...)):
    """
    💬 Send a message (non-streaming, REST API)

    For simple API calls without WebSocket.
    Returns complete response.
    """
    from app.intelligence import get_chat_agent

    scan_result = orchestrator.get_scan_result(scan_id)
    if not scan_result:
        raise HTTPException(status_code=404, detail="Scan not found")

    agent = await get_chat_agent()
    if not agent.available:
        raise HTTPException(status_code=503, detail="Chat not available")

    # Get or create session
    session = agent.get_session(scan_id)
    if not session:
        session = agent.create_session(scan_id, scan_result)

    # Get response
    response = await agent.ask_quick(scan_id, message)

    return {
        "scan_id": scan_id,
        "user_message": message,
        "assistant_response": response
    }

@app.get(f"{settings.API_PREFIX}/chat/{{scan_id}}/history")
async def get_chat_history(scan_id: str, limit: int = Query(20, ge=1, le=100)):
    """Get chat history for a session"""
    from app.intelligence import get_chat_agent

    agent = await get_chat_agent()
    history = agent.get_session_history(scan_id, limit)

    return {
        "scan_id": scan_id,
        "message_count": len(history),
        "messages": history
    }

@app.delete(f"{settings.API_PREFIX}/chat/{{scan_id}}")
async def delete_chat_session(scan_id: str):
    """Delete chat session and history"""
    from app.intelligence import get_chat_agent

    agent = await get_chat_agent()
    deleted = agent.delete_session(scan_id)

    if not deleted:
        raise HTTPException(status_code=404, detail="Chat session not found")

    return {
        "scan_id": scan_id,
        "message": "Chat session deleted"
    }

# ========== END CHAT INTERFACE ==========

# ========== AI-POWERED ANALYSIS ENDPOINTS ==========

@app.post(f"{settings.API_PREFIX}/scans/{{scan_id}}/analyze")
async def analyze_scan_with_ai(scan_id: str):
    """
    🧠 AI-Powered Analysis (NEW!)

    Analyze all vulnerabilities with local LLM (Ollama).
    Provides:
    - Root cause analysis
    - Exploitation complexity rating
    - Business impact assessment
    - Framework-specific remediation code
    - Strategic scan summary
    - Attack chain identification

    Requires: Ollama running locally
    Install: https://ollama.ai
    Cost: $0 (runs locally)
    """
    from app.intelligence import get_llm_analyst

    result = orchestrator.get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get LLM analyst
    analyst = await get_llm_analyst()

    if not analyst.available:
        raise HTTPException(
            status_code=503,
            detail="LLM analyst not available. Install Ollama: https://ollama.ai"
        )

    # Analyze all vulnerabilities
    analyses = []
    for vuln in result.vulnerabilities:
        analysis = await analyst.analyze_vulnerability(
            vuln,
            tech_stack=[t.dict() for t in result.detected_technologies]
        )
        if analysis:
            analyses.append({
                "vulnerability_id": vuln.id,
                "vulnerability_title": vuln.title,
                "analysis": {
                    "root_cause": analysis.root_cause,
                    "exploitation_complexity": analysis.exploitation_complexity,
                    "business_impact": analysis.business_impact,
                    "remediation_code": analysis.remediation_code,
                    "next_steps": analysis.next_steps,
                    "full_analysis": analysis.full_analysis
                }
            })

    # Generate strategic summary
    summary = await analyst.summarize_scan(result.vulnerabilities)

    return {
        "scan_id": scan_id,
        "analyzed": len(analyses),
        "vulnerability_analyses": analyses,
        "strategic_summary": summary.dict() if summary else None,
        "note": "Analysis powered by Ollama (local LLM)"
    }

@app.get(f"{settings.API_PREFIX}/vulnerabilities/{{vuln_id}}/analyze")
async def analyze_single_vulnerability(vuln_id: str, scan_id: str = Query(...)):
    """
    🧠 Analyze a single vulnerability with AI

    Provides detailed AI-powered analysis for one vulnerability.
    """
    from app.intelligence import get_llm_analyst

    result = orchestrator.get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Find vulnerability
    vuln = next((v for v in result.vulnerabilities if v.id == vuln_id), None)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Get LLM analyst
    analyst = await get_llm_analyst()
    if not analyst.available:
        raise HTTPException(
            status_code=503,
            detail="LLM analyst not available. Install Ollama: https://ollama.ai"
        )

    # Analyze
    analysis = await analyst.analyze_vulnerability(
        vuln,
        tech_stack=[t.dict() for t in result.detected_technologies]
    )

    if not analysis:
        raise HTTPException(status_code=500, detail="Analysis failed")

    return {
        "vulnerability": vuln,
        "ai_analysis": analysis.dict()
    }

@app.post(f"{settings.API_PREFIX}/vulnerabilities/{{vuln_id}}/exploit-guide")
async def get_exploitation_guide(vuln_id: str, scan_id: str = Query(...), question: str = Query(...)):
    """
    🧠 Get AI-powered exploitation guidance

    Ask questions like:
    - "How do I exploit this vulnerability?"
    - "What tools should I use?"
    - "Show me step-by-step exploitation"
    """
    from app.intelligence import get_llm_analyst

    result = orchestrator.get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    vuln = next((v for v in result.vulnerabilities if v.id == vuln_id), None)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    analyst = await get_llm_analyst()
    if not analyst.available:
        raise HTTPException(status_code=503, detail="LLM not available")

    guide = await analyst.generate_exploitation_guide(vuln, question)

    return {
        "vulnerability_id": vuln_id,
        "question": question,
        "exploitation_guide": guide
    }

@app.post(f"{settings.API_PREFIX}/vulnerabilities/{{vuln_id}}/generate-fix")
async def generate_code_fix(vuln_id: str, scan_id: str = Query(...)):
    """
    🛠️ Generate framework-specific code fix

    AI generates ready-to-use code fixes in git diff format.
    """
    from app.intelligence import get_llm_analyst

    result = orchestrator.get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    vuln = next((v for v in result.vulnerabilities if v.id == vuln_id), None)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    analyst = await get_llm_analyst()
    if not analyst.available:
        raise HTTPException(status_code=503, detail="LLM not available")

    code_fix = await analyst.generate_remediation_code(
        vuln,
        tech_stack=[t.dict() for t in result.detected_technologies]
    )

    return {
        "vulnerability_id": vuln_id,
        "code_fix": code_fix,
        "format": "git diff"
    }

@app.get(f"{settings.API_PREFIX}/scans/{{scan_id}}/attack-chains")
async def identify_attack_chains(scan_id: str):
    """
    🎯 Identify potential attack chains

    AI analyzes all vulnerabilities to find multi-step attack paths.
    """
    from app.intelligence import get_llm_analyst

    result = orchestrator.get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    analyst = await get_llm_analyst()
    if not analyst.available:
        raise HTTPException(status_code=503, detail="LLM not available")

    chains = await analyst.identify_attack_chains(result.vulnerabilities)

    return {
        "scan_id": scan_id,
        "attack_chains": chains or [],
        "note": "Potential multi-step attack paths"
    }

@app.get(f"{settings.API_PREFIX}/ai/status")
async def get_ai_status():
    """
    Check AI analyst availability

    Returns status of Ollama and available models.
    """
    from app.intelligence import get_ollama_client

    ollama = get_ollama_client()
    available = await ollama.check_available()

    return {
        "available": available,
        "provider": "Ollama (local)",
        "model": ollama.config.model,
        "endpoint": ollama.config.base_url,
        "cost": "$0 (free)",
        "install_instructions": "https://ollama.ai" if not available else None
    }

# ========== END AI ENDPOINTS ==========

# ========== POC VALIDATION ENDPOINTS ==========

@app.post(f"{settings.API_PREFIX}/scans/{{scan_id}}/validate")
async def validate_scan_vulnerabilities(scan_id: str):
    """
    ✅ Validate all vulnerabilities with PoC

    Automatically validates vulnerabilities using Proof-of-Concept exploits.

    **What it does:**
    - SQL Injection: Extracts database version/data
    - XSS: Executes JavaScript in headless browser
    - SSRF: Detects out-of-band callbacks
    - RCE: Executes safe commands and detects output

    **Returns:**
    - Validation status: CONFIRMED, LIKELY, UNCONFIRMED, FALSE_POSITIVE
    - Confidence score: 0.0 to 1.0
    - Evidence: Actual proof of exploitation

    **Cost:** $0 (runs locally)
    """
    from app.validation import get_validation_orchestrator

    result = orchestrator.get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get validation orchestrator
    validator = get_validation_orchestrator()

    # Validate all vulnerabilities
    validation_results = await validator.validate_all(
        vulnerabilities=result.vulnerabilities,
        target_url=result.target_url
    )

    # Get statistics
    stats = validator.get_statistics(validation_results)

    # Format results
    validated_vulnerabilities = []
    for vuln in result.vulnerabilities:
        if vuln.id in validation_results:
            val_result = validation_results[vuln.id]
            validated_vulnerabilities.append({
                "vulnerability": vuln.dict(),
                "validation": {
                    "status": val_result.status.value,
                    "confidence": val_result.confidence,
                    "evidence": val_result.evidence,
                    "validated_at": val_result.validated_at.isoformat(),
                    "validator": val_result.validator_name,
                    "details": val_result.details
                }
            })

    return {
        "scan_id": scan_id,
        "validated": len(validated_vulnerabilities),
        "statistics": stats,
        "results": validated_vulnerabilities,
        "note": "Validation powered by automated PoC testing"
    }

@app.post(f"{settings.API_PREFIX}/vulnerabilities/{{vuln_id}}/validate")
async def validate_single_vulnerability(vuln_id: str, scan_id: str = Query(...)):
    """
    ✅ Validate a single vulnerability with PoC

    Runs automated Proof-of-Concept testing on a specific vulnerability.
    """
    from app.validation import get_validation_orchestrator

    result = orchestrator.get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Find vulnerability
    vuln = next((v for v in result.vulnerabilities if v.id == vuln_id), None)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Get validation orchestrator
    validator = get_validation_orchestrator()

    # Validate
    validation_result = await validator.validate_vulnerability(
        vulnerability=vuln,
        target_url=result.target_url
    )

    if not validation_result:
        raise HTTPException(
            status_code=400,
            detail="No validator available for this vulnerability type"
        )

    return {
        "vulnerability": vuln.dict(),
        "validation": {
            "status": validation_result.status.value,
            "confidence": validation_result.confidence,
            "evidence": validation_result.evidence,
            "validated_at": validation_result.validated_at.isoformat(),
            "validator": validation_result.validator_name,
            "details": validation_result.details
        }
    }

@app.get(f"{settings.API_PREFIX}/scans/{{scan_id}}/validation-stats")
async def get_validation_statistics(scan_id: str):
    """
    📊 Get validation statistics for a scan

    Returns aggregated statistics about validation results.
    """
    from app.validation import get_validation_orchestrator

    result = orchestrator.get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get validation orchestrator
    validator = get_validation_orchestrator()

    # Validate all (if not already validated)
    validation_results = await validator.validate_all(
        vulnerabilities=result.vulnerabilities,
        target_url=result.target_url
    )

    # Get statistics
    stats = validator.get_statistics(validation_results)

    return {
        "scan_id": scan_id,
        "validation_statistics": stats,
        "note": "Statistics for PoC validation results"
    }

@app.get(f"{settings.API_PREFIX}/scans/{{scan_id}}/confirmed-vulnerabilities")
async def get_confirmed_vulnerabilities(
    scan_id: str,
    min_confidence: float = Query(0.5, ge=0.0, le=1.0)
):
    """
    ✅ Get only confirmed vulnerabilities

    Returns vulnerabilities that have been validated with high confidence.
    Filters out false positives and low-confidence findings.

    **Parameters:**
    - min_confidence: Minimum confidence threshold (0.0 to 1.0)
    """
    from app.validation import get_validation_orchestrator

    result = orchestrator.get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get validation orchestrator
    validator = get_validation_orchestrator()

    # Validate all
    validation_results = await validator.validate_all(
        vulnerabilities=result.vulnerabilities,
        target_url=result.target_url
    )

    # Filter confirmed vulnerabilities
    confirmed = validator.filter_vulnerabilities(
        vulnerabilities=result.vulnerabilities,
        validation_results=validation_results,
        min_confidence=min_confidence,
        exclude_false_positives=True
    )

    return {
        "scan_id": scan_id,
        "total_vulnerabilities": len(result.vulnerabilities),
        "confirmed_vulnerabilities": len(confirmed),
        "min_confidence": min_confidence,
        "vulnerabilities": [v.dict() for v in confirmed]
    }

# ========== END POC VALIDATION ENDPOINTS ==========

# ========== PHASE 2: MULTI-AGENT SYSTEM ENDPOINTS ==========

@app.post(f"{settings.API_PREFIX}/agents/scan")
async def start_multi_agent_scan(scan_request: ScanRequest):
    """
    🤖 Start Multi-Agent Scan (Phase 2)

    Uses intelligent agent system for coordinated scanning:
    - Orchestrator: Coordinates workflow
    - Recon Agent: Intelligent enumeration
    - Exploitation Agent: Adaptive payloads
    - Analysis Agent: Vulnerability correlation
    - Reporting Agent: Executive summaries

    **Agents learn from previous scans stored in memory**

    Cost: $0 (runs locally with Ollama)
    """
    from app.agents import get_agent_coordinator
    from app.memory import get_scan_memory

    # Get agent coordinator
    coordinator = get_agent_coordinator()

    # Check if we have similar scans in memory
    memory = get_scan_memory()
    similar_scans = memory.recall_similar_scans(
        target_url=scan_request.target_url,
        limit=3
    )

    # Start multi-agent workflow
    scan_id = await orchestrator.start_scan(scan_request)

    # Start agent workflow
    workflow_result = await coordinator.start_scan_workflow(
        scan_id=scan_id,
        scan_request=scan_request
    )

    return {
        "scan_id": scan_id,
        "message": "Multi-agent scan started",
        "workflow": workflow_result,
        "similar_scans_found": len(similar_scans),
        "learning_enabled": True,
        "agents": {
            "orchestrator": "coordinating",
            "recon": "pending",
            "exploitation": "pending",
            "analysis": "pending",
            "reporting": "pending"
        }
    }

@app.get(f"{settings.API_PREFIX}/agents/scan/{{scan_id}}/workflow")
async def get_agent_workflow_status(scan_id: str):
    """
    📊 Get Multi-Agent Workflow Status

    Shows current state of agent workflow:
    - Which phase is active
    - Agent states
    - Progress
    - Findings so far
    """
    from app.agents import get_agent_coordinator

    coordinator = get_agent_coordinator()

    # Get workflow status
    workflow = await coordinator.get_workflow_status(scan_id)

    if not workflow:
        raise HTTPException(status_code=404, detail=f"Workflow for scan {scan_id} not found")

    # Get all agent states
    agent_states = coordinator.get_all_agent_states()

    return {
        "scan_id": scan_id,
        "workflow": workflow,
        "agents": agent_states,
        "message": "Multi-agent workflow status"
    }

@app.post(f"{settings.API_PREFIX}/agents/{{agent_id}}/task")
async def execute_agent_task(agent_id: str, task: Dict[str, Any]):
    """
    🎯 Execute Task on Specific Agent

    Run a task on a specific agent:
    - recon: Reconnaissance tasks
    - exploitation: Exploitation tasks
    - analysis: Analysis tasks
    - reporting: Reporting tasks
    """
    from app.agents import get_agent_coordinator

    coordinator = get_agent_coordinator()

    result = await coordinator.execute_agent_task(
        agent_id=agent_id,
        task=task
    )

    return {
        "agent_id": agent_id,
        "task_type": task.get("type"),
        "result": result
    }

@app.get(f"{settings.API_PREFIX}/agents/status")
async def get_all_agents_status():
    """
    🤖 Get All Agents Status

    Returns status of all agents in the system.
    """
    from app.agents import get_agent_coordinator

    coordinator = get_agent_coordinator()
    states = coordinator.get_all_agent_states()

    return {
        "total_agents": len(states),
        "agents": states,
        "coordinator_active": True
    }

# ========== MEMORY SYSTEM ENDPOINTS ==========

@app.get(f"{settings.API_PREFIX}/memory/stats")
async def get_memory_statistics():
    """
    📚 Get Memory Statistics

    Shows what the system has learned from previous scans.
    """
    from app.memory import get_scan_memory, get_vector_memory

    scan_memory = get_scan_memory()
    vector_memory = get_vector_memory()

    return {
        "scan_memory": scan_memory.get_statistics(),
        "vector_memory": vector_memory.get_statistics(),
        "learning_enabled": True
    }

@app.get(f"{settings.API_PREFIX}/memory/similar")
async def find_similar_scans(target_url: str, limit: int = Query(5)):
    """
    🔍 Find Similar Scans

    Search memory for similar previous scans.
    Uses learned data to optimize current scan.
    """
    from app.memory import get_scan_memory

    memory = get_scan_memory()

    similar = memory.recall_similar_scans(
        target_url=target_url,
        limit=limit
    )

    return {
        "target_url": target_url,
        "similar_scans_found": len(similar),
        "similar_scans": [
            {
                "scan_id": s.scan_id,
                "target_domain": s.target_domain,
                "technologies": s.technologies,
                "vulnerabilities_found": s.vulnerabilities_found,
                "timestamp": s.timestamp
            }
            for s in similar
        ]
    }

@app.get(f"{settings.API_PREFIX}/memory/payloads/{{vuln_type}}")
async def get_successful_payloads(vuln_type: str, technology: str = Query(None)):
    """
    💡 Get Successful Payloads

    Retrieve successful payloads from memory for a vulnerability type.
    Learns from past successful exploitations.
    """
    from app.memory import get_scan_memory

    memory = get_scan_memory()

    payloads = memory.get_successful_payloads(
        vulnerability_type=vuln_type,
        technology=technology
    )

    return {
        "vulnerability_type": vuln_type,
        "technology": technology,
        "successful_payloads": payloads,
        "count": len(payloads)
    }

@app.post(f"{settings.API_PREFIX}/memory/store/{{scan_id}}")
async def store_scan_in_memory(scan_id: str):
    """
    💾 Store Scan in Memory

    Save scan results to memory for future learning.
    """
    from app.memory import get_scan_memory

    # Get scan result
    result = orchestrator.get_scan_result(scan_id)

    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Store in memory
    memory = get_scan_memory()
    memory.store_scan(
        scan_id=scan_id,
        target_url=result.target_url,
        scan_result=result.dict()
    )

    return {
        "scan_id": scan_id,
        "message": "Scan stored in memory",
        "memory_enabled": True
    }

# ========== END PHASE 2 ENDPOINTS ==========

# ========== INTELLIGENT AGENT ENDPOINTS ==========

@app.post(f"{settings.API_PREFIX}/intelligent/analyze")
async def intelligent_analyze(
    scan_results: Dict[str, Any],
    target: str = Query(..., description="Target URL or domain")
):
    """
    🧠 Intelligent Analysis with Reasoning

    Analyzes scan results using chain-of-thought reasoning to:
    - Filter out false positives
    - Validate vulnerabilities with evidence
    - Provide confidence scores
    """
    findings = await intelligent_agent.analyze_with_reasoning(
        target=target,
        scan_results=scan_results
    )

    return {
        "target": target,
        "validated_findings": [f.to_dict() for f in findings],
        "total_validated": len(findings),
        "reasoning_summary": intelligent_agent.get_reasoning_summary()
    }

@app.get(f"{settings.API_PREFIX}/intelligent/reasoning")
async def get_reasoning_history():
    """
    📊 Get Reasoning History

    Returns the reasoning chain used for vulnerability validation.
    """
    return intelligent_agent.get_reasoning_summary()

@app.get(f"{settings.API_PREFIX}/intelligent/findings")
async def get_validated_findings(
    confidence: Optional[str] = Query(None, description="Filter by confidence level"),
    limit: int = Query(50, le=200)
):
    """
    📋 Get Validated Findings

    Returns all validated vulnerability findings.
    """
    findings = intelligent_agent.findings

    if confidence:
        try:
            conf_level = ConfidenceLevel(confidence)
            findings = [f for f in findings if f.confidence == conf_level]
        except ValueError:
            pass

    return {
        "findings": [f.to_dict() for f in findings[:limit]],
        "total": len(findings)
    }

# ========== VULNERABILITY ENRICHMENT ENDPOINTS ==========

@app.post(f"{settings.API_PREFIX}/vulns/update")
async def update_vulnerability_database(
    background_tasks: BackgroundTasks,
    keywords: Optional[List[str]] = Query(None, description="Keywords to search"),
    days_back: int = Query(7, le=30, description="Days to look back")
):
    """
    🔄 Update Vulnerability Database

    Fetches latest CVEs and POCs from:
    - NVD (National Vulnerability Database)
    - GitHub POCs
    - Nuclei Templates
    """
    async def do_update():
        await vuln_enrichment.update_from_nvd(keywords=keywords, days_back=days_back)
        await vuln_enrichment.fetch_nuclei_templates()
        await vuln_enrichment._save_database()

    background_tasks.add_task(do_update)

    return {
        "status": "update_started",
        "message": "Database update started in background"
    }

@app.get(f"{settings.API_PREFIX}/vulns/search")
async def search_vulnerabilities(
    query: Optional[str] = Query(None, description="Search query"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    tags: Optional[str] = Query(None, description="Comma-separated tags"),
    has_exploit: Optional[bool] = Query(None, description="Filter by exploit availability"),
    limit: int = Query(50, le=200)
):
    """
    🔍 Search Vulnerabilities

    Search the vulnerability database with filters.
    """
    tag_list = tags.split(',') if tags else None

    results = vuln_enrichment.search_vulnerabilities(
        query=query,
        severity=severity,
        tags=tag_list,
        has_exploit=has_exploit,
        limit=limit
    )

    return {
        "results": [v.to_dict() for v in results],
        "total": len(results)
    }

@app.get(f"{settings.API_PREFIX}/vulns/stats")
async def get_vulnerability_stats():
    """
    📈 Get Vulnerability Database Stats

    Returns statistics about the vulnerability database.
    """
    return vuln_enrichment.get_stats()

@app.get(f"{settings.API_PREFIX}/vulns/{{vuln_id}}")
async def get_vulnerability_details(vuln_id: str):
    """
    📄 Get Vulnerability Details

    Get full details of a specific vulnerability including exploits.
    """
    vuln = vuln_enrichment.vulnerabilities.get(vuln_id.upper())
    if not vuln:
        raise HTTPException(status_code=404, detail=f"Vulnerability {vuln_id} not found")

    exploits = vuln_enrichment.get_exploits_for_vulnerability(vuln_id.upper())

    return {
        "vulnerability": vuln.to_dict(),
        "exploits": [e.to_dict() for e in exploits]
    }

@app.post(f"{settings.API_PREFIX}/vulns/{{vuln_id}}/enrich")
async def enrich_vulnerability(vuln_id: str, background_tasks: BackgroundTasks):
    """
    🔬 Enrich Specific Vulnerability

    Fully enriches a CVE with all available data and POCs.
    """
    async def do_enrich():
        await vuln_enrichment.enrich_vulnerability(vuln_id.upper())

    background_tasks.add_task(do_enrich)

    return {
        "status": "enrichment_started",
        "vuln_id": vuln_id.upper()
    }

@app.post(f"{settings.API_PREFIX}/vulns/search-pocs")
async def search_github_pocs(
    cve_id: Optional[str] = Query(None, description="CVE ID to search"),
    keywords: Optional[List[str]] = Query(None, description="Keywords to search"),
    max_results: int = Query(10, le=50)
):
    """
    🔎 Search GitHub for POCs

    Searches GitHub for proof-of-concept exploits.
    """
    exploits = await vuln_enrichment.search_github_pocs(
        cve_id=cve_id,
        keywords=keywords,
        max_results=max_results
    )

    return {
        "exploits": [e.to_dict() for e in exploits],
        "total": len(exploits)
    }

# ========== AUTONOMOUS EXPLOITATION ENDPOINTS ==========

@app.post(f"{settings.API_PREFIX}/exploit/auto")
async def autonomous_exploit(
    target_url: str = Query(..., description="Target URL to exploit"),
    parameters: Optional[List[str]] = Query(None, description="Specific parameters to test"),
    extract_data: bool = Query(True, description="Extract data after finding vulns"),
    max_rows: int = Query(100, le=1000, description="Max rows to extract")
):
    """
    🎯 Autonomous Exploitation

    Automatically detect and exploit vulnerabilities:
    - SQL Injection (Union, Error, Time-based, Boolean)
    - Local File Inclusion (LFI)
    - Extracts data with proof-of-concept

    Uses Ollama for intelligent reasoning (FREE, local).
    """
    exploiter = get_exploiter()
    await exploiter.initialize()

    session = await exploiter.exploit_target(
        target_url=target_url,
        parameters=parameters,
        extract_data=extract_data,
        max_extraction_rows=max_rows
    )

    return {
        "session_id": session.session_id,
        "status": session.status.value,
        "vulnerabilities_found": len(session.vulnerabilities_found),
        "extractions": len(session.extractions),
        "reasoning_chain": session.reasoning_chain,
        "details": session.to_dict()
    }

@app.get(f"{settings.API_PREFIX}/exploit/session/{{session_id}}")
async def get_exploit_session(session_id: str):
    """
    📋 Get Exploitation Session

    Retrieve details of an exploitation session.
    """
    exploiter = get_exploiter()
    session = exploiter.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    return session.to_dict()

@app.get(f"{settings.API_PREFIX}/exploit/sessions")
async def list_exploit_sessions():
    """
    📊 List All Exploitation Sessions

    Get all exploitation sessions with their status.
    """
    exploiter = get_exploiter()
    sessions = exploiter.get_all_sessions()

    return {
        "total": len(sessions),
        "sessions": sessions
    }

@app.post(f"{settings.API_PREFIX}/exploit/sqli")
async def exploit_sqli(
    target_url: str = Query(..., description="Target URL"),
    parameter: str = Query(..., description="Vulnerable parameter"),
    max_rows: int = Query(100, le=1000)
):
    """
    💉 SQL Injection Exploitation

    Specifically exploit SQL injection:
    - Detect injection type
    - Extract database structure
    - Dump table data
    - Generate PoC
    """
    exploiter = get_exploiter()
    await exploiter.initialize()

    session = await exploiter.exploit_target(
        target_url=target_url,
        parameters=[parameter],
        extract_data=True,
        max_extraction_rows=max_rows
    )

    sqli_extractions = [
        e for e in session.extractions
        if 'sqli' in e.exploit_type.value
    ]

    return {
        "session_id": session.session_id,
        "sqli_found": len(sqli_extractions) > 0,
        "extractions": [
            {
                "type": e.exploit_type.value,
                "data": e.data_extracted,
                "poc": e.proof_of_concept,
                "success": e.success
            }
            for e in sqli_extractions
        ]
    }

@app.post(f"{settings.API_PREFIX}/exploit/lfi")
async def exploit_lfi(
    target_url: str = Query(..., description="Target URL"),
    parameter: str = Query(..., description="Vulnerable parameter")
):
    """
    📁 Local File Inclusion Exploitation

    Exploit LFI to extract files:
    - /etc/passwd, /etc/shadow
    - Configuration files
    - Source code
    - Log files
    """
    exploiter = get_exploiter()
    await exploiter.initialize()

    session = await exploiter.exploit_target(
        target_url=target_url,
        parameters=[parameter],
        extract_data=True
    )

    lfi_extractions = [
        e for e in session.extractions
        if e.exploit_type.value == 'lfi'
    ]

    return {
        "session_id": session.session_id,
        "lfi_found": len(lfi_extractions) > 0,
        "files_extracted": [
            {
                "files": list(e.data_extracted.get("files_extracted", {}).keys()),
                "poc": e.proof_of_concept,
                "success": e.success
            }
            for e in lfi_extractions
        ]
    }

@app.get(f"{settings.API_PREFIX}/exploit/poc/{{session_id}}")
async def get_proof_of_concept(session_id: str):
    """
    📝 Get Proof of Concept

    Get the PoC for all exploits in a session.
    """
    exploiter = get_exploiter()
    session = exploiter.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    pocs = []
    for extraction in session.extractions:
        pocs.append({
            "type": extraction.exploit_type.value,
            "parameter": extraction.parameter,
            "poc": extraction.proof_of_concept,
            "success": extraction.success
        })

    return {
        "session_id": session_id,
        "target": session.target_url,
        "proofs_of_concept": pocs
    }

# ========== ADVANCED EXPLOITATION ENDPOINTS ==========

@app.post(f"{settings.API_PREFIX}/exploit/ssti")
async def exploit_ssti(
    target_url: str = Query(..., description="Target URL with parameter"),
    parameter: str = Query(..., description="Parameter to test")
):
    """
    🔥 SSTI (Server-Side Template Injection)

    Detect and exploit template injection:
    - Jinja2, Twig, Freemarker, Mako, ERB, EJS, Pug
    - Configuration disclosure
    - Remote code execution
    """
    from app.advanced_exploiter import get_advanced_exploiter

    exploiter = get_advanced_exploiter()
    await exploiter.initialize()

    result = await exploiter.detect_ssti(target_url, parameter)

    return {
        "vulnerable": result is not None,
        "details": {
            "vuln_type": result.vuln_type.value if result else None,
            "payload": result.payload if result else None,
            "evidence": result.evidence if result else None,
            "severity": result.severity if result else None,
            "poc": result.poc if result else None,
            "engine": result.details.get("engine") if result else None
        } if result else None
    }


@app.post(f"{settings.API_PREFIX}/exploit/xxe")
async def exploit_xxe(
    target_url: str = Query(..., description="Target URL accepting XML"),
    content_type: str = Query("application/xml", description="Content-Type header")
):
    """
    📄 XXE (XML External Entity)

    Detect and exploit XXE:
    - File disclosure (/etc/passwd, config files)
    - SSRF via XXE
    - Out-of-band exfiltration
    """
    from app.advanced_exploiter import get_advanced_exploiter

    exploiter = get_advanced_exploiter()
    await exploiter.initialize()

    result = await exploiter.detect_xxe(target_url, content_type)

    return {
        "vulnerable": result is not None,
        "details": {
            "vuln_type": result.vuln_type.value if result else None,
            "payload": result.payload if result else None,
            "evidence": result.evidence if result else None,
            "extracted_content": result.details.get("extracted_content") if result else None,
            "severity": result.severity if result else None,
            "poc": result.poc if result else None
        } if result else None
    }


@app.post(f"{settings.API_PREFIX}/exploit/nosql")
async def exploit_nosql(
    target_url: str = Query(..., description="Target URL"),
    parameter: str = Query(..., description="Parameter to test")
):
    """
    🍃 NoSQL Injection

    Detect and exploit NoSQL injection:
    - MongoDB, CouchDB, Redis
    - Authentication bypass
    - Data extraction
    """
    from app.advanced_exploiter import get_advanced_exploiter

    exploiter = get_advanced_exploiter()
    await exploiter.initialize()

    result = await exploiter.detect_nosql(target_url, parameter)

    return {
        "vulnerable": result is not None,
        "details": {
            "vuln_type": result.vuln_type.value if result else None,
            "payload": result.payload if result else None,
            "evidence": result.evidence if result else None,
            "severity": result.severity if result else None,
            "poc": result.poc if result else None
        } if result else None
    }


@app.post(f"{settings.API_PREFIX}/exploit/jwt")
async def exploit_jwt(
    token: str = Query(..., description="JWT token to test"),
    protected_url: str = Query(..., description="URL protected by JWT")
):
    """
    🔑 JWT Attacks

    Test JWT for vulnerabilities:
    - Algorithm:none attack
    - Weak secret bruteforce
    - Algorithm confusion (RS256 to HS256)
    """
    from app.advanced_exploiter import get_advanced_exploiter

    exploiter = get_advanced_exploiter()
    await exploiter.initialize()

    results = await exploiter.attack_jwt(token, protected_url)

    return {
        "vulnerable": len(results) > 0,
        "attacks_successful": len(results),
        "details": [
            {
                "attack_type": r.evidence,
                "forged_token": r.payload,
                "severity": r.severity,
                "poc": r.poc
            }
            for r in results
        ]
    }


@app.post(f"{settings.API_PREFIX}/exploit/graphql")
async def exploit_graphql(
    target_url: str = Query(..., description="GraphQL endpoint URL")
):
    """
    📊 GraphQL Exploitation

    Test GraphQL for:
    - Introspection enabled
    - SQL injection via arguments
    - DoS via nested queries
    - Information disclosure
    """
    from app.advanced_exploiter import get_advanced_exploiter

    exploiter = get_advanced_exploiter()
    await exploiter.initialize()

    results = await exploiter.exploit_graphql(target_url)

    return {
        "vulnerable": len(results) > 0,
        "findings": len(results),
        "details": [
            {
                "type": r.evidence,
                "severity": r.severity,
                "poc": r.poc,
                "schema": r.details.get("schema") if "schema" in r.details else None
            }
            for r in results
        ]
    }


@app.post(f"{settings.API_PREFIX}/exploit/ssrf")
async def exploit_ssrf(
    target_url: str = Query(..., description="Target URL"),
    parameter: str = Query(..., description="Parameter to test")
):
    """
    🌐 SSRF (Server-Side Request Forgery)

    Detect and exploit SSRF:
    - Cloud metadata (AWS, GCP, Azure)
    - Internal network scanning
    - Bypass techniques
    """
    from app.advanced_exploiter import get_advanced_exploiter

    exploiter = get_advanced_exploiter()
    await exploiter.initialize()

    results = await exploiter.detect_ssrf(target_url, parameter)

    return {
        "vulnerable": len(results) > 0,
        "findings": len(results),
        "details": [
            {
                "type": r.evidence,
                "payload": r.payload,
                "cloud_provider": r.details.get("cloud"),
                "data_exposed": r.details.get("data", "")[:500],
                "severity": r.severity,
                "poc": r.poc
            }
            for r in results
        ]
    }


@app.post(f"{settings.API_PREFIX}/exploit/deserialization")
async def exploit_deserialization(
    target_url: str = Query(..., description="Target URL"),
    parameter: str = Query(..., description="Parameter to test")
):
    """
    💣 Insecure Deserialization

    Detect deserialization vulnerabilities:
    - Java (ysoserial gadgets)
    - PHP (phpggc)
    - Python (pickle)
    - Ruby (Marshal)
    - .NET (BinaryFormatter)
    """
    from app.advanced_exploiter import get_advanced_exploiter

    exploiter = get_advanced_exploiter()
    await exploiter.initialize()

    result = await exploiter.detect_deserialization(target_url, parameter)

    return {
        "vulnerable": result is not None,
        "details": {
            "language": result.details.get("language") if result else None,
            "payload": result.payload if result else None,
            "evidence": result.evidence if result else None,
            "severity": result.severity if result else None,
            "poc": result.poc if result else None
        } if result else None
    }


@app.post(f"{settings.API_PREFIX}/exploit/full-scan")
async def full_advanced_scan(
    target_url: str = Query(..., description="Target URL"),
    parameters: Optional[List[str]] = Query(None, description="Parameters to test")
):
    """
    🚀 Full Advanced Scan

    Run ALL exploit modules:
    - SSTI, XXE, NoSQL, SSRF, Deserialization
    - GraphQL (if endpoint detected)
    - Generates comprehensive PoCs
    """
    from app.advanced_exploiter import get_advanced_exploiter

    exploiter = get_advanced_exploiter()
    results = await exploiter.full_scan(target_url, parameters)

    return {
        "target": target_url,
        "total_vulnerabilities": len(results),
        "findings": [
            {
                "type": r.vuln_type.value,
                "severity": r.severity,
                "evidence": r.evidence,
                "payload": r.payload[:200] if len(r.payload) > 200 else r.payload,
                "poc": r.poc
            }
            for r in results
        ],
        "severity_summary": {
            "critical": len([r for r in results if r.severity == "critical"]),
            "high": len([r for r in results if r.severity == "high"]),
            "medium": len([r for r in results if r.severity == "medium"]),
            "low": len([r for r in results if r.severity == "low"])
        }
    }


@app.get(f"{settings.API_PREFIX}/payloads/{{vuln_type}}")
async def get_payloads(
    vuln_type: str,
    category: Optional[str] = Query(None, description="Payload category"),
    limit: int = Query(50, le=500)
):
    """
    📦 Get Payloads

    Retrieve payloads for a specific vulnerability type:
    - sqli, xss, ssti, xxe, nosql, lfi, rce, ssrf
    - Optional category filter
    """
    from app.payloads import (
        SQLI_PAYLOADS, XSS_PAYLOADS, SSTI_PAYLOADS,
        XXE_PAYLOADS, NOSQL_PAYLOADS, LFI_PAYLOADS,
        RCE_PAYLOADS, SSRF_PAYLOADS
    )

    payload_map = {
        "sqli": SQLI_PAYLOADS,
        "xss": XSS_PAYLOADS,
        "ssti": SSTI_PAYLOADS,
        "xxe": XXE_PAYLOADS,
        "nosql": NOSQL_PAYLOADS,
        "lfi": LFI_PAYLOADS,
        "rce": RCE_PAYLOADS,
        "ssrf": SSRF_PAYLOADS,
    }

    if vuln_type not in payload_map:
        raise HTTPException(status_code=400, detail=f"Unknown vuln_type: {vuln_type}")

    payloads = payload_map[vuln_type]

    if category and category in payloads:
        result = payloads[category]
    else:
        result = payloads

    # Flatten if nested dict
    if isinstance(result, dict):
        flat = []
        for k, v in result.items():
            if isinstance(v, list):
                flat.extend(v[:limit // len(result)])
        result = flat[:limit]
    elif isinstance(result, list):
        result = result[:limit]

    return {
        "vuln_type": vuln_type,
        "category": category,
        "count": len(result) if isinstance(result, list) else "dict",
        "payloads": result
    }


# ========== UNIFIED SCANNER ENDPOINTS ==========

@app.post(f"{settings.API_PREFIX}/attack")
async def start_unified_attack(
    target_url: str = Query(..., description="Target URL"),
    max_pages: int = Query(50, description="Max pages to crawl", le=200),
    background_tasks: BackgroundTasks = None
):
    """
    Full Attack - All-in-One Security Assessment

    Runs complete security scan including:
    - Reconnaissance and crawling
    - Technology detection
    - SQL Injection testing
    - XSS testing
    - LFI/Path traversal
    - SSTI detection
    - SSRF testing
    - Command injection
    - XXE testing
    - NoSQL injection
    - GraphQL exploitation
    """
    scanner = get_unified_scanner()
    session = await scanner.full_scan(target_url, max_pages)

    return {
        "scan_id": session.scan_id,
        "target": session.target_url,
        "status": session.phase.value,
        "progress": session.progress,
        "findings_count": len(session.findings),
        "endpoints_discovered": len(session.endpoints_discovered),
        "technologies": session.technologies,
        "findings": [f.to_dict() for f in session.findings],
        "severity_summary": session._count_severities(),
        "total_requests": session.total_requests
    }


@app.post(f"{settings.API_PREFIX}/attack/async")
async def start_async_attack(
    target_url: str = Query(..., description="Target URL"),
    max_pages: int = Query(50, description="Max pages to crawl", le=200),
    background_tasks: BackgroundTasks = None
):
    """
    Start Async Attack - Returns immediately with scan_id

    Poll /attack/{scan_id}/status for progress
    """
    import asyncio

    scanner = get_unified_scanner()
    scan_id = scanner._generate_id()

    # Create initial session
    from app.unified_scanner import ScanSession, ScanPhase
    from datetime import datetime

    session = ScanSession(
        scan_id=scan_id,
        target_url=target_url,
        start_time=datetime.now().isoformat(),
        phase=ScanPhase.INIT
    )
    scanner.sessions[scan_id] = session

    # Run scan in background
    async def run_scan():
        await scanner.full_scan(target_url, max_pages)

    asyncio.create_task(run_scan())

    return {
        "scan_id": scan_id,
        "status": "started",
        "message": "Scan started. Poll /attack/{scan_id}/status for progress"
    }


@app.get(f"{settings.API_PREFIX}/attack/{{scan_id}}/status")
async def get_attack_status(scan_id: str):
    """Get attack scan status and recent events"""
    scanner = get_unified_scanner()
    status = scanner.get_session_status(scan_id)

    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")

    return status


@app.get(f"{settings.API_PREFIX}/attack/{{scan_id}}")
async def get_attack_results(scan_id: str):
    """Get full attack results"""
    scanner = get_unified_scanner()
    session = scanner.get_session(scan_id)

    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    return session.to_dict()


@app.post(f"{settings.API_PREFIX}/attack/{{scan_id}}/stop")
async def stop_attack(scan_id: str):
    """Stop running attack"""
    scanner = get_unified_scanner()
    scanner.stop_scan(scan_id)

    return {"status": "stop_requested", "scan_id": scan_id}


# ========== STATIC FRONTEND SERVING ==========

# Mount static files if frontend is built
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/", response_class=FileResponse, include_in_schema=False)
    async def serve_frontend():
        """Serve frontend index.html"""
        return FileResponse(FRONTEND_DIST / "index.html")

    @app.get("/{path:path}", include_in_schema=False)
    async def serve_spa(path: str):
        """Serve SPA routes - fallback to index.html for client-side routing"""
        # Don't intercept API routes
        if path.startswith("api/") or path.startswith("docs") or path.startswith("openapi") or path == "health":
            raise HTTPException(status_code=404, detail="Not found")

        file_path = FRONTEND_DIST / path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        # Fallback to index.html for SPA routing
        return FileResponse(FRONTEND_DIST / "index.html")

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
    uvicorn.run(
        app,
        host=settings.API_HOST,
        port=settings.API_PORT,
        log_level="info"
    )
