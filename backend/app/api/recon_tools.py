"""
Recon and Tools API Routes
Exposes reconnaissance scanners and external tools
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import asyncio
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["recon", "tools"])


# ============ Request/Response Models ============

class PortScanRequest(BaseModel):
    target: str = Field(..., description="Target hostname or IP")
    ports: Optional[List[int]] = Field(None, description="Specific ports to scan (default: common ports)")
    timeout: Optional[float] = Field(5.0, description="Timeout per port in seconds")


class SubdomainScanRequest(BaseModel):
    target: str = Field(..., description="Target domain")
    wordlist: Optional[str] = Field(None, description="Custom wordlist (default: common subdomains)")


class SSLScanRequest(BaseModel):
    target: str = Field(..., description="Target URL or hostname")
    port: Optional[int] = Field(443, description="Port to scan")


class DirectoryScanRequest(BaseModel):
    target: str = Field(..., description="Target URL")
    wordlist: Optional[str] = Field(None, description="Custom wordlist")
    extensions: Optional[List[str]] = Field(None, description="File extensions to check")


class SQLMapRequest(BaseModel):
    target: str = Field(..., description="Target URL with parameter")
    method: Optional[str] = Field("GET", description="HTTP method")
    data: Optional[str] = Field(None, description="POST data")
    level: Optional[int] = Field(1, description="SQLMap level (1-5)")
    risk: Optional[int] = Field(1, description="SQLMap risk (1-3)")


class NucleiRequest(BaseModel):
    target: str = Field(..., description="Target URL")
    templates: Optional[List[str]] = Field(None, description="Specific templates to use")
    severity: Optional[List[str]] = Field(None, description="Filter by severity")


class PayloadGenRequest(BaseModel):
    vuln_type: str = Field(..., description="Vulnerability type (sqli, xss, rce, etc.)")
    context: Optional[Dict[str, Any]] = Field(None, description="Context for payload generation")
    count: Optional[int] = Field(10, description="Number of payloads to generate")


# ============ Recon Endpoints ============

@router.post("/recon/ports")
async def scan_ports(request: PortScanRequest):
    """
    Scan target for open ports and services
    """
    try:
        from app.scanners.advanced.port_scanner import PortScanner

        scanner = PortScanner(request.target)

        if request.ports:
            scanner.COMMON_PORTS = request.ports

        results = await scanner.scan()

        return {
            "target": request.target,
            "open_ports": results.get("open_ports", []),
            "services": results.get("services", {}),
            "vulnerabilities": results.get("vulnerabilities", [])
        }
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Scanner not available: {e}")
    except Exception as e:
        logger.error(f"Port scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/recon/subdomains")
async def scan_subdomains(request: SubdomainScanRequest):
    """
    Enumerate subdomains for target domain
    """
    try:
        from app.scanners.advanced.subdomain_scanner import SubdomainScanner

        scanner = SubdomainScanner(request.target)
        results = await scanner.scan()

        return {
            "target": request.target,
            "subdomains": results,
            "count": len(results)
        }
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Scanner not available: {e}")
    except Exception as e:
        logger.error(f"Subdomain scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/recon/ssl")
async def scan_ssl(request: SSLScanRequest):
    """
    Analyze SSL/TLS configuration
    """
    try:
        from app.scanners.advanced.ssl_scanner import SSLScanner

        target = request.target
        if not target.startswith("http"):
            target = f"https://{target}"

        scanner = SSLScanner(target)
        vulnerabilities, misconfigurations = await scanner.scan()

        return {
            "target": request.target,
            "vulnerabilities": [v.dict() if hasattr(v, 'dict') else v for v in vulnerabilities],
            "misconfigurations": [m.dict() if hasattr(m, 'dict') else m for m in misconfigurations],
            "summary": {
                "vulnerabilities_count": len(vulnerabilities),
                "misconfigurations_count": len(misconfigurations)
            }
        }
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Scanner not available: {e}")
    except Exception as e:
        logger.error(f"SSL scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/recon/directories")
async def scan_directories(request: DirectoryScanRequest):
    """
    Fuzzing directories and files
    """
    try:
        from app.scanners.advanced.directory_fuzzer import DirectoryFuzzer

        scanner = DirectoryFuzzer(request.target)
        results = await scanner.scan()

        return {
            "target": request.target,
            "directories": results.get("directories", []),
            "files": results.get("files", []),
            "count": results.get("total_found", 0)
        }
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Scanner not available: {e}")
    except Exception as e:
        logger.error(f"Directory scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============ Tools Endpoints ============

@router.post("/tools/sqlmap")
async def run_sqlmap(request: SQLMapRequest, background_tasks: BackgroundTasks):
    """
    Run SQLMap against target
    """
    try:
        from app.integrations.sqlmap_integration import SQLMapIntegration

        sqlmap = SQLMapIntegration()

        # Run scan
        result = await sqlmap.scan(
            url=request.target,
            method=request.method,
            data=request.data,
            level=request.level,
            risk=request.risk
        )

        return {
            "target": request.target,
            "vulnerable": result.get("vulnerable", False),
            "injection_points": result.get("injection_points", []),
            "databases": result.get("databases", []),
            "output": result.get("output", "")
        }
    except ImportError:
        # SQLMap not installed - provide fallback info
        return {
            "target": request.target,
            "error": "SQLMap not installed",
            "install_hint": "apt install sqlmap or pip install sqlmap",
            "fallback": "Using built-in SQLi scanner instead"
        }
    except Exception as e:
        logger.error(f"SQLMap error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tools/nuclei")
async def run_nuclei(request: NucleiRequest):
    """
    Run Nuclei templates against target
    """
    try:
        from app.integrations.nuclei_integration import NucleiIntegration

        nuclei = NucleiIntegration()

        result = await nuclei.scan(
            url=request.target,
            templates=request.templates,
            severity=request.severity
        )

        return {
            "target": request.target,
            "findings": result.get("findings", []),
            "templates_run": result.get("templates_run", 0),
            "vulnerabilities_found": result.get("vulnerabilities_found", 0)
        }
    except ImportError:
        return {
            "target": request.target,
            "error": "Nuclei not installed",
            "install_hint": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "fallback": "Using built-in scanners instead"
        }
    except Exception as e:
        logger.error(f"Nuclei error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tools/payloads")
async def generate_payloads(request: PayloadGenRequest):
    """
    Generate AI-powered payloads
    """
    try:
        from app.ai_agent.payload_generator import AIPayloadGenerator
        from app.services.llm_service import LLMService

        llm = LLMService()
        await llm.initialize()

        generator = AIPayloadGenerator(llm)

        payloads = await generator.generate(
            vuln_type=request.vuln_type,
            context=request.context or {},
            count=request.count
        )

        return {
            "vuln_type": request.vuln_type,
            "payloads": payloads,
            "count": len(payloads)
        }
    except ImportError:
        # Fallback to static payloads
        from app.payloads import get_payloads

        payloads = get_payloads(request.vuln_type)[:request.count]
        return {
            "vuln_type": request.vuln_type,
            "payloads": payloads,
            "count": len(payloads),
            "source": "static"
        }
    except Exception as e:
        logger.error(f"Payload generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/payloads/{vuln_type}")
async def get_static_payloads(vuln_type: str, limit: int = 50):
    """
    Get static payloads for vulnerability type
    """
    try:
        # Map vuln types to payload modules
        payload_map = {
            "sqli": "app.payloads.sqli",
            "xss": "app.payloads.xss",
            "lfi": "app.payloads.lfi",
            "rce": "app.payloads.rce",
            "ssti": "app.payloads.ssti",
            "xxe": "app.payloads.xxe",
            "nosql": "app.payloads.nosql",
            "ssrf": "app.payloads.ssrf",
        }

        if vuln_type not in payload_map:
            return {"error": f"Unknown vuln type: {vuln_type}", "available": list(payload_map.keys())}

        import importlib
        module = importlib.import_module(payload_map[vuln_type])

        # Get payloads from module
        payloads = []
        if hasattr(module, 'PAYLOADS'):
            payloads = module.PAYLOADS[:limit]
        elif hasattr(module, 'get_payloads'):
            payloads = module.get_payloads()[:limit]

        return {
            "vuln_type": vuln_type,
            "payloads": payloads,
            "count": len(payloads)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============ Exploitation Assistant ============

@router.post("/tools/exploit-assist")
async def exploitation_assistant(vuln_type: str, target: str, findings: List[Dict] = None):
    """
    Get AI-powered exploitation assistance
    """
    try:
        from app.intelligence.exploitation_assistant import ExploitationAssistant
        from app.services.llm_service import LLMService

        llm = LLMService()
        await llm.initialize()

        assistant = ExploitationAssistant(llm)

        guidance = await assistant.get_guidance(
            vuln_type=vuln_type,
            target=target,
            findings=findings or []
        )

        return {
            "vuln_type": vuln_type,
            "target": target,
            "guidance": guidance
        }
    except ImportError:
        # Return static guidance
        static_guidance = {
            "sqli": {
                "steps": [
                    "1. Identify injection point",
                    "2. Determine database type",
                    "3. Extract database structure",
                    "4. Dump sensitive data"
                ],
                "tools": ["sqlmap", "manual injection"],
                "payloads": ["' OR 1=1--", "' UNION SELECT NULL--"]
            },
            "xss": {
                "steps": [
                    "1. Identify reflection point",
                    "2. Determine context (HTML, JS, attribute)",
                    "3. Craft context-appropriate payload",
                    "4. Test for DOM-based XSS"
                ],
                "tools": ["browser devtools", "XSS hunter"],
                "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
            },
            "rce": {
                "steps": [
                    "1. Confirm command execution",
                    "2. Identify OS type",
                    "3. Establish reverse shell",
                    "4. Escalate privileges"
                ],
                "tools": ["netcat", "metasploit"],
                "payloads": ["; id", "| whoami", "$(id)"]
            }
        }

        return {
            "vuln_type": vuln_type,
            "target": target,
            "guidance": static_guidance.get(vuln_type, {"error": "No guidance available"}),
            "source": "static"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
