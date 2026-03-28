"""
Recon and Tools API Routes
Exposes reconnaissance scanners and external tools
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
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

        # Handle URL or hostname
        target = request.target
        if target.startswith("http"):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            target = parsed.hostname

        scanner = PortScanner(f"http://{target}" if not request.target.startswith("http") else request.target)

        if request.ports:
            scanner.COMMON_PORTS = request.ports

        # scan() returns tuple: (open_ports, vulnerabilities, misconfigurations)
        open_ports, vulnerabilities, misconfigurations = await scanner.scan()

        # Build services dict from open ports
        services = {}
        for port_info in open_ports:
            if isinstance(port_info, dict) and port_info.get('open'):
                services[port_info['port']] = {
                    'service': port_info.get('service', 'unknown'),
                    'version': port_info.get('version', ''),
                    'banner': port_info.get('banner', '')
                }

        return {
            "target": target,
            "open_ports": [p['port'] for p in open_ports if isinstance(p, dict) and p.get('open')],
            "services": services,
            "vulnerabilities": [v.dict() if hasattr(v, 'dict') else str(v) for v in vulnerabilities],
            "misconfigurations": [m.dict() if hasattr(m, 'dict') else str(m) for m in misconfigurations],
            "total_scanned": len(scanner.COMMON_PORTS),
            "note": "PaaS-hosted targets (Heroku, AWS ELB, etc.) may only expose ports 80/443"
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

        if not nuclei.is_available():
            return {
                "target": request.target,
                "error": "Nuclei not installed",
                "install_hint": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
                "templates_run": 0,
                "vulnerabilities_found": 0
            }

        # Call the correct method
        vulns, misconfigs = await nuclei.scan_target(
            target=request.target,
            severity_filter=request.severity
        )

        findings = []
        for v in vulns:
            findings.append({
                "title": v.title,
                "severity": v.severity.value if hasattr(v.severity, 'value') else str(v.severity),
                "url": v.affected_url,
                "description": v.description
            })
        for m in misconfigs:
            findings.append({
                "title": m.title,
                "severity": m.severity.value if hasattr(m.severity, 'value') else str(m.severity),
                "url": m.affected_url,
                "description": m.description
            })

        return {
            "target": request.target,
            "findings": findings,
            "templates_run": len(findings),
            "vulnerabilities_found": len(vulns),
            "misconfigurations_found": len(misconfigs)
        }
    except ImportError:
        return {
            "target": request.target,
            "error": "Nuclei integration not available",
            "install_hint": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "templates_run": 0,
            "vulnerabilities_found": 0
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
        from app.payloads import (
            SQLI_PAYLOADS, XSS_PAYLOADS, LFI_PAYLOADS,
            RCE_PAYLOADS, SSTI_PAYLOADS, XXE_PAYLOADS,
            NOSQL_PAYLOADS, SSRF_PAYLOADS
        )

        # Map vuln types to payload constants
        payload_map = {
            "sqli": SQLI_PAYLOADS,
            "xss": XSS_PAYLOADS,
            "lfi": LFI_PAYLOADS,
            "rce": RCE_PAYLOADS,
            "ssti": SSTI_PAYLOADS,
            "xxe": XXE_PAYLOADS,
            "nosql": NOSQL_PAYLOADS,
            "ssrf": SSRF_PAYLOADS,
        }

        if vuln_type not in payload_map:
            return {"error": f"Unknown vuln type: {vuln_type}", "available": list(payload_map.keys())}

        payloads_data = payload_map[vuln_type]

        # Flatten if dict (payloads organized by category)
        if isinstance(payloads_data, dict):
            payloads = []
            for category, items in payloads_data.items():
                if isinstance(items, list):
                    payloads.extend(items[:limit // max(len(payloads_data), 1)])
            payloads = payloads[:limit]
        elif isinstance(payloads_data, list):
            payloads = payloads_data[:limit]
        else:
            payloads = []

        return {
            "vuln_type": vuln_type,
            "payloads": payloads,
            "count": len(payloads)
        }
    except Exception as e:
        logger.error(f"Payload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============ Exploitation Assistant ============

@router.post("/tools/exploit-assist")
async def exploitation_assistant(
    vuln_type: str = Query(..., description="Vulnerability type"),
    target: str = Query("", description="Target URL")
):
    """
    Get AI-powered exploitation assistance
    """
    try:
        # Try multi-agent first for consensus
        from app.services.multi_agent import get_orchestrator
        orchestrator = get_orchestrator()

        status = orchestrator.get_status()
        if status.get("providers") and len(status["providers"]) > 0:
            prompt = f"""Generate exploitation guidance for {vuln_type} vulnerability.
Target: {target}

Provide:
1. Step-by-step exploitation steps
2. Recommended tools
3. Example payloads specific to {vuln_type}
4. Post-exploitation actions

Format as JSON with keys: steps (array), tools (array), payloads (array), post_exploitation (array)"""

            result = await orchestrator.query_single(
                prompt=prompt,
                system_prompt="You are a penetration testing expert. Provide technical, actionable guidance for exploiting vulnerabilities. Return valid JSON only."
            )

            if result.success:
                import json
                try:
                    guidance = json.loads(result.response)
                except:
                    guidance = {
                        "steps": [result.response],
                        "tools": [],
                        "payloads": []
                    }
                return {
                    "vuln_type": vuln_type,
                    "target": target,
                    "guidance": guidance,
                    "provider": result.provider_name
                }

        # Fallback to single LLM
        from app.services.llm_service import LLMService
        llm = LLMService()
        await llm.initialize()

        if llm.available:
            from app.intelligence.exploitation_assistant import ExploitationAssistant
            assistant = ExploitationAssistant(llm)

            guidance = await assistant.get_guidance(
                vuln_type=vuln_type,
                target=target,
                findings=[]
            )

            return {
                "vuln_type": vuln_type,
                "target": target,
                "guidance": guidance
            }
    except Exception as e:
        logger.warning(f"AI guidance failed: {e}")
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


# ============ Decision Engine Endpoints ============

@router.get("/agent/decision-engine")
async def get_decision_engine_info():
    """
    Get DecisionEngine available tests and capabilities
    """
    try:
        from app.ai_agent.decision_engine import DecisionEngine

        engine = DecisionEngine()
        available_tests = engine.get_available_tests()

        return {
            "available_tests": available_tests,
            "total_tests": len(available_tests),
            "categories": {
                "authentication": [t for t in available_tests if "auth" in t["name"].lower()],
                "injection": [t for t in available_tests if any(x in t["name"].lower() for x in ["sql", "nosql", "graphql"])],
                "api_security": [t for t in available_tests if any(x in t["name"].lower() for x in ["jwt", "api", "rate"])],
                "logic_flaws": [t for t in available_tests if any(x in t["name"].lower() for x in ["business", "session", "file"])]
            }
        }
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"DecisionEngine not available: {e}")
    except Exception as e:
        logger.error(f"DecisionEngine error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agent/decision-engine/parse")
async def parse_ai_action(action: Dict[str, Any], endpoints: List[str] = None):
    """
    Parse an AI-recommended action into executable test
    """
    try:
        from app.ai_agent.decision_engine import DecisionEngine

        engine = DecisionEngine()
        test_action = engine.parse_action(action, endpoints or [])

        return {
            "test_name": test_action.test_name,
            "scanner": test_action.scanner_class,
            "target_endpoints": test_action.target_endpoints,
            "priority": test_action.priority,
            "reason": test_action.reason,
            "params": test_action.custom_params,
            "available": engine.is_test_available(test_action.test_name)
        }
    except Exception as e:
        logger.error(f"Action parse error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
