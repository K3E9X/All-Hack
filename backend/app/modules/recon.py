"""
Automated Reconnaissance Module

Features:
- Subdomain enumeration
- Port scanning
- Technology fingerprinting
- Wayback Machine integration
- Certificate transparency logs
- DNS enumeration
- Directory bruteforce
"""

import asyncio
import aiohttp
import re
import json
import socket
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


@dataclass
class ReconResult:
    domain: str
    subdomains: List[str] = field(default_factory=list)
    open_ports: Dict[str, List[int]] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    wayback_urls: List[str] = field(default_factory=list)
    directories: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    emails: List[str] = field(default_factory=list)
    interesting_files: List[str] = field(default_factory=list)


class ReconScanner:
    """Automated reconnaissance"""

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.result: Optional[ReconResult] = None

    async def _ensure_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
                connector=aiohttp.TCPConnector(ssl=False, limit=50)
            )

    async def _request(self, url: str, **kwargs) -> Tuple[Optional[str], int]:
        await self._ensure_session()
        try:
            async with self.session.get(url, **kwargs) as resp:
                return await resp.text(), resp.status
        except:
            return None, 0

    # ==================== SUBDOMAIN ENUMERATION ====================

    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using multiple sources"""
        subdomains: Set[str] = set()

        # Source 1: crt.sh (Certificate Transparency)
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp, status = await self._request(url)
            if status == 200 and resp:
                data = json.loads(resp)
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
        except Exception as e:
            logger.error(f"crt.sh error: {e}")

        # Source 2: HackerTarget
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp, status = await self._request(url)
            if status == 200 and resp and "error" not in resp.lower():
                for line in resp.split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].strip()
                        if sub.endswith(domain):
                            subdomains.add(sub)
        except Exception as e:
            logger.error(f"HackerTarget error: {e}")

        # Source 3: Common subdomain wordlist
        common_subs = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "beta", "app", "mobile", "m", "shop", "store", "blog", "news",
            "support", "help", "docs", "cdn", "static", "assets", "media",
            "img", "images", "video", "vpn", "remote", "gateway", "portal",
            "login", "auth", "sso", "id", "account", "my", "dashboard",
            "panel", "cpanel", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
            "dns", "mx", "relay", "backup", "db", "database", "mysql", "sql",
            "postgres", "mongo", "redis", "elastic", "kibana", "grafana",
            "jenkins", "gitlab", "git", "svn", "jira", "confluence", "wiki",
            "internal", "intranet", "extranet", "corp", "office", "hr",
            "crm", "erp", "billing", "payment", "checkout", "cart", "order",
            "track", "status", "monitor", "health", "metrics", "logs",
            "stage", "uat", "qa", "prod", "production", "demo", "sandbox",
        ]

        async def check_subdomain(sub: str):
            full = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full)
                subdomains.add(full)
            except:
                pass

        tasks = [check_subdomain(sub) for sub in common_subs]
        await asyncio.gather(*tasks)

        return sorted(list(subdomains))

    # ==================== PORT SCANNING ====================

    async def scan_ports(self, host: str, ports: List[int] = None) -> List[int]:
        """Scan ports on a host"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                     993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000,
                     8080, 8443, 8888, 9000, 9090, 9200, 11211, 27017]

        open_ports = []

        async def check_port(port: int):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=2
                )
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
            except:
                pass

        tasks = [check_port(port) for port in ports]
        await asyncio.gather(*tasks)

        return sorted(open_ports)

    # ==================== TECHNOLOGY DETECTION ====================

    async def detect_technologies(self, url: str) -> List[str]:
        """Detect technologies used by target"""
        techs = []

        resp, status = await self._request(url)
        if not resp:
            return techs

        # Response-based detection
        patterns = {
            "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
            "Drupal": [r"Drupal", r"drupal.js", r"sites/all"],
            "Joomla": [r"Joomla", r"/administrator", r"com_content"],
            "Laravel": [r"laravel", r"csrf-token", r"Laravel"],
            "Django": [r"csrfmiddlewaretoken", r"Django", r"__debug__"],
            "Flask": [r"werkzeug", r"Flask"],
            "Express": [r"X-Powered-By: Express"],
            "ASP.NET": [r"__VIEWSTATE", r"ASP\.NET", r"\.aspx"],
            "PHP": [r"\.php", r"PHPSESSID"],
            "Java": [r"JSESSIONID", r"\.jsp", r"\.do"],
            "Ruby": [r"_session_id", r"Ruby", r"Rails"],
            "Node.js": [r"node", r"express", r"npm"],
            "React": [r"react", r"_reactRoot", r"__NEXT_DATA__"],
            "Angular": [r"ng-app", r"angular", r"ng-"],
            "Vue": [r"vue", r"__vue__", r"nuxt"],
            "jQuery": [r"jquery", r"jQuery"],
            "Bootstrap": [r"bootstrap"],
            "Nginx": [r"nginx"],
            "Apache": [r"Apache", r"apache"],
            "IIS": [r"Microsoft-IIS", r"ASP\.NET"],
            "Cloudflare": [r"cloudflare", r"cf-ray"],
            "AWS": [r"amazonaws", r"aws", r"x-amz"],
            "GraphQL": [r"graphql", r"__schema"],
            "Swagger": [r"swagger", r"openapi"],
        }

        for tech, regex_list in patterns.items():
            for regex in regex_list:
                if re.search(regex, resp, re.I):
                    if tech not in techs:
                        techs.append(tech)
                    break

        return techs

    # ==================== WAYBACK MACHINE ====================

    async def get_wayback_urls(self, domain: str, limit: int = 100) -> List[str]:
        """Get historical URLs from Wayback Machine"""
        urls = []

        try:
            api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&limit={limit}"
            resp, status = await self._request(api_url)

            if status == 200 and resp:
                data = json.loads(resp)
                for entry in data[1:]:  # Skip header
                    if len(entry) > 2:
                        urls.append(entry[2])  # Original URL
        except Exception as e:
            logger.error(f"Wayback error: {e}")

        # Filter interesting URLs
        interesting_patterns = [
            r"\.php", r"\.asp", r"\.jsp", r"\.cgi",
            r"\.bak", r"\.old", r"\.backup", r"\.sql",
            r"\.log", r"\.txt", r"\.xml", r"\.json",
            r"admin", r"login", r"api", r"config",
            r"\.env", r"\.git", r"\.svn",
            r"upload", r"file", r"download",
            r"password", r"secret", r"key", r"token",
        ]

        filtered = []
        for url in urls:
            if any(re.search(p, url, re.I) for p in interesting_patterns):
                filtered.append(url)

        return list(set(filtered))[:limit]

    # ==================== DIRECTORY BRUTEFORCE ====================

    async def bruteforce_directories(self, base_url: str, wordlist: List[str] = None) -> List[str]:
        """Bruteforce directories and files"""
        if wordlist is None:
            wordlist = [
                "admin", "administrator", "login", "wp-admin", "phpmyadmin",
                "cpanel", "webmail", "mail", "dashboard", "panel", "manager",
                "api", "v1", "v2", "graphql", "swagger", "docs", "documentation",
                "backup", "backups", "bak", "old", "test", "testing", "dev",
                "staging", "stage", "uat", "demo", "beta", "alpha",
                "config", "configuration", "settings", "setup", "install",
                "uploads", "upload", "files", "file", "images", "img", "assets",
                "static", "media", "content", "data", "tmp", "temp", "cache",
                "logs", "log", "debug", "error", "errors",
                ".git", ".svn", ".env", ".htaccess", ".htpasswd",
                "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
                "package.json", "composer.json", "Gemfile", "requirements.txt",
                "web.config", "config.php", "config.inc.php", "wp-config.php",
                "database.yml", "settings.py", "local_settings.py",
                ".aws", ".ssh", ".bash_history", ".npmrc",
                "server-status", "server-info", "phpinfo.php", "info.php",
            ]

        found = []
        base_url = base_url.rstrip("/")

        async def check_path(path: str):
            url = f"{base_url}/{path}"
            resp, status = await self._request(url)
            if status in [200, 301, 302, 403]:
                found.append({"path": path, "status": status})

        tasks = [check_path(path) for path in wordlist]
        await asyncio.gather(*tasks)

        return found

    # ==================== EMAIL HARVESTING ====================

    async def harvest_emails(self, domain: str) -> List[str]:
        """Harvest email addresses"""
        emails: Set[str] = set()

        # Check main domain
        url = f"https://{domain}"
        resp, status = await self._request(url)

        if resp:
            # Find emails in page
            found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp)
            for email in found:
                if domain in email.lower():
                    emails.add(email.lower())

        return sorted(list(emails))

    # ==================== INTERESTING FILES ====================

    async def find_interesting_files(self, base_url: str) -> List[Dict]:
        """Find potentially sensitive files"""
        interesting_paths = [
            ".git/config", ".git/HEAD", ".gitignore",
            ".svn/entries", ".svn/wc.db",
            ".env", ".env.local", ".env.production", ".env.backup",
            ".htaccess", ".htpasswd",
            "web.config", "config.php", "config.inc.php",
            "wp-config.php", "wp-config.php.bak",
            "database.yml", "settings.py", "local_settings.py",
            "config/database.yml", "config/secrets.yml",
            "backup.sql", "database.sql", "dump.sql",
            "backup.zip", "backup.tar.gz", "site.zip",
            "phpinfo.php", "info.php", "test.php",
            "debug.log", "error.log", "access.log",
            "robots.txt", "sitemap.xml", "security.txt",
            ".well-known/security.txt",
            "crossdomain.xml", "clientaccesspolicy.xml",
            "package.json", "package-lock.json", "yarn.lock",
            "composer.json", "composer.lock",
            "Gemfile", "Gemfile.lock",
            "requirements.txt", "Pipfile", "Pipfile.lock",
            "Dockerfile", "docker-compose.yml", ".dockerignore",
            "Makefile", "Rakefile", "Gruntfile.js", "gulpfile.js",
            ".travis.yml", ".gitlab-ci.yml", "Jenkinsfile",
            "id_rsa", "id_rsa.pub", ".ssh/id_rsa",
            "credentials.xml", "secrets.json", "keys.json",
        ]

        found = []
        base_url = base_url.rstrip("/")

        async def check_file(path: str):
            url = f"{base_url}/{path}"
            resp, status = await self._request(url)
            if status == 200 and resp:
                # Verify it's not a custom 404
                if len(resp) > 10 and "not found" not in resp.lower()[:100]:
                    found.append({
                        "path": path,
                        "url": url,
                        "size": len(resp),
                        "preview": resp[:200]
                    })

        tasks = [check_file(path) for path in interesting_paths]
        await asyncio.gather(*tasks)

        return found

    # ==================== FULL RECON ====================

    async def full_recon(self, target: str) -> ReconResult:
        """Run full reconnaissance"""
        await self._ensure_session()

        # Parse target
        parsed = urlparse(target)
        domain = parsed.netloc or target
        base_url = f"https://{domain}" if not target.startswith("http") else target

        logger.info(f"Starting recon on {domain}")

        result = ReconResult(domain=domain)

        # Subdomain enumeration
        logger.info("Enumerating subdomains...")
        result.subdomains = await self.enumerate_subdomains(domain)
        logger.info(f"Found {len(result.subdomains)} subdomains")

        # Port scanning on main domain
        logger.info("Scanning ports...")
        result.open_ports[domain] = await self.scan_ports(domain)
        logger.info(f"Found {len(result.open_ports[domain])} open ports")

        # Technology detection
        logger.info("Detecting technologies...")
        result.technologies = await self.detect_technologies(base_url)
        logger.info(f"Detected {len(result.technologies)} technologies")

        # Wayback URLs
        logger.info("Fetching Wayback URLs...")
        result.wayback_urls = await self.get_wayback_urls(domain)
        logger.info(f"Found {len(result.wayback_urls)} historical URLs")

        # Directory bruteforce
        logger.info("Bruteforcing directories...")
        dirs = await self.bruteforce_directories(base_url)
        result.directories = [d["path"] for d in dirs]
        logger.info(f"Found {len(result.directories)} directories")

        # Email harvesting
        logger.info("Harvesting emails...")
        result.emails = await self.harvest_emails(domain)
        logger.info(f"Found {len(result.emails)} emails")

        # Interesting files
        logger.info("Finding interesting files...")
        files = await self.find_interesting_files(base_url)
        result.interesting_files = [f["path"] for f in files]
        logger.info(f"Found {len(result.interesting_files)} interesting files")

        self.result = result
        return result
