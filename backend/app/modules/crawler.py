"""
Intelligent Web Crawler Module

Features:
- Smart crawling with deduplication
- JavaScript rendering support (via external service)
- Form detection and parsing
- API endpoint discovery
- Sitemap parsing
- robots.txt parsing
- Rate limiting and politeness
"""

import asyncio
import aiohttp
import re
import json
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import deque
import logging
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class CrawledPage:
    url: str
    status: int
    content_type: str
    title: Optional[str]
    forms: List[Dict]
    links: List[str]
    scripts: List[str]
    parameters: List[str]
    headers: Dict[str, str]
    content_hash: str


@dataclass
class Form:
    action: str
    method: str
    inputs: List[Dict]
    url: str


@dataclass
class CrawlResult:
    base_url: str
    pages_crawled: int
    endpoints: List[str]
    forms: List[Form]
    parameters: Set[str]
    api_endpoints: List[str]
    scripts: List[str]
    technologies: List[str]
    sitemap_urls: List[str]
    robots_paths: Dict[str, List[str]]


class IntelligentCrawler:
    """Smart web crawler with deduplication and form detection"""

    def __init__(
        self,
        max_pages: int = 100,
        max_depth: int = 5,
        rate_limit: int = 10,
        timeout: int = 15,
        respect_robots: bool = True
    ):
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.respect_robots = respect_robots

        self.session: Optional[aiohttp.ClientSession] = None
        self.visited: Set[str] = set()
        self.content_hashes: Set[str] = set()
        self.queue: deque = deque()
        self.pages: List[CrawledPage] = []
        self.forms: List[Form] = []
        self.parameters: Set[str] = set()
        self.api_endpoints: List[str] = []
        self.disallowed_paths: List[str] = []
        self.semaphore: asyncio.Semaphore = None

    async def _ensure_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(ssl=False, limit=self.rate_limit)
            )
            self.semaphore = asyncio.Semaphore(self.rate_limit)

    async def _request(self, url: str) -> Tuple[Optional[str], int, Dict]:
        await self._ensure_session()
        async with self.semaphore:
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (compatible; AllHackCrawler/1.0)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                }
                async with self.session.get(url, headers=headers, allow_redirects=True) as resp:
                    # Only read HTML content
                    content_type = resp.headers.get("Content-Type", "")
                    if "html" in content_type or "text" in content_type or "json" in content_type:
                        text = await resp.text()
                    else:
                        text = ""
                    return text, resp.status, dict(resp.headers)
            except Exception as e:
                logger.debug(f"Request failed for {url}: {e}")
                return None, 0, {}

    # ==================== PARSING ====================

    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize and validate URL"""
        # Handle relative URLs
        if not url.startswith(("http://", "https://", "//")):
            url = urljoin(base_url, url)
        elif url.startswith("//"):
            parsed_base = urlparse(base_url)
            url = f"{parsed_base.scheme}:{url}"

        # Parse and validate
        try:
            parsed = urlparse(url)

            # Skip non-HTTP
            if parsed.scheme not in ["http", "https"]:
                return None

            # Skip common non-page extensions
            skip_extensions = [
                ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
                ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt",
                ".zip", ".tar", ".gz", ".rar", ".7z",
                ".mp3", ".mp4", ".avi", ".mov", ".wmv",
            ]
            if any(parsed.path.lower().endswith(ext) for ext in skip_extensions):
                return None

            # Remove fragment
            url = parsed._replace(fragment="").geturl()

            return url

        except:
            return None

    def _is_same_domain(self, url: str, base_url: str) -> bool:
        """Check if URL is on same domain"""
        try:
            parsed_url = urlparse(url)
            parsed_base = urlparse(base_url)
            return parsed_url.netloc == parsed_base.netloc
        except:
            return False

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        links = []

        # href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, html, re.I):
            url = self._normalize_url(match.group(1), base_url)
            if url and self._is_same_domain(url, base_url):
                links.append(url)

        # action attributes (forms)
        action_pattern = r'action=["\']([^"\']+)["\']'
        for match in re.finditer(action_pattern, html, re.I):
            url = self._normalize_url(match.group(1), base_url)
            if url and self._is_same_domain(url, base_url):
                links.append(url)

        # src attributes (for AJAX endpoints)
        src_pattern = r'src=["\']([^"\']+)["\']'
        for match in re.finditer(src_pattern, html, re.I):
            url = match.group(1)
            if ".js" in url or "api" in url.lower():
                norm_url = self._normalize_url(url, base_url)
                if norm_url:
                    links.append(norm_url)

        return list(set(links))

    def _extract_forms(self, html: str, page_url: str) -> List[Form]:
        """Extract forms from HTML"""
        forms = []

        form_pattern = r'<form[^>]*>(.*?)</form>'
        for form_match in re.finditer(form_pattern, html, re.I | re.DOTALL):
            form_html = form_match.group(0)
            form_content = form_match.group(1)

            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            action = action_match.group(1) if action_match else ""
            action = self._normalize_url(action, page_url) or page_url

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            method = method_match.group(1).upper() if method_match else "GET"

            # Extract inputs
            inputs = []
            input_pattern = r'<(?:input|textarea|select)[^>]*>'
            for input_match in re.finditer(input_pattern, form_content, re.I):
                input_html = input_match.group(0)

                name_match = re.search(r'name=["\']([^"\']+)["\']', input_html, re.I)
                type_match = re.search(r'type=["\']([^"\']+)["\']', input_html, re.I)
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_html, re.I)

                if name_match:
                    inputs.append({
                        "name": name_match.group(1),
                        "type": type_match.group(1) if type_match else "text",
                        "value": value_match.group(1) if value_match else ""
                    })

                    # Track parameter
                    self.parameters.add(name_match.group(1))

            if inputs:
                forms.append(Form(
                    action=action,
                    method=method,
                    inputs=inputs,
                    url=page_url
                ))

        return forms

    def _extract_parameters(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    def _extract_scripts(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript URLs"""
        scripts = []
        pattern = r'<script[^>]*src=["\']([^"\']+)["\']'

        for match in re.finditer(pattern, html, re.I):
            url = self._normalize_url(match.group(1), base_url)
            if url:
                scripts.append(url)

        return scripts

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract page title"""
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        return match.group(1).strip() if match else None

    def _detect_api_endpoints(self, html: str, scripts: List[str], base_url: str) -> List[str]:
        """Detect API endpoints from JavaScript and HTML"""
        api_endpoints = []

        # Common API patterns in HTML/JS
        patterns = [
            r'["\'](?:/api/[^"\']+)["\']',
            r'["\'](?:/v[0-9]+/[^"\']+)["\']',
            r'["\'](?:/graphql)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest[^}]*\.open\([^,]+,\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, html, re.I):
                endpoint = match.group(1) if match.lastindex else match.group(0).strip("\"'")
                if endpoint.startswith("/"):
                    parsed_base = urlparse(base_url)
                    endpoint = f"{parsed_base.scheme}://{parsed_base.netloc}{endpoint}"
                if self._is_same_domain(endpoint, base_url):
                    api_endpoints.append(endpoint)

        return list(set(api_endpoints))

    def _content_hash(self, content: str) -> str:
        """Generate hash of content for deduplication"""
        # Remove dynamic parts
        cleaned = re.sub(r'[0-9]+', '', content)
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return hashlib.md5(cleaned[:5000].encode()).hexdigest()

    # ==================== ROBOTS.TXT ====================

    async def parse_robots(self, base_url: str) -> Dict[str, List[str]]:
        """Parse robots.txt"""
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        resp, status, _ = await self._request(robots_url)

        result = {"disallow": [], "allow": [], "sitemap": []}

        if status == 200 and resp:
            lines = resp.split("\n")
            current_agent = None

            for line in lines:
                line = line.strip().lower()

                if line.startswith("user-agent:"):
                    agent = line.split(":", 1)[1].strip()
                    current_agent = agent

                elif line.startswith("disallow:") and current_agent in ["*", "allhackcrawler"]:
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["disallow"].append(path)

                elif line.startswith("allow:") and current_agent in ["*", "allhackcrawler"]:
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["allow"].append(path)

                elif line.startswith("sitemap:"):
                    sitemap = line.split(":", 1)[1].strip()
                    if ":" in sitemap:  # Has protocol
                        result["sitemap"].append(sitemap)

        self.disallowed_paths = result["disallow"]
        return result

    def _is_allowed(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt"""
        if not self.respect_robots or not self.disallowed_paths:
            return True

        parsed = urlparse(url)
        path = parsed.path

        for disallowed in self.disallowed_paths:
            if path.startswith(disallowed):
                return False

        return True

    # ==================== SITEMAP ====================

    async def parse_sitemap(self, sitemap_url: str) -> List[str]:
        """Parse sitemap.xml"""
        urls = []

        resp, status, _ = await self._request(sitemap_url)

        if status == 200 and resp:
            # Extract URLs
            loc_pattern = r'<loc>([^<]+)</loc>'
            for match in re.finditer(loc_pattern, resp):
                urls.append(match.group(1))

            # Check for sitemap index
            sitemap_pattern = r'<sitemap>.*?<loc>([^<]+)</loc>.*?</sitemap>'
            for match in re.finditer(sitemap_pattern, resp, re.DOTALL):
                sub_urls = await self.parse_sitemap(match.group(1))
                urls.extend(sub_urls)

        return urls[:500]  # Limit

    # ==================== MAIN CRAWL ====================

    async def crawl(self, start_url: str) -> CrawlResult:
        """Crawl website starting from URL"""
        await self._ensure_session()

        # Parse base URL
        parsed = urlparse(start_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        logger.info(f"Starting crawl of {base_url}")

        # Parse robots.txt
        robots = await self.parse_robots(base_url)
        sitemap_urls = []

        # Parse sitemaps
        for sitemap_url in robots.get("sitemap", [f"{base_url}/sitemap.xml"]):
            urls = await self.parse_sitemap(sitemap_url)
            sitemap_urls.extend(urls)
            for url in urls[:50]:  # Add some sitemap URLs to crawl queue
                if url not in self.visited:
                    self.queue.append((url, 0))

        # Add start URL
        self.queue.append((start_url, 0))

        # Crawl loop
        while self.queue and len(self.visited) < self.max_pages:
            url, depth = self.queue.popleft()

            # Skip if visited or too deep
            if url in self.visited or depth > self.max_depth:
                continue

            # Check robots.txt
            if not self._is_allowed(url):
                continue

            self.visited.add(url)
            logger.debug(f"Crawling: {url} (depth={depth})")

            # Fetch page
            html, status, headers = await self._request(url)

            if not html or status != 200:
                continue

            # Check for duplicate content
            content_hash = self._content_hash(html)
            if content_hash in self.content_hashes:
                continue
            self.content_hashes.add(content_hash)

            # Extract information
            links = self._extract_links(html, url)
            forms = self._extract_forms(html, url)
            scripts = self._extract_scripts(html, url)
            params = self._extract_parameters(url)
            title = self._extract_title(html)
            api_endpoints = self._detect_api_endpoints(html, scripts, base_url)

            # Store page
            page = CrawledPage(
                url=url,
                status=status,
                content_type=headers.get("Content-Type", ""),
                title=title,
                forms=[{"action": f.action, "method": f.method, "inputs": f.inputs} for f in forms],
                links=links,
                scripts=scripts,
                parameters=params,
                headers=headers,
                content_hash=content_hash
            )
            self.pages.append(page)
            self.forms.extend(forms)
            self.api_endpoints.extend(api_endpoints)
            self.parameters.update(params)

            # Add links to queue
            for link in links:
                if link not in self.visited:
                    self.queue.append((link, depth + 1))

        # Detect technologies
        technologies = self._detect_technologies()

        # Build result
        result = CrawlResult(
            base_url=base_url,
            pages_crawled=len(self.pages),
            endpoints=[p.url for p in self.pages],
            forms=self.forms,
            parameters=self.parameters,
            api_endpoints=list(set(self.api_endpoints)),
            scripts=list(set(s for p in self.pages for s in p.scripts)),
            technologies=technologies,
            sitemap_urls=sitemap_urls,
            robots_paths=robots
        )

        logger.info(f"Crawl complete: {len(self.pages)} pages, {len(self.forms)} forms, {len(self.parameters)} params")

        return result

    def _detect_technologies(self) -> List[str]:
        """Detect technologies from crawled data"""
        technologies = set()

        tech_patterns = {
            "WordPress": [r"wp-content", r"wp-includes"],
            "Drupal": [r"/sites/all", r"drupal"],
            "Joomla": [r"joomla", r"/administrator"],
            "React": [r"react", r"_reactRoot"],
            "Vue": [r"vue", r"__vue__"],
            "Angular": [r"ng-app", r"angular"],
            "jQuery": [r"jquery"],
            "Bootstrap": [r"bootstrap"],
            "Laravel": [r"laravel"],
            "Django": [r"csrfmiddlewaretoken"],
            "Express": [r"express"],
            "GraphQL": [r"graphql", r"__schema"],
        }

        all_content = " ".join(p.url + str(p.scripts) for p in self.pages)

        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, all_content, re.I):
                    technologies.add(tech)
                    break

        return list(technologies)

    async def close(self):
        """Close session"""
        if self.session:
            await self.session.close()
