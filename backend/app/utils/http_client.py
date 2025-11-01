"""
HTTP client utilities for pentest operations
"""
import httpx
import asyncio
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin, urlparse
import logging
from app.config import settings

logger = logging.getLogger(__name__)

class PentestHTTPClient:
    """
    Async HTTP client for pentest operations with rate limiting and error handling
    """

    def __init__(
        self,
        base_url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth_token: Optional[str] = None,
        rate_limit: int = 10
    ):
        self.base_url = base_url
        self.rate_limit = rate_limit
        self.request_count = 0

        # Setup headers
        self.headers = {
            "User-Agent": settings.USER_AGENT,
            **(headers or {})
        }

        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"

        self.cookies = cookies or {}

        # Rate limiting
        self.rate_limiter = asyncio.Semaphore(rate_limit)

    async def _make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[httpx.Response]:
        """Make HTTP request with rate limiting"""
        async with self.rate_limiter:
            try:
                async with httpx.AsyncClient(
                    timeout=settings.REQUEST_TIMEOUT,
                    follow_redirects=True,
                    verify=False  # For testing, ignore SSL errors
                ) as client:
                    response = await client.request(
                        method,
                        url,
                        headers={**self.headers, **kwargs.get("headers", {})},
                        cookies={**self.cookies, **kwargs.get("cookies", {})},
                        **{k: v for k, v in kwargs.items() if k not in ["headers", "cookies"]}
                    )
                    self.request_count += 1
                    return response
            except Exception as e:
                logger.error(f"Request failed for {url}: {e}")
                return None

    async def get(self, path: str = "", **kwargs) -> Optional[httpx.Response]:
        """GET request"""
        url = urljoin(self.base_url, path)
        return await self._make_request("GET", url, **kwargs)

    async def post(self, path: str = "", **kwargs) -> Optional[httpx.Response]:
        """POST request"""
        url = urljoin(self.base_url, path)
        return await self._make_request("POST", url, **kwargs)

    async def put(self, path: str = "", **kwargs) -> Optional[httpx.Response]:
        """PUT request"""
        url = urljoin(self.base_url, path)
        return await self._make_request("PUT", url, **kwargs)

    async def delete(self, path: str = "", **kwargs) -> Optional[httpx.Response]:
        """DELETE request"""
        url = urljoin(self.base_url, path)
        return await self._make_request("DELETE", url, **kwargs)

    async def patch(self, path: str = "", **kwargs) -> Optional[httpx.Response]:
        """PATCH request"""
        url = urljoin(self.base_url, path)
        return await self._make_request("PATCH", url, **kwargs)

    async def options(self, path: str = "", **kwargs) -> Optional[httpx.Response]:
        """OPTIONS request"""
        url = urljoin(self.base_url, path)
        return await self._make_request("OPTIONS", url, **kwargs)

    async def head(self, path: str = "", **kwargs) -> Optional[httpx.Response]:
        """HEAD request"""
        url = urljoin(self.base_url, path)
        return await self._make_request("HEAD", url, **kwargs)

    async def test_multiple_methods(self, path: str) -> Dict[str, Any]:
        """Test multiple HTTP methods on an endpoint"""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        results = {}

        for method in methods:
            response = await self._make_request(method, urljoin(self.base_url, path))
            if response:
                results[method] = {
                    "status_code": response.status_code,
                    "allowed": response.status_code not in [404, 405, 501]
                }

        return results

def extract_forms(html_content: str) -> List[Dict[str, Any]]:
    """Extract forms from HTML content"""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html_content, 'lxml')
    forms = []

    for form in soup.find_all('form'):
        form_data = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').upper(),
            'inputs': []
        }

        for input_tag in form.find_all(['input', 'textarea']):
            form_data['inputs'].append({
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', '')
            })

        forms.append(form_data)

    return forms

def extract_links(html_content: str, base_url: str) -> List[str]:
    """Extract links from HTML content"""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html_content, 'lxml')
    links = set()

    for link in soup.find_all(['a', 'link']):
        href = link.get('href')
        if href:
            absolute_url = urljoin(base_url, href)
            # Only keep same domain links
            if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                links.add(absolute_url)

    return list(links)

def parse_robots_txt(content: str) -> Dict[str, List[str]]:
    """Parse robots.txt content"""
    disallowed = []
    allowed = []
    sitemaps = []

    for line in content.split('\n'):
        line = line.strip()
        if line.lower().startswith('disallow:'):
            path = line.split(':', 1)[1].strip()
            if path:
                disallowed.append(path)
        elif line.lower().startswith('allow:'):
            path = line.split(':', 1)[1].strip()
            if path:
                allowed.append(path)
        elif line.lower().startswith('sitemap:'):
            sitemap = line.split(':', 1)[1].strip()
            if sitemap:
                sitemaps.append(sitemap)

    return {
        'disallowed': disallowed,
        'allowed': allowed,
        'sitemaps': sitemaps
    }
