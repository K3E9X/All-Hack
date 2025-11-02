"""Dynamic crawling using a headless browser to discover JavaScript-heavy routes."""

from __future__ import annotations

import asyncio
import logging
from typing import List, Set
from urllib.parse import urljoin, urlparse

from app.models import EndpointInfo

logger = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    from playwright.async_api import async_playwright  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    async_playwright = None  # type: ignore


class BrowserCrawler:
    """Headless browser crawler capturing client-side routes and network requests."""

    def __init__(
        self,
        base_url: str,
        max_pages: int = 40,
        wait_ms: int = 1500,
        headless: bool = True,
    ):
        self.base_url = base_url
        self.max_pages = max_pages
        self.wait_ms = wait_ms
        self.headless = headless

    async def crawl(self) -> List[EndpointInfo]:
        if not async_playwright:
            logger.warning("Playwright is not installed; skipping browser-based crawling")
            return []

        discovered: Set[str] = set()
        endpoints: List[EndpointInfo] = []
        parsed = urlparse(self.base_url)
        base_domain = parsed.netloc

        async with async_playwright() as playwright:  # type: ignore
            browser = await playwright.chromium.launch(headless=self.headless)
            context = await browser.new_context()
            page = await context.new_page()

            async def track_request(request):
                try:
                    url = request.url
                    if urlparse(url).netloc == base_domain:
                        discovered.add(url)
                except Exception:
                    logger.debug("Failed to analyze browser request: %s", request.url)

            page.on("requestfinished", track_request)

            queue = [self.base_url]
            visited: Set[str] = set()

            while queue and len(visited) < self.max_pages:
                current = queue.pop(0)
                if current in visited:
                    continue

                visited.add(current)

                try:
                    await page.goto(current, wait_until="networkidle")
                    await asyncio.sleep(self.wait_ms / 1000)
                except Exception as exc:  # pragma: no cover - network flakiness
                    logger.debug("Browser crawl failed for %s: %s", current, exc)
                    continue

                try:
                    anchors = await page.eval_on_selector_all(
                        "a[href]",
                        "elements => elements.map(a => a.href)",
                    )
                except Exception:
                    anchors = []

                for href in anchors:
                    if not isinstance(href, str):
                        continue
                    normalized = urljoin(current, href)
                    if urlparse(normalized).netloc == base_domain and normalized not in visited:
                        queue.append(normalized)
                        discovered.add(normalized)

            await browser.close()

        for url in sorted(discovered):
            endpoints.append(
                EndpointInfo(
                    url=url,
                    method="GET",
                    status_code=200,
                    requires_auth=False,
                    parameters=[],
                    headers={},
                )
            )

        logger.info("Browser crawler discovered %s potential routes", len(endpoints))
        return endpoints

