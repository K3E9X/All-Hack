"""
Screenshot Service using Playwright

Captures screenshots of vulnerable pages for documentation
"""

import asyncio
import os
import base64
from datetime import datetime
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Screenshot storage directory
SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "screenshots")


class ScreenshotService:
    """Async screenshot capture service using Playwright"""

    def __init__(self):
        self.browser = None
        self.playwright = None
        self._initialized = False

    async def initialize(self):
        """Initialize Playwright browser"""
        if self._initialized:
            return

        try:
            from playwright.async_api import async_playwright
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox"]
            )
            self._initialized = True
            os.makedirs(SCREENSHOT_DIR, exist_ok=True)
            logger.info("Screenshot service initialized")
        except ImportError:
            logger.warning("Playwright not installed. Screenshots disabled.")
            logger.warning("Install with: pip install playwright && playwright install chromium")
        except Exception as e:
            logger.error(f"Failed to initialize screenshot service: {e}")

    async def close(self):
        """Close browser and cleanup"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        self._initialized = False

    async def capture(
        self,
        url: str,
        finding_id: str,
        full_page: bool = False,
        timeout: int = 10000
    ) -> Optional[str]:
        """
        Capture screenshot of a URL

        Args:
            url: URL to capture
            finding_id: Unique ID for the finding
            full_page: Capture full scrollable page
            timeout: Page load timeout in ms

        Returns:
            Path to saved screenshot or None on failure
        """
        if not self._initialized:
            await self.initialize()

        if not self.browser:
            return None

        try:
            context = await self.browser.new_context(
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True
            )
            page = await context.new_page()

            await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            await page.wait_for_timeout(1000)  # Wait for JS to settle

            filename = f"{finding_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            filepath = os.path.join(SCREENSHOT_DIR, filename)

            await page.screenshot(path=filepath, full_page=full_page)
            await context.close()

            logger.info(f"Screenshot saved: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Screenshot capture failed for {url}: {e}")
            return None

    async def capture_with_payload(
        self,
        url: str,
        finding_id: str,
        highlight_element: Optional[str] = None
    ) -> Optional[str]:
        """
        Capture screenshot with optional element highlighting

        Args:
            url: URL to capture (already contains payload)
            finding_id: Unique ID for the finding
            highlight_element: CSS selector to highlight

        Returns:
            Path to saved screenshot or None
        """
        if not self._initialized:
            await self.initialize()

        if not self.browser:
            return None

        try:
            context = await self.browser.new_context(
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True
            )
            page = await context.new_page()

            await page.goto(url, timeout=10000, wait_until="domcontentloaded")
            await page.wait_for_timeout(500)

            # Add highlight styling if element selector provided
            if highlight_element:
                await page.evaluate(f"""
                    (() => {{
                        const el = document.querySelector('{highlight_element}');
                        if (el) {{
                            el.style.border = '3px solid red';
                            el.style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
                        }}
                    }})();
                """)

            # Add annotation overlay
            await page.evaluate("""
                (() => {
                    const overlay = document.createElement('div');
                    overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;background:rgba(255,0,0,0.9);color:white;padding:8px;font-family:monospace;font-size:14px;z-index:99999;text-align:center;';
                    overlay.textContent = 'VULNERABILITY PROOF - ' + window.location.href;
                    document.body.prepend(overlay);
                })();
            """)

            filename = f"{finding_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            filepath = os.path.join(SCREENSHOT_DIR, filename)

            await page.screenshot(path=filepath, full_page=False)
            await context.close()

            logger.info(f"Annotated screenshot saved: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Annotated screenshot failed for {url}: {e}")
            return None

    async def capture_to_base64(self, url: str) -> Optional[str]:
        """Capture screenshot and return as base64 string"""
        if not self._initialized:
            await self.initialize()

        if not self.browser:
            return None

        try:
            context = await self.browser.new_context(
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True
            )
            page = await context.new_page()

            await page.goto(url, timeout=10000, wait_until="domcontentloaded")
            await page.wait_for_timeout(500)

            screenshot_bytes = await page.screenshot(full_page=False)
            await context.close()

            return base64.b64encode(screenshot_bytes).decode("utf-8")

        except Exception as e:
            logger.error(f"Base64 screenshot failed for {url}: {e}")
            return None


# Global instance
_screenshot_service: Optional[ScreenshotService] = None


def get_screenshot_service() -> ScreenshotService:
    """Get or create screenshot service singleton"""
    global _screenshot_service
    if _screenshot_service is None:
        _screenshot_service = ScreenshotService()
    return _screenshot_service


async def capture_finding_screenshot(url: str, finding_id: str) -> Optional[str]:
    """Convenience function to capture a finding screenshot"""
    service = get_screenshot_service()
    return await service.capture_with_payload(url, finding_id)
