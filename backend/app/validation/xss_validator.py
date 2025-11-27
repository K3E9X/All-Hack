"""
XSS PoC Validator

Validates XSS by executing JavaScript in headless browser.
"""
import logging
import asyncio
from typing import Optional

from app.validation.base_validator import BaseValidator, ValidationStatus, ValidationResult
from app.utils import PentestHTTPClient

logger = logging.getLogger(__name__)

class XSSValidator(BaseValidator):
    """
    Validates XSS vulnerabilities

    Uses headless browser to confirm JavaScript execution.
    Falls back to response analysis if browser not available.
    """

    # Test payloads
    TEST_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg/onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "';alert('XSS');//",
    ]

    def _is_applicable(self, vulnerability: any) -> bool:
        """Check if XSS validator applies"""
        vuln_category = getattr(vulnerability, 'category', '')
        if hasattr(vuln_category, 'value'):
            vuln_category = vuln_category.value

        return 'xss' in str(vuln_category).lower() or 'cross' in str(vuln_category).lower()

    async def validate(
        self,
        vulnerability: any,
        target_url: str,
        client: Optional[PentestHTTPClient] = None,
        **kwargs
    ) -> Optional[ValidationResult]:
        """
        Validate XSS by testing JavaScript execution

        Args:
            vulnerability: Vulnerability object
            target_url: Base URL
            client: HTTP client
            **kwargs: Additional params

        Returns:
            ValidationResult with evidence
        """
        if not self._is_applicable(vulnerability):
            return None

        logger.info(f"🔍 Validating XSS: {vulnerability.title}")

        if client is None:
            client = PentestHTTPClient(base_url=target_url)

        vuln_url = getattr(vulnerability, 'affected_url', target_url)
        vuln_param = getattr(vulnerability, 'affected_parameter', None)

        # Try browser-based validation (if available)
        browser_result = await self._validate_with_browser(vuln_url, vuln_param)
        if browser_result:
            return browser_result

        # Fallback: Response analysis
        response_result = await self._validate_with_response(client, vuln_url, vuln_param)
        if response_result:
            return response_result

        # Could not confirm
        return self._create_result(
            status=ValidationStatus.UNCONFIRMED,
            confidence=0.3,
            evidence="Could not confirm XSS execution",
            details={"reason": "No JavaScript execution detected"}
        )

    async def _validate_with_browser(
        self,
        url: str,
        param: Optional[str]
    ) -> Optional[ValidationResult]:
        """
        Validate XSS using headless browser

        Requires playwright or selenium installed.
        """
        try:
            # Try importing playwright
            from playwright.async_api import async_playwright

            logger.info("🌐 Using headless browser for XSS validation")

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                # Set up alert handler
                alert_detected = []

                async def handle_dialog(dialog):
                    alert_detected.append(dialog.message)
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)

                # Try payloads
                for payload in self.TEST_PAYLOADS[:3]:  # Test first 3
                    test_url = self._inject_payload(url, param, payload)

                    try:
                        await page.goto(test_url, timeout=10000, wait_until="networkidle")
                        await asyncio.sleep(1)  # Wait for alerts

                        if alert_detected:
                            logger.info(f"✅ XSS CONFIRMED: Alert triggered with message '{alert_detected[0]}'")

                            await browser.close()

                            return self._create_result(
                                status=ValidationStatus.CONFIRMED,
                                confidence=1.0,
                                evidence=f"JavaScript alert executed in browser: {alert_detected[0]}",
                                details={
                                    "alert_message": alert_detected[0],
                                    "payload": payload,
                                    "method": "headless_browser"
                                }
                            )

                    except Exception as e:
                        logger.debug(f"Browser test failed for {payload}: {e}")
                        continue

                await browser.close()

        except ImportError:
            logger.debug("Playwright not available, skipping browser validation")
        except Exception as e:
            logger.debug(f"Browser validation error: {e}")

        return None

    async def _validate_with_response(
        self,
        client: PentestHTTPClient,
        url: str,
        param: Optional[str]
    ) -> Optional[ValidationResult]:
        """
        Validate XSS by checking if payload appears unescaped in response

        Less definitive than browser test, but faster.
        """
        for payload in self.TEST_PAYLOADS:
            try:
                test_url = self._inject_payload(url, param, payload)
                response = await client.get(test_url)

                if not response:
                    continue

                content = response.text

                # Check if payload appears unescaped
                if payload in content:
                    logger.info(f"✅ XSS LIKELY: Payload reflected unescaped")

                    return self._create_result(
                        status=ValidationStatus.LIKELY,
                        confidence=0.75,
                        evidence=f"XSS payload reflected unescaped in response",
                        details={
                            "payload": payload,
                            "method": "response_analysis",
                            "note": "Browser validation recommended for confirmation"
                        }
                    )

                # Check for partially escaped payload (might still be exploitable)
                # Remove < > from payload and check
                escaped_indicators = [
                    payload.replace('<', '&lt;').replace('>', '&gt;'),
                    payload.replace('<', '\\u003c').replace('>', '\\u003e'),
                ]

                for escaped in escaped_indicators:
                    if escaped in content and payload not in content:
                        # Escaped, but let's check context
                        logger.debug(f"Payload escaped in response")
                        break

            except Exception as e:
                logger.debug(f"Response validation failed: {e}")
                continue

        return None

    def _inject_payload(self, url: str, param: Optional[str], payload: str) -> str:
        """Inject XSS payload into URL"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

        if not param:
            separator = '&' if '?' in url else '?'
            return f"{url}{separator}test={quote(payload)}"

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        if param in query_params:
            query_params[param] = [payload]
        else:
            query_params[param] = [payload]

        new_query = urlencode(query_params, doseq=True, quote_via=quote)
        new_parsed = parsed._replace(query=new_query)

        return urlunparse(new_parsed)
