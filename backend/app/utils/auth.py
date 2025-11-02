"""Advanced authentication orchestration utilities."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional

try:
    import pyotp  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    pyotp = None  # type: ignore

from app.utils.http_client import PentestHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class AuthStepResult:
    """Summary of an executed authentication step."""

    index: int
    method: str
    path: str
    status_code: Optional[int]
    notes: Optional[str] = None


class AdvancedAuthManager:
    """Execute complex, multi-step authentication flows for grey-box scans."""

    def __init__(self, client: PentestHTTPClient):
        self.client = client

    async def execute_sequence(
        self,
        sequence: List[Dict[str, Any]],
        totp_secret: Optional[str] = None,
    ) -> List[AuthStepResult]:
        """
        Execute a sequence of authentication requests.

        Args:
            sequence: List of request descriptors. Each descriptor may contain:
                - method: HTTP verb (default GET)
                - path: request path relative to base URL
                - data/json: body payload
                - headers: custom headers
                - capture: {"response_json": ["token"], "cookies": True}
                - store_tokens: bool indicating if cookies/headers should be
                  persisted on the shared HTTP client
                - inject_totp: bool to automatically add a TOTP code
                - totp_field: name of the field used for the TOTP code (default "otp")
            totp_secret: Optional base32 secret to generate OTP codes.

        Returns:
            List of step execution summaries.
        """

        results: List[AuthStepResult] = []

        for index, step in enumerate(sequence):
            method = (step.get("method") or "GET").upper()
            path = step.get("path") or "/"
            payload: Dict[str, Any] = {}
            headers: Dict[str, str] = step.get("headers", {})
            json_payload = step.get("json")
            data_payload = step.get("data")

            if step.get("inject_totp") and totp_secret:
                otp_value = self._generate_totp(totp_secret)
                field_name = step.get("totp_field", "otp")

                if json_payload is not None:
                    json_payload = dict(json_payload)
                    json_payload[field_name] = otp_value
                else:
                    data_payload = data_payload or {}
                    if isinstance(data_payload, dict):
                        data_payload[field_name] = otp_value
                    else:
                        payload[field_name] = otp_value
                logger.debug("Injected TOTP value for step %s", index)

            request_kwargs: Dict[str, Any] = {}
            if headers:
                request_kwargs["headers"] = headers
            if json_payload is not None:
                request_kwargs["json"] = json_payload
            if data_payload is not None:
                request_kwargs["data"] = data_payload
            if payload:
                request_kwargs.setdefault("data", {}).update(payload)

            request_func = getattr(self.client, method.lower(), None)
            if not request_func:
                logger.warning("Unsupported auth method '%s' in step %s", method, index)
                continue

            response = await request_func(path, **request_kwargs)
            status_code = response.status_code if response else None

            notes: Optional[str] = None

            if response is not None:
                if step.get("store_tokens"):
                    self._store_tokens(response)
                    notes = "Stored authentication tokens"

                capture_cfg = step.get("capture") or {}
                if capture_cfg.get("response_json"):
                    try:
                        json_body = response.json()
                        for json_key in capture_cfg["response_json"]:
                            token_value = json_body
                            for fragment in json_key.split('.'):
                                if isinstance(token_value, dict):
                                    token_value = token_value.get(fragment)
                                else:
                                    token_value = None
                                    break
                            if token_value:
                                header_name = capture_cfg.get("as_header") or "Authorization"
                                self.client.headers[header_name] = (
                                    f"Bearer {token_value}" if header_name.lower() == "authorization" else str(token_value)
                                )
                                notes = (notes or "") + f" Captured {json_key}."
                    except Exception:  # pragma: no cover - defensive
                        logger.debug("Failed to parse JSON response for auth capture")

            results.append(
                AuthStepResult(
                    index=index,
                    method=method,
                    path=path,
                    status_code=status_code,
                    notes=notes,
                )
            )

        return results

    @staticmethod
    def _generate_totp(secret: str) -> str:
        if not pyotp:  # pragma: no cover - optional dependency
            logger.warning("pyotp is not installed; skipping TOTP generation")
            return "000000"

        try:
            return pyotp.TOTP(secret).now()
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to generate TOTP: %s", exc)
            return "000000"

    def _store_tokens(self, response: Any) -> None:
        """Persist cookies and headers from an authentication response."""

        try:
            for cookie_name, cookie_value in response.cookies.items():
                self.client.cookies[cookie_name] = cookie_value

            if "set-cookie" in response.headers:
                raw_cookie = response.headers["set-cookie"]
                parsed = SimpleCookie()
                parsed.load(raw_cookie)
                for key, morsel in parsed.items():
                    self.client.cookies[key] = morsel.value
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Failed to persist auth cookies: %s", exc)


def parse_auth_sequence(sequence_text: str) -> Optional[List[Dict[str, Any]]]:
    """Parse a JSON string representing an authentication sequence."""

    if not sequence_text:
        return None

    try:
        parsed = json.loads(sequence_text)
        if isinstance(parsed, list):
            return parsed
        logger.warning("Auth sequence JSON should be a list; got %s", type(parsed))
        return None
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse auth sequence JSON: %s", exc)
        raise

