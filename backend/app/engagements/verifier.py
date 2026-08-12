"""Authorization verification (spec §8).

Two automatic methods prove the operator controls the target:

  * DNS TXT  - a TXT record `syphax-verify=<token>` on the target host.
  * WELL_KNOWN - a file at https://host/.well-known/syphax-<token>.txt
    whose body is exactly the token.

A MANUAL method exists for signed-authorization uploads but is approved
out-of-band (not implemented here).

Both checks are deliberately strict and side-effect free. No scan, no tool,
nothing touches the target before one of these passes.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from app.engagements.models import Engagement, VerificationMethod

logger = logging.getLogger("syphax.engagements.verifier")


@dataclass
class VerificationResult:
    ok: bool
    method: Optional[VerificationMethod]
    detail: str


class AuthorizationVerifier:
    def __init__(self, http_timeout: float = 10.0, dns_timeout: float = 5.0) -> None:
        self.http_timeout = http_timeout
        self.dns_timeout = dns_timeout

    async def verify(self, engagement: Engagement) -> VerificationResult:
        """Try DNS first (cheap, no connection to the target app), then the
        .well-known file. Returns on the first success."""
        token = engagement.verification_token
        host = engagement.target_host

        dns = await self._verify_dns(host, token)
        if dns.ok:
            return dns

        well_known = await self._verify_well_known(host, token)
        if well_known.ok:
            return well_known

        return VerificationResult(
            ok=False,
            method=None,
            detail=(
                f"Neither DNS TXT (syphax-verify={token} on {host}) nor "
                f"https://{host}/.well-known/syphax-{token}.txt could be confirmed. "
                f"DNS: {dns.detail} | well-known: {well_known.detail}"
            ),
        )

    async def _verify_dns(self, host: str, token: str) -> VerificationResult:
        expected = f"syphax-verify={token}"
        try:
            import dns.asyncresolver  # dnspython

            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = self.dns_timeout
            answers = await resolver.resolve(host, "TXT")
            for rdata in answers:
                # Each TXT record can be a list of byte strings; join them.
                value = b"".join(getattr(rdata, "strings", [])).decode("utf-8", "replace")
                if not value:
                    value = str(rdata).strip('"')
                if value.strip() == expected:
                    return VerificationResult(True, VerificationMethod.DNS_TXT, "TXT record matched")
            return VerificationResult(False, None, "no matching TXT record")
        except ModuleNotFoundError:
            return VerificationResult(False, None, "dnspython not installed")
        except Exception as exc:  # noqa: BLE001 - resolver raises many types
            return VerificationResult(False, None, f"DNS lookup failed: {type(exc).__name__}")

    async def _verify_well_known(self, host: str, token: str) -> VerificationResult:
        url = f"https://{host}/.well-known/syphax-{token}.txt"
        try:
            async with httpx.AsyncClient(
                timeout=self.http_timeout, follow_redirects=False, verify=True
            ) as client:
                resp = await client.get(url)
            if resp.status_code != 200:
                return VerificationResult(False, None, f"HTTP {resp.status_code}")
            body = (resp.text or "").strip()
            if body == token:
                return VerificationResult(
                    True, VerificationMethod.WELL_KNOWN, "well-known file matched"
                )
            return VerificationResult(False, None, "file content did not match token")
        except Exception as exc:  # noqa: BLE001
            return VerificationResult(False, None, f"fetch failed: {type(exc).__name__}")


_verifier: Optional[AuthorizationVerifier] = None


def get_verifier() -> AuthorizationVerifier:
    global _verifier
    if _verifier is None:
        _verifier = AuthorizationVerifier()
    return _verifier
