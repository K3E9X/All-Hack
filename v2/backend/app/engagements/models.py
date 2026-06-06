"""Engagement domain model.

An *engagement* is the unit of authorized testing: a verified target + its
scope + the budget the operator allots. Nothing scans until the engagement
reaches the AUTHORIZED state via a proof of ownership (spec §8).
"""
from __future__ import annotations

import enum
import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class EngagementStatus(str, enum.Enum):
    # Created, target recorded, awaiting an authorization proof.
    PENDING_AUTHORIZATION = "pending_authorization"
    # Ownership verified; scans may run.
    AUTHORIZED = "authorized"
    # Operator stopped it / it finished.
    CLOSED = "closed"
    # Verification explicitly failed or was revoked.
    REVOKED = "revoked"


class VerificationMethod(str, enum.Enum):
    DNS_TXT = "dns_txt"            # TXT record allhack-verify=<token> on the apex
    WELL_KNOWN = "well_known"      # GET https://host/.well-known/allhack-<token>.txt
    MANUAL = "manual"             # operator uploaded signed written authorization


def _new_token() -> str:
    # URL/DNS-safe, short enough to paste, long enough to be unforgeable.
    return secrets.token_hex(16)


def new_engagement_id() -> str:
    return f"eng_{int(time.time() * 1000)}_{secrets.token_hex(3)}"


@dataclass
class Engagement:
    id: str
    target_url: str
    target_host: str
    scope_hosts: List[str]            # allow-list of hostnames in scope
    status: EngagementStatus
    verification_token: str
    created_at: float
    title: str = ""
    notes: str = ""
    verification_method: Optional[VerificationMethod] = None
    verified_at: Optional[float] = None
    closed_at: Optional[float] = None
    # Budget guardrails (enforced by the orchestrator later).
    budget_requests: Optional[int] = None
    budget_seconds: Optional[int] = None
    # Operator attestation (the legal checkbox) - timestamp when accepted.
    attested_at: Optional[float] = None
    # Pause before the exploitation phase and wait for human approval.
    require_exploit_approval: bool = False

    # ----- factory -----
    @classmethod
    def create(
        cls,
        target_url: str,
        *,
        title: str = "",
        notes: str = "",
        scope_hosts: Optional[List[str]] = None,
        budget_requests: Optional[int] = None,
        budget_seconds: Optional[int] = None,
        attested: bool = False,
        require_exploit_approval: bool = False,
    ) -> "Engagement":
        host = _host_of(target_url)
        scope = scope_hosts or [host]
        # Always include the primary host in scope.
        if host not in scope:
            scope = [host] + scope
        return cls(
            id=new_engagement_id(),
            target_url=target_url,
            target_host=host,
            scope_hosts=scope,
            status=EngagementStatus.PENDING_AUTHORIZATION,
            verification_token=_new_token(),
            created_at=time.time(),
            title=title or host,
            notes=notes,
            budget_requests=budget_requests,
            budget_seconds=budget_seconds,
            attested_at=time.time() if attested else None,
            require_exploit_approval=require_exploit_approval,
        )

    # ----- scope check -----
    def host_in_scope(self, host: str) -> bool:
        host = (host or "").lower().strip()
        for allowed in self.scope_hosts:
            allowed = allowed.lower().strip()
            if host == allowed:
                return True
            # allow subdomains of an in-scope apex when the entry starts with '.'
            if allowed.startswith(".") and host.endswith(allowed):
                return True
        return False

    def url_in_scope(self, url: str) -> bool:
        return self.host_in_scope(_host_of(url))

    # ----- serialization -----
    def to_public(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["verification_method"] = (
            self.verification_method.value if self.verification_method else None
        )
        # The token itself is needed by the UI to render the challenge, but
        # never leak it once authorized.
        if self.status != EngagementStatus.PENDING_AUTHORIZATION:
            d["verification_token"] = None
        return d

    def challenge(self) -> Dict[str, Any]:
        """How the operator proves ownership. Shown in the UI."""
        token = self.verification_token
        return {
            "token": token,
            "methods": {
                "dns_txt": {
                    "record_name": self.target_host,
                    "record_type": "TXT",
                    "record_value": f"allhack-verify={token}",
                    "instructions": (
                        f"Add a TXT record on {self.target_host} with value "
                        f"'allhack-verify={token}', then verify."
                    ),
                },
                "well_known": {
                    "url": f"https://{self.target_host}/.well-known/allhack-{token}.txt",
                    "file_content": token,
                    "instructions": (
                        f"Serve a file at "
                        f"https://{self.target_host}/.well-known/allhack-{token}.txt "
                        f"containing exactly '{token}', then verify."
                    ),
                },
            },
        }


def _host_of(url: str) -> str:
    if "://" in url:
        return (urlparse(url).hostname or url).lower()
    return url.split("/", 1)[0].lower()


def scope_to_json(scope: List[str]) -> str:
    return json.dumps(scope)


def scope_from_json(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    try:
        v = json.loads(raw)
        return [str(x) for x in v] if isinstance(v, list) else []
    except json.JSONDecodeError:
        return []
