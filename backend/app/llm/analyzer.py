"""LLM copilot: turn proxy captures and scan findings into actionable output.

Three public methods, all async:

  - suggest_attacks(flow)  -> structured JSON: suspicious parameters + scan proposals
  - explain_findings(job)  -> markdown section per finding (human-readable)
  - generate_report(...)   -> full markdown pentest report

The module is careful with context size: large request/response bodies and
long finding lists are truncated before being sent to the model so the free
tier (typically 8-32k context) does not overflow.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.llm.client import LLMClient, LLMError
from app.llm.prompts import (
    EXPLAIN_FINDINGS_SYSTEM,
    EXPLAIN_FINDINGS_USER,
    REPORT_SYSTEM,
    REPORT_USER,
    SUGGEST_ATTACKS_SYSTEM,
    SUGGEST_ATTACKS_USER,
)

logger = logging.getLogger("syphax.llm.analyzer")

# Body preview caps sent to the model. Small on purpose: the LLM only needs
# enough signal to spot parameter shapes, auth scheme, framework hints.
REQUEST_BODY_PREVIEW_CHARS = 2000
RESPONSE_BODY_PREVIEW_CHARS = 2000
HEADERS_PREVIEW_LIMIT = 30
FINDINGS_JSON_CHAR_CAP = 20000


@dataclass
class SuggestionResult:
    raw: str
    parsed: Optional[Dict[str, Any]]
    parse_error: Optional[str]

    def to_public(self) -> Dict[str, Any]:
        return {
            "parsed": self.parsed,
            "raw": self.raw,
            "parse_error": self.parse_error,
        }


class Analyzer:
    def __init__(self, client: LLMClient) -> None:
        self.client = client

    async def suggest_attacks(self, flow: Dict[str, Any]) -> SuggestionResult:
        ctx = _flow_to_context(flow)
        user = SUGGEST_ATTACKS_USER.format(**ctx)
        raw = await self.client.chat(
            [
                {"role": "system", "content": SUGGEST_ATTACKS_SYSTEM},
                {"role": "user", "content": user},
            ],
            temperature=0.1,
            max_tokens=1500,
        )
        parsed, parse_error = _extract_json(raw)
        if parsed is not None:
            parsed = _sanitize_suggestions(parsed)
        return SuggestionResult(raw=raw, parsed=parsed, parse_error=parse_error)

    async def explain_findings(self, job: Dict[str, Any]) -> str:
        findings = job.get("findings") or []
        findings_json = _truncate_json(findings, FINDINGS_JSON_CHAR_CAP)
        user = EXPLAIN_FINDINGS_USER.format(
            tool=job.get("tool", ""),
            target=job.get("target", ""),
            options=" ".join(job.get("args") or []) or "(none)",
            exit_code=job.get("exit_code"),
            findings_count=len(findings),
            findings_json=findings_json,
        )
        return await self.client.chat(
            [
                {"role": "system", "content": EXPLAIN_FINDINGS_SYSTEM},
                {"role": "user", "content": user},
            ],
            temperature=0.2,
            max_tokens=2500,
        )

    async def generate_report(
        self,
        *,
        title: str,
        scope: str,
        hosts: List[Dict[str, Any]],
        jobs: List[Dict[str, Any]],
    ) -> str:
        findings: List[Dict[str, Any]] = []
        jobs_summary_lines: List[str] = []

        for j in jobs:
            jobs_summary_lines.append(
                f"- {j.get('tool')} on {j.get('target')} "
                f"(status={j.get('status')}, findings={len(j.get('findings') or [])})"
            )
            for f in j.get("findings") or []:
                # Copy to avoid mutating the source.
                f2 = dict(f)
                f2["_from_job"] = j.get("id")
                f2["_tool"] = j.get("tool")
                findings.append(f2)

        hosts_block = "\n".join(
            f"- {h['host']} ({h['count']} flows)" for h in hosts[:20]
        ) or "- (none captured)"
        jobs_block = "\n".join(jobs_summary_lines[:20]) or "- (no jobs)"
        findings_json = _truncate_json(findings, FINDINGS_JSON_CHAR_CAP)

        user = REPORT_USER.format(
            title=title or "Penetration Test Report",
            scope=scope or "(no scope note provided)",
            hosts=hosts_block,
            jobs_summary=jobs_block,
            findings_json=findings_json,
        )
        return await self.client.chat(
            [
                {"role": "system", "content": REPORT_SYSTEM},
                {"role": "user", "content": user},
            ],
            temperature=0.2,
            max_tokens=4000,
        )


# ----- helpers -----

def _flow_to_context(
    flow: Dict[str, Any],
    *,
    req_cap: int = REQUEST_BODY_PREVIEW_CHARS,
    resp_cap: int = RESPONSE_BODY_PREVIEW_CHARS,
) -> Dict[str, Any]:
    """Flatten a stored flow into prompt-ready strings.

    The body caps are parameters so a long-context caller (llm_recon) can feed
    far more of each response than the small default used by the copilot.
    """
    req_headers = _format_headers(flow.get("request_headers"))
    resp_headers = _format_headers(flow.get("response_headers"))
    req_body = _body_to_str(flow.get("request_body_preview"), req_cap)
    resp_body = _body_to_str(flow.get("response_body_preview"), resp_cap)
    return {
        "method": flow.get("method", ""),
        "url": flow.get("url", ""),
        "request_headers": req_headers,
        "request_content_type": flow.get("request_content_type") or "(none)",
        "request_body_preview": req_body or "(empty)",
        "status_code": flow.get("status_code"),
        "response_content_type": flow.get("response_content_type") or "(none)",
        "response_headers": resp_headers,
        "response_body_preview": resp_body or "(empty)",
    }


def _format_headers(headers: Optional[List[List[str]]]) -> str:
    if not headers:
        return "(none)"
    trimmed = headers[:HEADERS_PREVIEW_LIMIT]
    lines = [f"{name}: {value}" for name, value in trimmed]
    extra = len(headers) - len(trimmed)
    if extra > 0:
        lines.append(f"... ({extra} more)")
    return "\n".join(lines)


def _body_to_str(body_preview: Optional[Dict[str, Any]], cap: int) -> str:
    if not body_preview or not body_preview.get("present"):
        return ""
    if body_preview.get("encoding") == "text":
        text = body_preview.get("text") or ""
    else:
        text = f"(binary, {body_preview.get('size', 0)} bytes, hex preview not included)"
    if len(text) > cap:
        text = text[:cap] + f"\n... (truncated, total {body_preview.get('size', len(text))} bytes)"
    return text


def _truncate_json(obj: Any, max_chars: int) -> str:
    raw = json.dumps(obj, ensure_ascii=False, indent=2)
    if len(raw) <= max_chars:
        return raw
    return raw[:max_chars] + f"\n... (JSON truncated, total {len(raw)} chars)"


_JSON_BLOCK = re.compile(r"\{[\s\S]*\}")


def _extract_json(text: str):
    """Return (parsed, error). Tolerates ```json fences or leading/trailing prose."""
    candidate = text.strip()
    # Strip code fences if present.
    if candidate.startswith("```"):
        candidate = candidate.strip("`")
        # Drop optional language tag on the first line.
        parts = candidate.split("\n", 1)
        if len(parts) == 2 and len(parts[0]) <= 10:
            candidate = parts[1]
    try:
        return json.loads(candidate), None
    except json.JSONDecodeError as exc:
        # Try to find the outermost JSON object in the text.
        match = _JSON_BLOCK.search(text)
        if match:
            try:
                return json.loads(match.group(0)), None
            except json.JSONDecodeError as exc2:
                return None, f"{type(exc2).__name__}: {exc2}"
        return None, f"{type(exc).__name__}: {exc}"


_ALLOWED_TOOLS = {"nuclei", "sqlmap", "ffuf", "dalfox", "nmap"}


def _sanitize_suggestions(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only suggestions with a known tool and a non-empty target."""
    scans = parsed.get("suggested_scans")
    if isinstance(scans, list):
        cleaned = []
        for item in scans:
            if not isinstance(item, dict):
                continue
            tool = str(item.get("tool", "")).strip().lower()
            target = str(item.get("target", "")).strip()
            if tool not in _ALLOWED_TOOLS or not target:
                continue
            options = item.get("options") or []
            if not isinstance(options, list):
                options = []
            cleaned.append({
                "tool": tool,
                "target": target,
                "options": [str(x) for x in options],
                "rationale": str(item.get("rationale", "")),
            })
        parsed["suggested_scans"] = cleaned
    return parsed


_analyzer: Optional[Analyzer] = None


def get_analyzer(client: Optional[LLMClient] = None) -> Analyzer:
    global _analyzer
    if _analyzer is None:
        from app.llm.client import get_llm as _get_llm
        _analyzer = Analyzer(client or _get_llm())
    return _analyzer


__all__ = ["Analyzer", "SuggestionResult", "get_analyzer", "LLMError"]
