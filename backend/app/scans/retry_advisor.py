"""Executor role: diagnose a job that failed or found nothing, and say what to
change.

The gap this fills: when nuclei exits 1, when ffuf returns zero hits, when
sqlmap times out, nothing looks at why. The job is marked done, coverage moves
on, and the run quietly loses that test. Most of those failures are mundane and
fixable - a timeout too tight for a slow app, a rate limit tripping the WAF,
a wordlist wrong for the stack, TLS verification on a self-signed cert.

This is the right job for the executor role rather than the planner: it is
narrow, mechanical, per-job, and it happens often. It wants the cheap fast
model, not the reasoning one.

Safety: the model never writes a command line. It picks from a per-tool
allowlist of options that only ever make a scan *gentler or more patient* -
timeouts, retries, concurrency, redirect following. Nothing that widens the
target, changes the verb, or adds a payload. `filter_options` enforces it, and
anything unrecognised is dropped rather than passed through.

One retry per job, ever. A model that keeps proposing fixes for a genuinely
broken target would otherwise loop forever.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from app.llm import ROLE_EXECUTOR, LLMError, get_router
from app.llm.grounding import extract_json, filter_options

logger = logging.getLogger("syphax.scans.retry_advisor")

# Marker appended to a retried job's options so a retry can never be retried.
RETRY_MARKER = "--syphax-retry"

# Per-tool allowlist. Every entry makes the scan slower, more patient or more
# tolerant - never broader. Adding a flag here is a security decision.
ALLOWED_RETRY_OPTIONS: Dict[str, Set[str]] = {
    "nuclei": {"-timeout", "-retries", "-rate-limit", "-c", "-bulk-size",
               "-follow-redirects", "-max-redirects", "-no-color"},
    "ffuf": {"-timeout", "-rate", "-t", "-r", "-mc", "-fc", "-ac"},
    "sqlmap": {"--timeout", "--retries", "--delay", "--threads",
               "--random-agent", "--ignore-code"},
    "dalfox": {"--timeout", "--delay", "--worker", "--follow-redirects"},
    "httpx": {"-timeout", "-retries", "-rate-limit", "-threads",
              "-follow-redirects"},
    "katana": {"-timeout", "-retry", "-rate-limit", "-c", "-depth"},
    "nikto": {"-timeout", "-Pause"},
    "wpscan": {"--request-timeout", "--connect-timeout", "--max-threads",
               "--throttle"},
    "commix": {"--timeout", "--retries", "--delay"},
    "testssl": {"--connect-timeout", "--openssl-timeout"},
    "nmap": {"--host-timeout", "--max-retries", "--scan-delay", "-T2", "-T3"},
    "naabu": {"-timeout", "-retries", "-rate", "-c"},
    "subfinder": {"-timeout", "-t"},
    "dnsx": {"-retry", "-rate-limit", "-t"},
    "gau": {"--timeout", "--retries", "--threads"},
    "whatweb": {"--open-timeout", "--read-timeout", "--max-threads"},
    "wafw00f": {"-a"},
}

# Diagnoses the model may return. A closed set so the UI and the metrics can
# rely on it; anything else becomes "unknown".
DIAGNOSES = {
    "timeout",          # target too slow for the configured timeout
    "rate_limited",     # WAF/server pushed back
    "tls_error",        # certificate / handshake problem
    "auth_required",    # endpoint needs credentials we did not send
    "wrong_target",     # tool does not apply to this asset
    "no_findings",      # ran fine, genuinely found nothing
    "tool_error",       # the binary itself failed
    "unknown",
}

MAX_TAIL = 2000

_SYSTEM = """\
You triage a finished security-scan job that failed or found nothing.

You get the tool, its exit code, the tail of its stderr/stdout, and the options
it ran with. Decide why it came back empty and whether a single retry with
gentler settings would plausibly change the outcome.

Rules:
- Choose `diagnosis` from the provided list only.
- `retry_options` may ONLY contain flags from the provided allowlist. Every one
  of them makes the scan slower or more patient; you cannot widen the scan,
  change the target, or add payloads.
- Set `retry` false when the output shows the tool ran correctly and the target
  simply has nothing - retrying identical work wastes the budget.
- Ground `reason` in the output you were given. Do not speculate about the
  target beyond what the output shows.

Reply JSON only:
{"diagnosis":"<one of the list>","retry":true|false,
 "retry_options":["-timeout=30"],"reason":"<one sentence>"}
"""


@dataclass
class RetryAdvice:
    diagnosis: str
    retry: bool
    options: List[str]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"diagnosis": self.diagnosis, "retry": self.retry,
                "options": self.options, "reason": self.reason}


def already_retried(options: Any) -> bool:
    """True once this job is itself a retry. One retry per job, ever."""
    return any(str(o) == RETRY_MARKER for o in (options or []))


def should_triage(tool: str, exit_code: Optional[int], finding_count: int,
                  options: Any) -> bool:
    """Worth spending an LLM call on this job?

    Only when it actually underperformed, the tool is one we can tune, and it
    is not already a retry.
    """
    if tool not in ALLOWED_RETRY_OPTIONS:
        return False
    if already_retried(options):
        return False
    failed = exit_code is not None and exit_code != 0
    return bool(failed or finding_count == 0)


def parse_advice(raw: Any, tool: str) -> Optional[RetryAdvice]:
    """Validate the model's reply against the allowlist for this tool."""
    obj = extract_json(raw) if isinstance(raw, str) else raw
    if not isinstance(obj, dict):
        return None

    diagnosis = str(obj.get("diagnosis") or "").strip().lower()
    if diagnosis not in DIAGNOSES:
        diagnosis = "unknown"

    allowed = ALLOWED_RETRY_OPTIONS.get(tool, set())
    options = filter_options(obj.get("retry_options"), allowed)

    retry = bool(obj.get("retry"))
    # A retry that changes nothing is the same scan again: refuse it rather
    # than burn the job budget re-running identical work.
    if retry and not options:
        retry = False

    return RetryAdvice(
        diagnosis=diagnosis,
        retry=retry,
        options=options,
        reason=str(obj.get("reason") or "").strip()[:300],
    )


def retry_options(base_options: Any, advice: RetryAdvice) -> List[str]:
    """Options for the retry: the originals, the tuning, and the marker."""
    out = [str(o) for o in (base_options or [])]
    for opt in advice.options:
        if opt not in out:
            out.append(opt)
    out.append(RETRY_MARKER)
    return out


async def advise(tool: str, *, exit_code: Optional[int], stderr_tail: str,
                 stdout_tail: str, options: Any) -> Optional[RetryAdvice]:
    """Ask the executor role what went wrong. No LLM -> no advice."""
    client = get_router().get(ROLE_EXECUTOR)
    if not client.configured:
        return None

    allowed = sorted(ALLOWED_RETRY_OPTIONS.get(tool, set()))
    user = (
        f"Tool: {tool}\n"
        f"Exit code: {exit_code}\n"
        f"Options used: {list(options or [])}\n"
        f"Allowed retry flags: {allowed}\n"
        f"Diagnoses: {sorted(DIAGNOSES)}\n\n"
        f"stderr tail:\n{(stderr_tail or '')[:MAX_TAIL]}\n\n"
        f"stdout tail:\n{(stdout_tail or '')[:MAX_TAIL]}"
    )
    try:
        raw = await client.chat(
            [{"role": "system", "content": _SYSTEM},
             {"role": "user", "content": user}],
            temperature=0.0, max_tokens=300,
        )
    except LLMError as exc:
        logger.warning("retry advisor unavailable: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001 - triage must never break ingest
        logger.warning("retry advisor error: %s", exc)
        return None

    return parse_advice(raw, tool)
