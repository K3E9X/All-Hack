"""Executor-role triage of failed/empty jobs.

The allowlist tests are the load-bearing ones: this is the one place a model's
output becomes flags on a command line that runs against a live target. Every
allowed flag must only ever make a scan slower or more patient - never broader.
"""
from __future__ import annotations

import pytest

from app.scans.retry_advisor import (ALLOWED_RETRY_OPTIONS, DIAGNOSES,
                                     RETRY_MARKER, RetryAdvice, already_retried,
                                     parse_advice, retry_options, should_triage)


# ---- When is triage worth a call ----

def test_failed_job_is_triaged():
    assert should_triage("nuclei", exit_code=1, finding_count=0, options=[])


def test_empty_but_successful_job_is_triaged():
    """Exit 0 with nothing found is the common case worth diagnosing."""
    assert should_triage("ffuf", exit_code=0, finding_count=0, options=[])


def test_successful_job_with_findings_is_left_alone():
    assert not should_triage("nuclei", exit_code=0, finding_count=3, options=[])


def test_unknown_tool_is_not_triaged():
    assert not should_triage("some-tool", exit_code=1, finding_count=0, options=[])


def test_a_retry_is_never_retried():
    """Otherwise a genuinely broken target loops forever."""
    assert already_retried([RETRY_MARKER])
    assert not should_triage("nuclei", exit_code=1, finding_count=0,
                             options=["-timeout=30", RETRY_MARKER])


# ---- The allowlist is the safety boundary ----

def test_every_tool_allowlist_is_non_empty():
    for tool, opts in ALLOWED_RETRY_OPTIONS.items():
        assert opts, f"{tool} has an empty allowlist"


@pytest.mark.parametrize("evil", [
    "-u", "--url", "-target", "-o", "--output", "-H", "--data", "--os-shell",
    "--file-write", "-x", "--proxy", "-w", "--tamper",
])
def test_target_and_payload_flags_are_not_allowlisted_anywhere(evil):
    """A retry must not be able to widen the scan, redirect it, or add a payload."""
    for tool, opts in ALLOWED_RETRY_OPTIONS.items():
        assert evil not in opts, f"{evil} is allowlisted for {tool}"


def test_proposed_options_outside_the_allowlist_are_dropped():
    advice = parse_advice(
        {"diagnosis": "timeout", "retry": True,
         "retry_options": ["-timeout=30", "-u=https://evil.example", "--os-shell"]},
        "nuclei",
    )
    assert advice.options == ["-timeout=30"]


def test_options_are_filtered_per_tool():
    """--timeout is sqlmap's spelling; nuclei uses -timeout."""
    assert parse_advice(
        {"diagnosis": "timeout", "retry": True, "retry_options": ["--timeout=30"]},
        "nuclei").options == []
    assert parse_advice(
        {"diagnosis": "timeout", "retry": True, "retry_options": ["--timeout=30"]},
        "sqlmap").options == ["--timeout=30"]


# ---- Advice parsing ----

def test_retry_without_any_change_is_refused():
    """Re-running the identical scan just burns the job budget."""
    advice = parse_advice(
        {"diagnosis": "timeout", "retry": True, "retry_options": []}, "nuclei")
    assert advice.retry is False


def test_unknown_diagnosis_falls_back():
    advice = parse_advice({"diagnosis": "cosmic rays", "retry": False}, "nuclei")
    assert advice.diagnosis == "unknown"


@pytest.mark.parametrize("diagnosis", sorted(DIAGNOSES))
def test_every_declared_diagnosis_round_trips(diagnosis):
    assert parse_advice({"diagnosis": diagnosis, "retry": False},
                        "nuclei").diagnosis == diagnosis


def test_no_findings_diagnosis_can_decline_the_retry():
    advice = parse_advice(
        {"diagnosis": "no_findings", "retry": False,
         "reason": "tool ran fine, target is clean"}, "ffuf")
    assert advice.retry is False
    assert "clean" in advice.reason


@pytest.mark.parametrize("raw", [None, "", [], 42, "not json"])
def test_malformed_replies_yield_nothing(raw):
    assert parse_advice(raw, "nuclei") is None


def test_json_in_a_string_is_accepted():
    advice = parse_advice(
        '{"diagnosis":"rate_limited","retry":true,"retry_options":["-rate-limit=10"]}',
        "nuclei")
    assert advice.diagnosis == "rate_limited"
    assert advice.options == ["-rate-limit=10"]


# ---- Building the retry ----

def test_retry_keeps_the_originals_and_marks_itself():
    advice = RetryAdvice("timeout", True, ["-timeout=30"], "slow")
    out = retry_options(["-severity", "high"], advice)
    assert out[:2] == ["-severity", "high"]
    assert "-timeout=30" in out
    assert out[-1] == RETRY_MARKER
    assert already_retried(out)


def test_retry_does_not_duplicate_an_existing_option():
    advice = RetryAdvice("timeout", True, ["-timeout=30"], "slow")
    out = retry_options(["-timeout=30"], advice)
    assert out.count("-timeout=30") == 1


# ---- Retry budget ----

async def test_retries_are_capped_per_run():
    """Retries are submitted from ingest, outside the loop's per-batch budget
    check, so they need their own ceiling - otherwise a run full of empty jobs
    could roughly double the request count against the target."""
    from app.orchestrator.executor import MAX_RETRIES_PER_RUN, Executor
    from app.orchestrator.state import EngagementState

    ex = Executor(EngagementState("eng-1"))
    assert ex.retries_launched == 0
    ex.retries_launched = MAX_RETRIES_PER_RUN

    class _Job:
        tool, exit_code, findings, args = "nuclei", 1, [], []
        id, target, catalog_item_id, stderr, stdout = "j", "t", None, b"", b""

    called = []

    async def _boom(*a, **k):
        called.append(1)
        raise AssertionError("advisor must not run once the cap is hit")

    import app.scans.retry_advisor as ra
    original, ra.advise = ra.advise, _boom
    try:
        await ex._triage_underperforming(_Job())
    finally:
        ra.advise = original
    assert not called
