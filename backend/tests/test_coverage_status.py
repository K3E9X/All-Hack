"""Regression guard for the recon->vuln deadlock.

A task that was attempted but couldn't run ('skipped', tool missing) or failed
('error', scanner exited non-zero) MUST count as covered. If it doesn't, the
planner - which advances one phase at a time - keeps it as an uncovered
candidate forever, pinning the run on recon so mapping/vuln/exploitation never
get planned. This test pins the contract.
"""
from app.orchestrator.state import COVERED_STATUSES, status_is_covered


def test_attempted_statuses_count_as_covered():
    # The two that caused the deadlock when they were NOT covered:
    assert status_is_covered("skipped")
    assert status_is_covered("error")
    # The already-scheduled ones:
    assert status_is_covered("pending")
    assert status_is_covered("running")
    assert status_is_covered("done")


def test_unknown_or_missing_is_not_covered():
    assert not status_is_covered(None)
    assert not status_is_covered("")
    assert not status_is_covered("queued")     # not a status we write


def test_all_executor_written_statuses_are_covered():
    # Every status the executor/ingest can write must be "covered" so no
    # attempted task is ever re-planned and able to block phase advancement.
    for written in ("pending", "running", "done", "skipped", "error"):
        assert written in COVERED_STATUSES
        assert status_is_covered(written)
