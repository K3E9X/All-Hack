"""Reproducible proof records.

Two things are being protected here. A finding goes into a report that leaves
the operator's machine, so no credential may survive into it. And the rendered
command is meant to be copy-pasted into a shell, so it must mean exactly what
it says.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.exploit.repro import MASK, build_record, redact_argv, render_command


def job(**over):
    base = {"tool": "commix", "target": "https://app.example.com/ping?ip=1",
            "args": ["--batch", "--os-cmd", "id"], "exit_code": 0,
            "started_at": 1000.0, "finished_at": 1012.5, "id": "job-1"}
    base.update(over)
    return SimpleNamespace(**base)


# ---- Credentials never reach the report ----

def test_cookie_value_is_masked():
    out = redact_argv(["sqlmap", "--cookie", "PHPSESSID=abc123"])
    assert "abc123" not in out
    assert MASK in out


def test_equals_form_is_masked():
    out = redact_argv(["wpscan", "--api-token=SECRETTOKEN"])
    assert "SECRETTOKEN" not in " ".join(out)
    assert "--api-token" in " ".join(out)


def test_header_keeps_its_name_and_loses_its_value():
    """The reader needs to know an Authorization header was sent, not what was in it."""
    out = redact_argv(["nuclei", "-H", "Authorization: Bearer eyJhbGci.SECRET"])
    joined = " ".join(out)
    assert "SECRET" not in joined
    assert "Authorization" in joined


def test_non_secret_header_survives():
    out = redact_argv(["nuclei", "-H", "Accept: application/json"])
    assert "Accept: application/json" in " ".join(out)


def test_credentials_in_a_url_are_masked():
    out = redact_argv(["curl", "https://admin:hunter2@app.example.com/x"])
    joined = " ".join(out)
    assert "hunter2" not in joined
    assert "app.example.com/x" in joined


@pytest.mark.parametrize("flag", ["--password", "--api-key", "--token", "--auth"])
def test_every_declared_secret_flag_is_masked(flag):
    assert "s3cr3t" not in " ".join(redact_argv(["tool", flag, "s3cr3t"]))


def test_the_payload_itself_is_not_masked():
    """Masking the payload would defeat the purpose - it IS the evidence."""
    out = redact_argv(["commix", "--os-cmd", "id"])
    assert "id" in out


# ---- The rendered command means what it says ----

def test_command_is_shell_quoted():
    cmd = render_command(["commix", "--os-cmd", "id; whoami", "--url", "http://t/?a=b c"])
    assert "'id; whoami'" in cmd
    assert "'http://t/?a=b c'" in cmd


def test_quotes_in_a_payload_cannot_break_out():
    cmd = render_command(["sqlmap", "-p", "id'\" OR 1=1--"])
    # Whatever the payload contains, it stays one argument once quoted.
    import shlex
    assert shlex.split(cmd)[2] == "id'\" OR 1=1--"


# ---- The record ----

def test_record_carries_what_a_replay_needs():
    r = build_record(job(), output_excerpt="uid=33(www-data)")
    assert r.tool == "commix"
    assert r.exit_code == 0
    assert r.duration_s == pytest.approx(12.5)
    assert "--os-cmd" in r.command
    assert r.output_excerpt == "uid=33(www-data)"


def test_target_is_appended_only_when_missing():
    r = build_record(job(args=["--url", "https://app.example.com/ping?ip=1"]))
    assert r.command.count("app.example.com") == 1

    r2 = build_record(job(args=["--batch"]))
    assert "app.example.com" in r2.command


def test_missing_timings_do_not_break_the_record():
    r = build_record(job(started_at=None, finished_at=None))
    assert r.duration_s is None
    assert r.ran_at > 0


def test_evidence_block_is_readable_and_complete():
    ev = build_record(job(), output_excerpt="uid=33(www-data)").as_evidence()
    assert "# Reproduce" in ev
    assert "$ commix" in ev
    assert "exit code : 0" in ev
    assert "duration  : 12.5s" in ev
    assert "uid=33(www-data)" in ev


def test_evidence_never_leaks_a_credential():
    ev = build_record(
        job(args=["--batch", "--cookie", "PHPSESSID=abc123", "--os-cmd", "id"])
    ).as_evidence()
    assert "abc123" not in ev
    assert MASK in ev


def test_sqlmap_parameter_flag_is_not_treated_as_a_password():
    """`-p` is the injectable parameter in sqlmap - the core of the evidence.
    Masking it would destroy the very thing the finding proves."""
    out = redact_argv(["sqlmap", "-p", "id", "--batch"])
    assert "id" in out
    assert MASK not in out
