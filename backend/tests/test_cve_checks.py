"""Targeted CVE checks: data integrity + applicability + match/redact helpers."""
from app.cve_refs import normalize_cve
from app.exploit.cve_checks import CHECKS, applicable, host_root, matches, redact


def test_checks_are_well_formed():
    assert len(CHECKS) >= 5
    ids = [c.cve_id for c in CHECKS]
    assert len(ids) == len(set(ids))                  # unique
    for c in CHECKS:
        assert normalize_cve(c.cve_id) == c.cve_id     # valid CVE id
        assert c.paths and all(p.startswith("/") for p in c.paths)
        assert c.signature
        assert c.severity in ("critical", "high", "medium", "low")


def test_applicable_respects_tech_gate():
    citrix = next(c for c in CHECKS if c.cve_id == "CVE-2019-19781")
    assert applicable(citrix, ["Citrix NetScaler"])
    assert not applicable(citrix, ["nginx", "php"])


def test_applicable_without_tech_gate_runs_always():
    class C:
        tech_any = ()
    assert applicable(C(), [])


def test_matches_case_insensitive():
    assert matches("...\nroot:x:0:0:root:/root:/bin/bash\n...", "root:x:0:0")
    assert not matches("nothing here", "root:x:0:0")


def test_redact_shows_signature_line_not_whole_file():
    body = "header\n" + "\n".join(f"user{i}:x:{i}" for i in range(200)) + "\nroot:x:0:0:root\n" + "secret" * 100
    out = redact(body, "root:x:0:0")
    assert "root:x:0:0" in out
    assert "(redacted)" in out
    assert len(out) < 400               # not the whole file
    assert "secretsecret" not in out


def test_host_root():
    assert host_root("https://app.example.com/a/b?x=1") == "https://app.example.com"
    assert host_root("http://t") == "http://t"
