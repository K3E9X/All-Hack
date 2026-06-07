"""Findings dedup key, cvss mapping and HackerOne export (pure helpers)."""
from app import findings_util as fu
from app.reporting.mappings import for_class
from app.validation.models import ValidatedFinding


def test_dedup_is_stable_and_class_target_scoped():
    a = fu.dedup("sql_injection", "https://t/?p=")
    b = fu.dedup("sql_injection", "https://t/?p=")
    c = fu.dedup("xss", "https://t/?p=")
    assert a == b and a != c and len(a) == 16


def test_cvss_scale_ordered():
    assert fu.CVSS["critical"] > fu.CVSS["high"] > fu.CVSS["medium"] > fu.CVSS["low"]
    assert fu.cvss_for("critical") == 9.5
    assert fu.cvss_for("unknown") == 1.0


def test_triage_statuses():
    assert fu.TRIAGE_STATUSES == {"new", "triaged", "confirmed", "reported", "false_positive"}


def _vf():
    return ValidatedFinding(
        id="vf1", engagement_id="e", source_job_id="j", tool="sqlmap",
        vuln_class="sql_injection", severity="critical", title="SQL Injection",
        target="https://t/?p=", status="confirmed", confidence=0.95, method="analysis",
        poc="https://t/?p=1' AND SLEEP(5)-- -", evidence="SQL syntax error", created_at=0.0,
    )


def test_h1_markdown_has_sections_and_mapping():
    f = _vf()
    md = fu.h1_markdown(f, for_class(f.vuln_class), fu.cvss_for(f.severity))
    assert md.startswith("# SQL Injection")
    for section in ("## Summary", "## Steps To Reproduce", "## Impact", "## Remediation"):
        assert section in md
    assert "CWE-89" in md and "WSTG-INPV-05" in md
