"""Structured report exporters: JSON + SARIF."""
from types import SimpleNamespace

from app.reporting.export import findings_json, sarif
from app.validation.models import ValidatedFinding


def _eng():
    return SimpleNamespace(id="eng1", target_url="https://t/", scope_hosts=["t"])


def _vf(vclass="sql_injection", sev="critical"):
    return ValidatedFinding(
        id="vf1", engagement_id="eng1", source_job_id="j", tool="sqlmap",
        vuln_class=vclass, severity=sev, title="SQL Injection", target="https://t/?p=",
        status="confirmed", confidence=0.95, method="analysis",
        poc="payload", evidence="err", created_at=0.0,
    )


def test_findings_json_enriches_with_mapping():
    j = findings_json(_eng(), [_vf()], [])
    assert j["engagement"]["id"] == "eng1"
    f = j["findings"][0]
    assert f["cwe"] == "CWE-89" and f["wstg"] == "WSTG-INPV-05"
    assert f["category"] == "injection"


def test_sarif_structure_and_level():
    s = sarif(_eng(), [_vf(sev="critical"), _vf("xss", "medium")])
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "syphax"
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] == "error"     # critical
    assert run["results"][1]["level"] == "warning"   # medium
    # rules deduped per vuln_class
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"sql_injection", "xss"}


def test_sarif_empty():
    s = sarif(_eng(), [])
    assert s["runs"][0]["results"] == []
