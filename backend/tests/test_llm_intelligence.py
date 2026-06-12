"""Pure-core guards for the 4 LLM intelligence layers (no model calls).

The whole safety story is that the LLM proposes but these pure functions ground
and constrain it. These tests pin that contract.
"""
from app.llm.grounding import (clamp_confidence, extract_json, filter_options,
                               norm_severity, norm_status, quote_is_grounded,
                               safe_tokens)


# ---- shared grounding ----
def test_extract_json_tolerates_fences_and_prose():
    assert extract_json('```json\n{"a":1}\n```') == {"a": 1}
    assert extract_json('here you go: {"a": [1,2]} ok') == {"a": [1, 2]}
    assert extract_json("not json") is None


def test_quote_is_grounded_blocks_hallucination():
    corpus = "Server: Apache/2.4.49\nX-Powered-By: PHP/8.1"
    assert quote_is_grounded("Apache/2.4.49", corpus)
    assert not quote_is_grounded("Nginx/1.0 leaked", corpus)   # not present -> drop
    assert not quote_is_grounded("a", corpus)                  # too short


def test_clamp_and_norm():
    assert clamp_confidence(2.5) == 1.0
    assert clamp_confidence(-1) == 0.0
    assert clamp_confidence("x", 0.4) == 0.4
    assert norm_severity("HIGH") == "high"
    assert norm_severity("bogus") == "info"
    assert norm_status("false_positive") == "false_positive"
    assert norm_status("???") == "likely"


def test_safe_tokens_and_filter_options():
    assert safe_tokens(["jira", "cve", "rm -rf", "a;b", "ok_1"]) == ["jira", "cve", "ok_1"]
    assert filter_options(["--tamper=x", "--os-shell", "-H h"], {"--tamper", "-H"}) == \
        ["--tamper=x", "-H h"]


# ---- #1 llm_recon ----
def test_llm_recon_drops_ungrounded_findings():
    from app.analysis.llm_recon import findings_from_llm
    corpus = "GET /x\nResponse: Whitelabel Error Page, Spring Boot trace id=abc"
    parsed = {"findings": [
        {"title": "Spring Boot error leak", "severity": "medium", "vuln_class": "info_leak",
         "confidence": 0.7, "url": "https://t/x", "evidence": "Whitelabel Error Page", "why": "leak"},
        {"title": "Invented SQLi", "severity": "critical", "vuln_class": "sqli",
         "confidence": 0.9, "url": "https://t/x", "evidence": "you are vulnerable to sqli", "why": "x"},
    ]}
    out = findings_from_llm(parsed, corpus)
    assert len(out) == 1                       # the hallucinated one is dropped
    assert out[0].metadata["status"] == "likely"
    assert out[0].severity == "medium"


# ---- #2 hypothesis-driven hunts ----
def test_build_hunt_tasks_grounds_assets_and_sanitizes_tags():
    from app.orchestrator.hypothesis import build_hunt_tasks
    assets = ["https://app.example.com", "https://api.example.com"]
    parsed = {"extra_hunts": [
        {"asset": "https://app.example.com", "tags": ["jira", "cve", "rm -rf"]},
        {"asset": "https://evil.com", "tags": ["x"]},        # not in assets -> drop
        {"asset": "https://api.example.com", "tags": []},     # no valid tags -> drop
    ]}
    tasks = build_hunt_tasks(parsed, assets, "vuln_analysis")
    assert len(tasks) == 1
    t = tasks[0]
    assert t.tool == "nuclei" and t.asset_value == "https://app.example.com"
    assert t.options == ["-tags", "jira,cve"]                # 'rm -rf' sanitized out
    assert t.catalog_item_id.startswith("LLM-HUNT-")


# ---- #3 judge ----
def test_judge_reconcile_caps_ungrounded_confirm():
    from app.validation.llm_judge import parse_judgment, reconcile
    evidence = "HTTP/1.1 200 OK\nbody: id=1 returned admin row"
    j = parse_judgment('{"verdict":"confirmed","confidence":0.95,"quote":"made up","reason":"x"}')
    status, conf = reconcile("likely", 0.6, j, evidence)
    assert status == "likely" and conf <= 0.6        # ungrounded confirm -> capped

    j2 = parse_judgment('{"verdict":"confirmed","confidence":0.9,"quote":"admin row","reason":"ok"}')
    status2, conf2 = reconcile("likely", 0.6, j2, evidence)
    assert status2 == "confirmed"                    # grounded -> honoured

    j3 = parse_judgment('{"verdict":"false_positive","confidence":0.8,"quote":"","reason":"benign"}')
    status3, conf3 = reconcile("likely", 0.6, j3, evidence)
    assert status3 == "false_positive" and conf3 <= 0.2


# ---- #4 payload adaptation ----
def test_tamper_allowlist_and_strip():
    from app.scans.payload_adapt import (filter_tampers, parse_tamper_reply,
                                         strip_tamper, tamper_option)
    assert filter_tampers(["space2comment", "evil", "between"]) == ["space2comment", "between"]
    assert tamper_option(["space2comment", "nope"]) == ["--tamper=space2comment"]
    assert tamper_option(["nope"]) == []
    assert parse_tamper_reply('{"tampers":["randomcase","DROP TABLE"]}') == ["randomcase"]
    assert strip_tamper(["--tamper=x", "--delay=1"]) == ["--delay=1"]
