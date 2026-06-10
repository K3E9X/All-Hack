"""CVE id normalization + public-exploit reference resolver."""
from app import cve_refs as cr
from app.scans.wrappers.nuclei import _classify, _first_cve


def test_normalize_cve():
    assert cr.normalize_cve("CVE-2023-1234") == "CVE-2023-1234"
    assert cr.normalize_cve("cve-2021-44228") == "CVE-2021-44228"
    assert cr.normalize_cve("nginx 1.24") is None


def test_exploit_refs_links():
    refs = cr.exploit_refs("CVE-2021-44228")
    assert set(refs) == {"nvd", "exploit_db", "github_poc", "metasploit"}
    assert "CVE-2021-44228" in refs["nvd"]
    assert "exploit-db.com" in refs["exploit_db"]


def test_exploit_refs_empty_for_garbage():
    assert cr.exploit_refs("not-a-cve") == {}
    assert cr.refs_text("not-a-cve") == ""


def test_refs_text_mentions_cve_and_sources():
    txt = cr.refs_text("CVE-2017-5638")
    assert "CVE-2017-5638" in txt
    assert "exploit-db" in txt and "metasploit" in txt


def test_first_cve_from_list_or_string():
    assert cr.first_cve(["CVE-2020-0001"]) == "CVE-2020-0001"
    assert cr.first_cve("CVE-2019-0708 blah") == "CVE-2019-0708"
    assert cr.first_cve(["x", "y"]) is None


def test_nuclei_first_cve_prefers_classification_then_template():
    assert _first_cve(["CVE-2023-1111"], "cve,rce", "tpl") == "CVE-2023-1111"
    assert _first_cve(None, "cve", "CVE-2022-2222") == "CVE-2022-2222"
    assert _first_cve(None, "rce", "generic-template") is None


def test_classify_cve_fallback():
    # a CVE-tagged template with no finer class -> "cve"
    assert _classify("cve", "") == "cve"
    # but a finer class still wins
    assert _classify("cve,sqli", "") == "sql_injection"
