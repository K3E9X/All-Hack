"""GitHub PoC discovery for a fingerprinted CVE.

The ranking is what matters. Sorting by stars puts a 20k-star CVE index above
the 3-star repository written the day the CVE dropped - and the second one is
the actual exploit. These tests pin that ordering down.
"""
from __future__ import annotations

import pytest

from app.exploit_sources import aggregate, rank_github_repos

CVE = "CVE-2024-1234"


def repo(full_name, description="", stars=0, pushed_at="2024-02-01T00:00:00Z"):
    return {"full_name": full_name, "description": description,
            "stargazers_count": stars, "pushed_at": pushed_at,
            "html_url": f"https://github.com/{full_name}"}


# ---- Ranking ----

def test_cve_in_the_repo_name_beats_a_popular_index():
    """The specific PoC wins over the aggregator, however many stars it has."""
    ranked = rank_github_repos([
        repo("nomi-sec/PoC-in-GitHub", "All CVE PoCs", stars=20000),
        repo("someone/CVE-2024-1234-poc", "exploit", stars=3),
    ], CVE)
    assert ranked[0]["title"] == "someone/CVE-2024-1234-poc"


def test_aggregators_are_pushed_down_but_not_hidden():
    ranked = rank_github_repos([
        repo("x/awesome-cve-list", f"includes {CVE}", stars=9000),
        repo("y/CVE-2024-1234", "poc", stars=1),
    ], CVE)
    assert [r["title"] for r in ranked] == ["y/CVE-2024-1234", "x/awesome-cve-list"]
    assert ranked[1]["aggregator"] is True


def test_unrelated_repositories_are_dropped():
    """GitHub search is fuzzy; a repo that mentions the CVE nowhere is noise."""
    assert rank_github_repos([repo("me/my-website", "personal blog", stars=50)], CVE) == []


def test_description_match_counts_when_the_name_does_not():
    ranked = rank_github_repos(
        [repo("researcher/exploit", f"PoC for {CVE} in Acme", stars=10)], CVE)
    assert len(ranked) == 1


def test_stars_only_break_ties():
    ranked = rank_github_repos([
        repo("a/CVE-2024-1234", "poc", stars=5),
        repo("b/CVE-2024-1234", "poc", stars=500),
    ], CVE)
    assert ranked[0]["title"] == "b/CVE-2024-1234"


def test_results_are_capped():
    items = [repo(f"u{i}/CVE-2024-1234", "poc", stars=i) for i in range(50)]
    assert len(rank_github_repos(items, CVE)) == 6
    assert len(rank_github_repos(items, CVE, limit=2)) == 2


@pytest.mark.parametrize("junk", [None, [], [None], [{}], [{"description": "x"}]])
def test_malformed_results_are_survived(junk):
    assert rank_github_repos(junk, CVE) == []


def test_matching_is_case_insensitive():
    assert rank_github_repos([repo("x/cve-2024-1234-poc", "y")], CVE)


# ---- Third-party code is never auto-run ----

def test_github_repos_are_sandbox_tier():
    """Unvetted third-party code: staged for the sandbox, behind human approval.
    Nothing here may be marked 'auto'."""
    for r in rank_github_repos([repo("x/CVE-2024-1234", "poc")], CVE):
        assert r["runnable"] == "sandbox"


# ---- Aggregation ----

def test_real_repos_replace_the_search_link():
    """Once the API answered, a 'go search GitHub yourself' link is just noise."""
    gh = rank_github_repos([repo("x/CVE-2024-1234", "poc")], CVE)
    agg = aggregate(CVE, github_repos=gh)
    sources = [(e["source"], e["runnable"]) for e in agg["exploits"]]
    assert ("github", "sandbox") in sources
    assert ("github", "reference") not in sources


def test_search_link_survives_when_nothing_was_found():
    agg = aggregate(CVE, github_repos=[])
    assert ("github", "reference") in [(e["source"], e["runnable"]) for e in agg["exploits"]]


def test_count_reflects_actionable_sources_only():
    agg = aggregate(CVE, nuclei_fired=True,
                    github_repos=rank_github_repos([repo("x/CVE-2024-1234", "p")], CVE))
    # nuclei template + one real GitHub PoC; the reference links do not count.
    assert agg["count"] == 2


def test_aggregate_without_github_still_works():
    """Back-compat: the parameter is optional and older callers are unaffected."""
    agg = aggregate(CVE, nuclei_fired=True)
    assert agg["cve"] == CVE
    assert agg["count"] == 1
