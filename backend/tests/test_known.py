"""Fingerprint -> nuclei product-tag mapping for the known-exploit phase."""
from app.exploit.known import product_tags


def test_maps_common_stacks():
    tags = product_tags(["WordPress 6.1", "PHP 7.4", "nginx 1.24"])
    assert set(tags) == {"wordpress", "php", "nginx"}


def test_atlassian_family():
    assert product_tags(["Atlassian Confluence 7.13"]) == ["atlassian"]
    assert product_tags(["Jira Software"]) == ["atlassian"]


def test_dedup_and_substring():
    # both match wordpress -> a single tag
    assert product_tags(["WordPress", "wp-content theme"]) == ["wordpress"]


def test_unknown_and_empty():
    assert product_tags([]) == []
    assert product_tags(["SomeBespokeFramework"]) == []
    assert product_tags(None) == []


def test_high_signal_apps_detected():
    for tech, tag in [("GitLab CE", "gitlab"), ("Jenkins", "jenkins"),
                      ("Apache Tomcat/9.0", "tomcat"), ("Grafana", "grafana"),
                      ("Citrix NetScaler", "citrix")]:
        assert tag in product_tags([tech])
