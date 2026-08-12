"""Cross-tool correlation: payload assembly and, above all, grounding.

The grounding tests are the important ones. A lead is a proposal to point a
scanner at something; one that references an asset nobody ever saw is how an
out-of-scope host ends up in a queue.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.analysis.correlation import (MAX_LEADS, NOMINABLE_TOOLS, build_payload,
                                      parse_leads)


def asset(value, kind="endpoint", has_params=False, source="katana"):
    return SimpleNamespace(value=value, kind=kind, has_params=has_params, source=source)


def flow(url, method="GET", status_code=200, content_type="text/html"):
    return SimpleNamespace(url=url, method=method, status_code=status_code,
                           content_type=content_type)


def finding(title, severity="high", status="likely", vuln_class="xss", target="t"):
    return SimpleNamespace(title=title, severity=severity, status=status,
                           vuln_class=vuln_class, target=target)


# ---- Payload assembly ----

def test_payload_carries_every_signal_family():
    payload = build_payload(
        assets=[asset("https://t/login")],
        technologies=["wordpress:6.2", "waf:cloudflare"],
        findings=[finding("Outdated plugin")],
        flows=[flow("https://t/wp-json/wp/v2/users")],
        coverage_summary={"done": 3},
    )
    assert payload["assets"][0]["value"] == "https://t/login"
    assert "waf:cloudflare" in payload["technologies"]
    assert payload["findings_so_far"][0]["title"] == "Outdated plugin"
    assert payload["captured_traffic"][0]["url"].endswith("/wp/v2/users")
    assert payload["coverage"] == {"done": 3}
    assert set(payload["available_tools"]) == NOMINABLE_TOOLS


def test_payload_is_bounded():
    """A 1M window is not a reason to send unbounded input."""
    payload = build_payload(
        assets=[asset(f"https://t/{i}") for i in range(500)],
        technologies=[f"tech{i}" for i in range(200)],
        findings=[finding(f"f{i}") for i in range(500)],
        flows=[flow(f"https://t/f{i}") for i in range(500)],
    )
    assert len(payload["assets"]) <= 120
    assert len(payload["captured_traffic"]) <= 60
    assert len(payload["findings_so_far"]) <= 80
    assert len(payload["technologies"]) <= 60


def test_traffic_digest_carries_shape_not_bodies():
    """Bodies are llm_recon's job; duplicating them here buys no extra signal."""
    payload = build_payload(assets=[asset("https://t/")], technologies=[],
                            findings=[], flows=[flow("https://t/api")])
    assert set(payload["captured_traffic"][0]) == {"method", "url", "status", "content_type"}


# ---- Grounding ----

KNOWN = {"https://t/login", "https://t/api"}


def _lead(**over):
    base = {"asset": "https://t/login", "tool": "nuclei",
            "rationale": "wordpress + exposed route", "signals": ["wordpress:6.2"],
            "confidence": 0.8}
    base.update(over)
    return {"leads": [base]}


def test_valid_lead_survives():
    leads = parse_leads(_lead(), KNOWN)
    assert len(leads) == 1
    assert leads[0].asset == "https://t/login"
    assert leads[0].tool == "nuclei"


def test_lead_on_an_unknown_asset_is_dropped():
    """The model must never widen the target set."""
    assert parse_leads(_lead(asset="https://evil.example/"), KNOWN) == []


def test_lead_with_an_unknown_tool_is_dropped():
    assert parse_leads(_lead(tool="metasploit"), KNOWN) == []


def test_lead_without_signals_is_dropped():
    """No traceable reasoning means nobody can check it - not actionable."""
    assert parse_leads(_lead(signals=[]), KNOWN) == []


def test_tags_are_sanitized():
    leads = parse_leads(_lead(tags=["wordpress", "cve", "; rm -rf /", "a" * 80]), KNOWN)
    assert leads[0].tags == ["wordpress", "cve"]


@pytest.mark.parametrize("value,expected", [
    (2.5, 1.0), (-1, 0.0), ("nope", 0.5), (0.42, 0.42),
])
def test_confidence_is_clamped(value, expected):
    leads = parse_leads(_lead(confidence=value), KNOWN)
    assert leads[0].confidence == expected


def test_leads_are_ranked_and_capped():
    raw = {"leads": [
        {"asset": "https://t/api", "tool": "nuclei", "rationale": f"r{i}",
         "signals": ["s"], "confidence": i / 100}
        for i in range(30)
    ]}
    leads = parse_leads(raw, KNOWN)
    assert len(leads) == MAX_LEADS
    assert leads == sorted(leads, key=lambda x: x.confidence, reverse=True)


@pytest.mark.parametrize("garbage", [None, "", [], {"leads": None}, {"nope": 1}, 42])
def test_malformed_replies_yield_nothing(garbage):
    assert parse_leads(garbage, KNOWN) == []


def test_asset_match_is_exact_not_fuzzy():
    """A near-miss is a different host, not a typo to be helpfully corrected."""
    assert parse_leads(_lead(asset="https://t/login/"), KNOWN) == []
    assert parse_leads(_lead(asset=" https://t/login"), KNOWN) != []  # stripped
