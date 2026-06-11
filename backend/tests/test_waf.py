"""WAF-aware exploitation option injection."""
from app.scans.waf import is_waf_tech, waf_args


def test_is_waf_tech():
    assert is_waf_tech(["nginx", "waf:Cloudflare"])
    assert is_waf_tech(["WAF:Akamai"])  # case-insensitive
    assert not is_waf_tech(["nginx", "php"])
    assert not is_waf_tech([])


def test_sqlmap_gets_tamper_and_random_agent():
    args = waf_args("sqlmap")
    assert "--random-agent" in args
    assert any(a.startswith("--tamper=") for a in args)


def test_nuclei_and_dalfox_get_throttled():
    assert "-rate-limit" in waf_args("nuclei")
    assert "--delay" in waf_args("dalfox")
    assert "-rate" in waf_args("ffuf")


def test_recon_tools_get_nothing():
    assert waf_args("subfinder") == []
    assert waf_args("httpx") == []
    assert waf_args("nikto") == []


def test_waf_args_returns_a_copy():
    a = waf_args("sqlmap")
    a.append("x")
    assert "x" not in waf_args("sqlmap")


def test_blind_args_dalfox_only_with_oob():
    from app.scans.waf import blind_args
    assert blind_args("dalfox", "https://oob.example") == ["--blind", "https://oob.example"]
    assert blind_args("dalfox", "") == []
    assert blind_args("sqlmap", "https://oob.example") == []
