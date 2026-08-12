"""Scan identity (User-Agent, attribution header, proxy flags) and the VPN
kill switch.

The kill switch tests matter most: a false "safe" there means a scan runs from
the operator's real IP while the UI claims a tunnel is up.
"""
from __future__ import annotations

import pytest

from app.config import settings
from app.network.privacy import MODE_OFF, MODE_PROXY, NetworkPrivacyManager
from app.scans.identity import (BROWSER_PROFILES, MODE_ROTATE, current_profile,
                                current_user_agent, identity_args, proxy_args,
                                supports_proxy)

USER_AGENT_POOL = [p["ua"] for p in BROWSER_PROFILES]


@pytest.fixture
def clean_settings():
    """Restore the settings this module mutates."""
    saved = (
        settings.user_agent_mode,
        settings.user_agent,
        settings.pentest_id,
        settings.require_vpn,
    )
    yield
    (settings.user_agent_mode, settings.user_agent,
     settings.pentest_id, settings.require_vpn) = saved


# ---- User-Agent policy ----

def test_fixed_mode_returns_configured_ua(clean_settings):
    settings.user_agent_mode = "fixed"
    settings.user_agent = "TestAgent/1.0"
    assert {current_user_agent() for _ in range(10)} == {"TestAgent/1.0"}


def test_rotate_mode_draws_from_the_pool(clean_settings):
    settings.user_agent_mode = MODE_ROTATE
    seen = {current_user_agent() for _ in range(200)}
    assert len(seen) > 1, "rotate mode returned a single UA"
    assert seen <= set(USER_AGENT_POOL)


def test_no_user_agent_announces_the_tool_name(clean_settings):
    """Regression: the old crawler sent 'SyphaxCrawler/1.0' to every target."""
    settings.user_agent_mode = MODE_ROTATE
    for ua in USER_AGENT_POOL:
        assert "syphax" not in ua.lower()
        assert "crawler" not in ua.lower()


# ---- Per-tool flags ----

@pytest.mark.parametrize("tool", ["nuclei", "ffuf", "dalfox", "katana", "httpx"])
def test_dash_h_tools_get_a_user_agent_header(clean_settings, tool):
    settings.user_agent_mode = "fixed"
    settings.user_agent = "TestAgent/1.0"
    settings.pentest_id = ""
    args = identity_args(tool)
    assert args[:2] == ["-H", "User-Agent: TestAgent/1.0"]


def test_sqlmap_uses_its_own_flag(clean_settings):
    settings.user_agent_mode = "fixed"
    settings.user_agent = "TestAgent/1.0"
    settings.pentest_id = ""
    assert identity_args("sqlmap")[:2] == ["--user-agent", "TestAgent/1.0"]


def test_pentest_id_is_attached_when_set(clean_settings):
    settings.user_agent_mode = "fixed"
    settings.user_agent = "TestAgent/1.0"
    settings.pentest_id = "AUDIT-2026-08"
    args = identity_args("nuclei")
    assert "-H" in args
    assert "X-Pentest-ID: AUDIT-2026-08" in args


def test_pentest_id_absent_by_default(clean_settings):
    """It marks traffic as an authorized test, which is the opposite of
    blending in. Must stay off unless the operator opts in."""
    settings.user_agent_mode = "fixed"
    settings.pentest_id = ""
    assert not any("X-Pentest-ID" in a for a in identity_args("nuclei"))
    assert settings.model_fields["pentest_id"].default == ""


def test_rotate_is_the_default_mode():
    assert settings.model_fields["user_agent_mode"].default == MODE_ROTATE


# ---- Browser profile coherence ----
# A UA that does not match the headers around it is a stronger signal than a
# missing UA, so these pin the combinations that exist in the wild.

def test_every_profile_carries_a_full_header_set():
    for p in BROWSER_PROFILES:
        h = p["headers"]
        assert h.get("Accept"), f"{p['ua']} has no Accept"
        assert h.get("Accept-Language"), f"{p['ua']} has no Accept-Language"
        assert h.get("Sec-Fetch-Mode") == "navigate"


def test_client_hints_only_on_chromium():
    """Firefox and Safari do not implement Sec-CH-UA. Sending it with their
    UA is an instant tell."""
    for p in BROWSER_PROFILES:
        ua = str(p["ua"])
        is_chromium = "Chrome/" in ua or "Edg/" in ua
        has_hints = "Sec-CH-UA" in p["headers"]
        assert has_hints == is_chromium, f"client-hint mismatch for {ua}"


def test_client_hint_version_matches_the_user_agent():
    import re

    for p in BROWSER_PROFILES:
        hints = p["headers"].get("Sec-CH-UA")
        if not hints:
            continue
        ua_ver = re.search(r"Chrome/(\d+)", str(p["ua"])).group(1)
        assert f'"{ua_ver}"' in hints, f"{p['ua']} claims a different hint version"


def test_mobile_hint_matches_the_platform():
    for p in BROWSER_PROFILES:
        mobile = p["headers"].get("Sec-CH-UA-Mobile")
        if mobile is None:
            continue
        looks_mobile = "Mobile" in str(p["ua"]) or "Android" in str(p["ua"])
        assert (mobile == "?1") == looks_mobile, f"mobile flag wrong for {p['ua']}"


def test_rotation_returns_whole_profiles(clean_settings):
    settings.user_agent_mode = MODE_ROTATE
    seen = {str(current_profile()["ua"]) for _ in range(200)}
    assert len(seen) > 1
    # And the headers always travel with their own UA
    for _ in range(50):
        p = current_profile()
        assert p["headers"]["Accept"]
        if "Firefox" in str(p["ua"]):
            assert "Sec-CH-UA" not in p["headers"]


def test_unknown_custom_ua_does_not_get_chromium_hints(clean_settings):
    """A pinned Firefox UA must not be paired with client hints."""
    settings.user_agent_mode = "fixed"
    settings.user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0"
    assert "Sec-CH-UA" not in current_profile()["headers"]


def test_emitted_headers_are_coherent_for_dash_h_tools(clean_settings):
    settings.user_agent_mode = MODE_ROTATE
    settings.pentest_id = ""
    args = identity_args("nuclei")
    sent = dict(a.split(": ", 1) for a in args if a != "-H")
    ua = sent["User-Agent"]
    if "Firefox" in ua:
        assert "Sec-CH-UA" not in sent
    else:
        assert sent.get("Sec-CH-UA")
    assert sent["Accept"]
    assert "X-Pentest-ID" not in sent


@pytest.mark.parametrize("tool", ["subfinder", "dnsx", "naabu", "gau", "nmap", "testssl"])
def test_non_http_tools_get_nothing(clean_settings, tool):
    settings.user_agent_mode = "fixed"
    settings.pentest_id = "AUDIT-1"
    assert identity_args(tool) == []


def test_wpscan_does_not_combine_conflicting_ua_flags(clean_settings):
    """--random-user-agent and --user-agent together make wpscan error out."""
    settings.user_agent_mode = MODE_ROTATE
    settings.pentest_id = ""
    assert "--user-agent" not in identity_args("wpscan")

    settings.user_agent_mode = "fixed"
    settings.user_agent = "TestAgent/1.0"
    assert identity_args("wpscan")[:2] == ["--user-agent", "TestAgent/1.0"]


def test_wpscan_wrapper_only_randomises_in_rotate_mode(clean_settings):
    from app.scans.wrappers.wpscan import WpscanWrapper

    settings.user_agent_mode = MODE_ROTATE
    assert "--random-user-agent" in WpscanWrapper().build_command("http://t", [])

    settings.user_agent_mode = "fixed"
    assert "--random-user-agent" not in WpscanWrapper().build_command("http://t", [])


# ---- Proxy flags ----

def test_proxy_flags_are_tool_specific():
    assert proxy_args("nuclei", "socks5://127.0.0.1:9050") == ["-proxy", "socks5://127.0.0.1:9050"]
    assert proxy_args("ffuf", "socks5://127.0.0.1:9050") == ["-x", "socks5://127.0.0.1:9050"]
    assert proxy_args("sqlmap", "http://p:8080") == ["--proxy=http://p:8080"]


def test_unsupported_tool_gets_no_proxy_flag():
    """Better no flag than a wrong one that the binary silently ignores."""
    assert proxy_args("subfinder", "socks5://127.0.0.1:9050") == []
    assert not supports_proxy("subfinder")


def test_empty_proxy_is_a_noop():
    assert proxy_args("nuclei", "") == []


# ---- Kill switch ----

async def test_guard_allows_when_require_vpn_is_off(clean_settings):
    settings.require_vpn = False
    result = await NetworkPrivacyManager().guard_scan()
    assert result["allowed"] is True


async def test_guard_blocks_when_vpn_required_but_absent(clean_settings):
    settings.require_vpn = True
    manager = NetworkPrivacyManager()
    manager.state.mode = MODE_OFF
    result = await manager.guard_scan()
    assert result["allowed"] is False
    assert "no VPN" in result["reason"]


async def test_leaking_tunnel_is_detected(clean_settings):
    """Exit IP still equal to the real IP means traffic bypasses the tunnel."""
    settings.require_vpn = True
    manager = NetworkPrivacyManager()
    manager.state.mode = MODE_PROXY
    manager.state.proxy_url = "socks5://127.0.0.1:9050"
    manager.state.baseline_ip = "203.0.113.7"

    async def same_ip(through_proxy: bool = True):
        return "203.0.113.7"

    manager.get_public_ip = same_ip

    check = await manager.verify_exit_ip()
    assert check["safe"] is False
    assert "NOT going through the tunnel" in check["reason"]
    assert (await manager.guard_scan())["allowed"] is False


async def test_working_tunnel_is_allowed(clean_settings):
    settings.require_vpn = True
    manager = NetworkPrivacyManager()
    manager.state.mode = MODE_PROXY
    manager.state.proxy_url = "socks5://127.0.0.1:9050"
    manager.state.baseline_ip = "203.0.113.7"

    async def tunnel_ip(through_proxy: bool = True):
        return "198.51.100.42"

    manager.get_public_ip = tunnel_ip

    check = await manager.verify_exit_ip()
    assert check["safe"] is True
    assert (await manager.guard_scan())["allowed"] is True


async def test_unreadable_ip_is_treated_as_unsafe(clean_settings):
    """Cannot confirm the tunnel is up, so do not let a scan start."""
    settings.require_vpn = True
    manager = NetworkPrivacyManager()
    manager.state.mode = MODE_PROXY
    manager.state.baseline_ip = "203.0.113.7"

    async def no_ip(through_proxy: bool = True):
        return None

    manager.get_public_ip = no_ip
    assert (await manager.verify_exit_ip())["safe"] is False


async def test_rejects_a_proxy_url_without_a_scheme():
    result = await NetworkPrivacyManager().set_proxy("127.0.0.1:9050")
    assert result["ok"] is False


def test_proxy_credentials_are_never_echoed_back():
    manager = NetworkPrivacyManager()
    manager.state.mode = MODE_PROXY
    manager.state.proxy_url = "socks5://user:hunter2@10.0.0.1:1080"
    exposed = manager.state.to_dict()["proxy_url"]
    assert "hunter2" not in exposed
    assert exposed == "socks5://***@10.0.0.1:1080"
