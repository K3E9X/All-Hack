"""Make scan traffic look like an ordinary browser.

Same shape as `auth_args` / `waf_args`: the wrappers stay pure, and this is
the single place that knows how each binary spells "User-Agent" and "header".

Why profiles rather than a list of User-Agent strings
-----------------------------------------------------
Rotating only the User-Agent is itself a signature. A real Chrome sends
Sec-CH-UA client hints, a specific Accept ordering and Sec-Fetch-* metadata;
Firefox sends none of the client hints and a different Accept. A request that
claims to be Firefox while sending Sec-CH-UA, or that claims Chrome while
sending a bare `Accept: */*`, stands out more than one with no User-Agent at
all - naive filters look at the UA, better ones look at whether the whole set
is self-consistent.

So each profile bundles a User-Agent with the exact headers that browser
really sends, and rotation picks a whole profile.

What this does not do
---------------------
It does not make a scan invisible. Your source IP is in their logs, the
request rate and ordering are a far stronger signal than any header, and the
payloads themselves are recorded. This defeats fingerprinting of *the tool*;
it does nothing against rate-based or behavioural detection. Use the scope
rate limit for that.
"""
from __future__ import annotations

import random
from typing import Dict, List

from app.config import settings

MODE_FIXED = "fixed"
MODE_ROTATE = "rotate"

# Accept strings, verbatim from each engine. Chromium's is the long one with
# the signed-exchange suffix; sending Firefox's with a Chrome UA is a tell.
_ACCEPT_CHROMIUM = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
)
_ACCEPT_FIREFOX = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,*/*;q=0.8"
)
_ACCEPT_SAFARI = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

# Navigation metadata every modern browser sends on a top-level request.
_FETCH_NAV = {
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


def _chromium(ua: str, brand: str, version: str, platform: str,
              mobile: str = "?0", lang: str = "en-US,en;q=0.9") -> Dict[str, object]:
    return {
        "ua": ua,
        "headers": {
            "Accept": _ACCEPT_CHROMIUM,
            "Accept-Language": lang,
            # Client hints: Chromium only. Order and the padding brand entry
            # match what the browser actually emits.
            "Sec-CH-UA": f'"Not/A)Brand";v="8", "Chromium";v="{version}", "{brand}";v="{version}"',
            "Sec-CH-UA-Mobile": mobile,
            "Sec-CH-UA-Platform": f'"{platform}"',
            **_FETCH_NAV,
        },
    }


def _gecko(ua: str, lang: str = "en-US,en;q=0.5") -> Dict[str, object]:
    return {
        "ua": ua,
        # No Sec-CH-UA: Firefox does not implement client hints.
        "headers": {"Accept": _ACCEPT_FIREFOX, "Accept-Language": lang, **_FETCH_NAV},
    }


def _webkit(ua: str, lang: str = "en-US,en;q=0.9") -> Dict[str, object]:
    return {
        "ua": ua,
        "headers": {"Accept": _ACCEPT_SAFARI, "Accept-Language": lang, **_FETCH_NAV},
    }


# Common, boring, current browsers. A rare browser is as memorable as a
# scanner UA, so nothing exotic here on purpose.
BROWSER_PROFILES: List[Dict[str, object]] = [
    _chromium(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36",
        "Google Chrome", "126", "Windows",
    ),
    _chromium(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36",
        "Google Chrome", "125", "Windows",
    ),
    _chromium(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36",
        "Google Chrome", "126", "macOS",
    ),
    _chromium(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36",
        "Google Chrome", "126", "Linux",
    ),
    _chromium(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        "Microsoft Edge", "126", "Windows",
    ),
    _chromium(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Mobile Safari/537.36",
        "Google Chrome", "126", "Android", mobile="?1",
    ),
    _gecko(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0"
    ),
    _gecko("Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"),
    _webkit(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.5 Safari/605.1.15"
    ),
    _webkit(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    ),
]

# Tools that accept repeated `-H "Name: value"`.
_DASH_H = {"nuclei", "ffuf", "dalfox", "katana", "httpx"}

# Recon tools that never make an HTTP app request: nothing to set.
_NO_HTTP = {"subfinder", "dnsx", "naabu", "gau", "nmap", "testssl"}


def current_profile() -> Dict[str, object]:
    """The browser profile to impersonate for the next job."""
    mode = (settings.user_agent_mode or MODE_ROTATE).strip().lower()
    if mode == MODE_ROTATE:
        return random.choice(BROWSER_PROFILES)

    # Fixed mode: the operator pinned a User-Agent. Reuse the matching
    # profile's headers when we recognise it, so the set stays coherent.
    pinned = (settings.user_agent or "").strip()
    for profile in BROWSER_PROFILES:
        if profile["ua"] == pinned:
            return profile
    if not pinned:
        return BROWSER_PROFILES[0]
    # Unknown custom UA: infer the engine from the string rather than pairing
    # it with Chromium client hints it would never send.
    low = pinned.lower()
    if "firefox" in low:
        return _gecko(pinned)
    if "safari" in low and "chrome" not in low:
        return _webkit(pinned)
    return {"ua": pinned, "headers": {"Accept": _ACCEPT_CHROMIUM,
                                      "Accept-Language": "en-US,en;q=0.9", **_FETCH_NAV}}


def current_user_agent() -> str:
    """The User-Agent to use for the next job"""
    return str(current_profile()["ua"])


def _headers_for_job() -> Dict[str, str]:
    """Full header set for this job: browser profile, plus the optional
    attribution header when the operator explicitly set one."""
    profile = current_profile()
    headers: Dict[str, str] = {"User-Agent": str(profile["ua"])}
    headers.update(profile["headers"])  # type: ignore[arg-type]

    # Off unless PENTEST_ID is set. It marks the traffic as an authorized test
    # so the client's SOC can tell it apart from a real intrusion - useful on
    # some engagements, and exactly what you do not want when the point is to
    # blend in or to test their detection.
    pentest_id = (settings.pentest_id or "").strip()
    if pentest_id:
        headers["X-Pentest-ID"] = pentest_id
    return headers


def identity_args(tool: str) -> List[str]:
    """CLI flags carrying the browser profile headers for `tool`"""
    if tool in _NO_HTTP:
        return []

    headers = _headers_for_job()
    ua = headers.pop("User-Agent", "")
    if not ua and not headers:
        return []

    if tool in _DASH_H:
        args: List[str] = []
        if ua:
            args += ["-H", f"User-Agent: {ua}"]
        for name, value in headers.items():
            args += ["-H", f"{name}: {value}"]
        return args

    if tool == "sqlmap":
        args = []
        if ua:
            args += ["--user-agent", ua]
        for name, value in headers.items():
            args += ["-H", f"{name}: {value}"]
        return args

    if tool == "commix":
        args = []
        if ua:
            args += ["--user-agent", ua]
        if headers:
            # commix takes every extra header in one \n-separated blob.
            args += ["--headers", "\\n".join(f"{n}: {v}" for n, v in headers.items())]
        return args

    if tool == "wpscan":
        # In rotate mode the wrapper adds --random-user-agent and we must not
        # also pass --user-agent: the two conflict.
        rotating = (settings.user_agent_mode or MODE_ROTATE).strip().lower() == MODE_ROTATE
        args = []
        if ua and not rotating:
            args += ["--user-agent", ua]
        for name, value in headers.items():
            args += ["--headers", f"{name}: {value}"]
        return args

    if tool == "whatweb":
        args = []
        if ua:
            args += [f"--user-agent={ua}"]
        args += [f"--header={n}: {v}" for n, v in headers.items()]
        return args

    if tool == "nikto":
        # nikto has no repeatable header flag worth relying on; UA only.
        return ["-useragent", ua] if ua else []

    return []


# How each binary spells "route through this proxy". Tools missing from the
# map get nothing rather than a wrong flag - a scan that silently ignores the
# proxy is worse than one that never claimed to use it.
_PROXY_FLAG = {
    "nuclei": lambda p: ["-proxy", p],
    "katana": lambda p: ["-proxy", p],
    "httpx": lambda p: ["-proxy", p],
    "dalfox": lambda p: ["--proxy", p],
    "ffuf": lambda p: ["-x", p],
    "sqlmap": lambda p: [f"--proxy={p}"],
    "commix": lambda p: [f"--proxy={p}"],
    "wpscan": lambda p: ["--proxy", p],
    "nikto": lambda p: ["-useproxy", p],
}


def proxy_args(tool: str, proxy_url: str) -> List[str]:
    """CLI flags routing `tool` through `proxy_url`, empty if unsupported"""
    if not proxy_url:
        return []
    builder = _PROXY_FLAG.get(tool)
    return builder(proxy_url) if builder else []


def supports_proxy(tool: str) -> bool:
    return tool in _PROXY_FLAG
