"""Map the configured scan identity (User-Agent, attribution header) to
per-tool CLI flags.

Same shape as `auth_args` / `waf_args`: the wrappers stay pure, and this is
the single place that knows how each binary spells "User-Agent".

Two settings drive it:

  user_agent_mode = fixed | rotate
      fixed  - send `user_agent` on every request (default)
      rotate - pick a random real browser string per job

  pentest_id
      When set, adds `X-Pentest-ID: <value>` to every request. On an authorized
      engagement the client's blue team needs to tell your traffic apart from a
      real attack; without it your scan reads as an intrusion and someone gets
      paged at 3am. Leave it empty when you are explicitly testing detection.

Note this cannot make a scan untraceable. Your source IP is in their logs, the
request timing is a signature, and the payloads are recorded. What it controls
is whether the traffic fingerprints as *this tool* - the crawler used to
announce itself by name in every access log line.
"""
from __future__ import annotations

import random
from typing import List

from app.config import settings

MODE_FIXED = "fixed"
MODE_ROTATE = "rotate"

# Deliberately common strings: a User-Agent nobody else sends is itself a
# signature, which defeats the point.
USER_AGENT_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
]

# Tools that accept repeated `-H "Name: value"`.
_DASH_H = {"nuclei", "ffuf", "dalfox", "katana", "httpx"}

# Recon tools that never make an HTTP app request: nothing to set.
_NO_HTTP = {"subfinder", "dnsx", "naabu", "gau", "nmap", "testssl"}


def current_user_agent() -> str:
    """The User-Agent to use for the next job"""
    mode = (settings.user_agent_mode or MODE_FIXED).strip().lower()
    if mode == MODE_ROTATE:
        return random.choice(USER_AGENT_POOL)
    return settings.user_agent


def identity_args(tool: str) -> List[str]:
    """CLI flags carrying the User-Agent and attribution header for `tool`"""
    if tool in _NO_HTTP:
        return []

    ua = (current_user_agent() or "").strip()
    pentest_id = (settings.pentest_id or "").strip()
    if not ua and not pentest_id:
        return []

    if tool in _DASH_H:
        args: List[str] = []
        if ua:
            args += ["-H", f"User-Agent: {ua}"]
        if pentest_id:
            args += ["-H", f"X-Pentest-ID: {pentest_id}"]
        return args

    if tool == "sqlmap":
        args = []
        if ua:
            args += ["--user-agent", ua]
        if pentest_id:
            args += ["-H", f"X-Pentest-ID: {pentest_id}"]
        return args

    if tool == "commix":
        args = []
        if ua:
            args += ["--user-agent", ua]
        if pentest_id:
            args += ["--headers", f"X-Pentest-ID: {pentest_id}"]
        return args

    if tool == "wpscan":
        # In rotate mode the wrapper adds --random-user-agent and we must not
        # also pass --user-agent: the two conflict.
        if (settings.user_agent_mode or "").strip().lower() == MODE_ROTATE:
            return ["--headers", f"X-Pentest-ID: {pentest_id}"] if pentest_id else []
        args = []
        if ua:
            args += ["--user-agent", ua]
        if pentest_id:
            args += ["--headers", f"X-Pentest-ID: {pentest_id}"]
        return args

    if tool == "whatweb":
        args = []
        if ua:
            args += [f"--user-agent={ua}"]
        if pentest_id:
            args += [f"--header=X-Pentest-ID: {pentest_id}"]
        return args

    if tool == "nikto":
        args = []
        if ua:
            args += ["-useragent", ua]
        return args

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
