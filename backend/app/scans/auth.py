"""Map an identity's HTTP headers to per-tool CLI flags for authenticated scans.

Each wrapper takes auth differently; this is the single place that knows how.
Headers come from the engagement's primary identity (list of {name,value}).
Recon tools that don't make authenticated app requests get nothing.
"""
from __future__ import annotations

from typing import Dict, List

# Tools that accept repeated `-H "Name: value"`.
_DASH_H = {"nuclei", "ffuf", "dalfox", "katana", "httpx"}


def auth_args(tool: str, headers: List[Dict[str, str]]) -> List[str]:
    pairs = [(h.get("name", "").strip(), h.get("value", "").strip())
             for h in headers or []]
    pairs = [(n, v) for n, v in pairs if n and v]
    if not pairs:
        return []

    if tool in _DASH_H:
        args: List[str] = []
        for n, v in pairs:
            args += ["-H", f"{n}: {v}"]
        return args

    if tool == "sqlmap":
        # sqlmap wants the session as --cookie; other headers via repeated -H.
        # Using -H for the Cookie leaves sqlmap effectively unauthenticated.
        cookie = next((v for n, v in pairs if n.lower() == "cookie"), None)
        args = []
        if cookie:
            args += ["--cookie", cookie]
        for n, v in pairs:
            if n.lower() != "cookie":
                args += ["-H", f"{n}: {v}"]
        return args

    if tool == "commix":
        # commix takes all extra headers in one --headers blob (\n separated),
        # and a Cookie via --cookie.
        cookie = next((v for n, v in pairs if n.lower() == "cookie"), None)
        others = [f"{n}: {v}" for n, v in pairs if n.lower() != "cookie"]
        args = []
        if cookie:
            args += ["--cookie", cookie]
        if others:
            args += ["--headers", "\\n".join(others)]
        return args

    if tool == "wpscan":
        cookie = next((v for n, v in pairs if n.lower() == "cookie"), None)
        others = [f"{n}: {v}" for n, v in pairs if n.lower() != "cookie"]
        args = []
        if cookie:
            args += ["--cookie-string", cookie]
        for h in others:
            args += ["--headers", h]
        return args

    if tool == "whatweb":
        return [f"--header={n}: {v}" for n, v in pairs]

    # nikto and recon tools (subfinder/dnsx/naabu/gau): no authenticated
    # app-request semantics here.
    return []
