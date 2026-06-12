"""Grounding & safety helpers shared by the LLM features.

The whole point: the LLM *proposes*, these pure helpers make sure it cannot
invent a target/finding or slip an unsafe option past the deterministic
executor. Everything here is pure (no IO) so it is unit-tested without a model.
"""
from __future__ import annotations

import json
import re
from typing import Any, List, Optional, Set

_JSON_BLOCK = re.compile(r"[\[{][\s\S]*[\]}]")

VALID_SEVERITY = {"critical", "high", "medium", "low", "info"}
VALID_STATUS = {"confirmed", "likely", "unconfirmed", "false_positive"}
# nuclei tags / ffuf-style tokens: keep to a safe charset (no shell metachars).
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._-]{1,40}$")


def extract_json(text: str) -> Optional[Any]:
    """Parse a JSON object/array out of an LLM reply, tolerating ``` fences and
    surrounding prose. Returns None on failure (caller degrades gracefully)."""
    if not text:
        return None
    c = text.strip()
    if c.startswith("```"):
        c = c.strip("`")
        parts = c.split("\n", 1)
        if len(parts) == 2 and len(parts[0]) <= 12:
            c = parts[1]
    try:
        return json.loads(c)
    except json.JSONDecodeError:
        m = _JSON_BLOCK.search(text)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None


def quote_is_grounded(quote: str, corpus: str, *, min_len: int = 8) -> bool:
    """True only if `quote` (a claimed evidence substring) actually appears in
    the corpus we sent the model. The anti-hallucination gate: a finding/judgment
    that can't point at real captured text is dropped."""
    q = (quote or "").strip()
    if len(q) < min_len:
        return False
    return q.lower() in (corpus or "").lower()


def clamp_confidence(v: Any, default: float = 0.5) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, f))


def norm_severity(s: Any, default: str = "info") -> str:
    s = str(s or "").lower().strip()
    return s if s in VALID_SEVERITY else default


def norm_status(s: Any, default: str = "likely") -> str:
    s = str(s or "").lower().strip()
    return s if s in VALID_STATUS else default


def safe_tokens(values: Any, *, limit: int = 12) -> List[str]:
    """Keep only tokens that match the safe charset (for nuclei -tags etc.)."""
    out: List[str] = []
    for v in (values or []):
        t = str(v).strip().lower()
        if _SAFE_TOKEN.match(t):
            out.append(t)
        if len(out) >= limit:
            break
    return out


def filter_options(options: Any, allowed: Set[str]) -> List[str]:
    """Keep only options whose flag (token before '=' or space) is allowlisted.
    Used to constrain LLM-proposed tool flags to a vetted set."""
    out: List[str] = []
    for o in (options or []):
        s = str(o)
        if not s:
            continue
        flag = s.split("=", 1)[0].split()[0]
        if flag in allowed:
            out.append(s)
    return out
