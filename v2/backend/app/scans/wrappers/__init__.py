"""Registry of available CLI tool wrappers."""
from __future__ import annotations

from typing import Dict, List

from app.scans.wrappers.base import BaseWrapper
from app.scans.wrappers.dalfox import DalfoxWrapper
from app.scans.wrappers.ffuf import FfufWrapper
from app.scans.wrappers.httpx import HttpxWrapper
from app.scans.wrappers.nmap import NmapWrapper
from app.scans.wrappers.nuclei import NucleiWrapper
from app.scans.wrappers.sqlmap import SqlmapWrapper
from app.scans.wrappers.subfinder import SubfinderWrapper

_WRAPPERS: Dict[str, BaseWrapper] = {
    "nuclei": NucleiWrapper(),
    "sqlmap": SqlmapWrapper(),
    "ffuf": FfufWrapper(),
    "dalfox": DalfoxWrapper(),
    "nmap": NmapWrapper(),
    "subfinder": SubfinderWrapper(),
    "httpx": HttpxWrapper(),
}


def get_wrapper(name: str) -> BaseWrapper:
    if name not in _WRAPPERS:
        raise KeyError(f"unknown tool: {name}")
    return _WRAPPERS[name]


def available_wrappers() -> List[Dict[str, object]]:
    """List of tools with availability info. Used by /api/scans/tools."""
    return [
        {
            "name": w.name,
            "binary": w.binary,
            "available": w.is_available(),
            "description": w.description,
        }
        for w in _WRAPPERS.values()
    ]


__all__ = ["BaseWrapper", "get_wrapper", "available_wrappers"]
