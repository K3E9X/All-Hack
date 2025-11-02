"""Lightweight monitoring helpers to observe host stability during scans."""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class StabilityMonitor:
    """Capture system load information to diagnose scan-induced instability."""

    def __init__(self) -> None:
        self.snapshots: Dict[str, List[Dict[str, Any]]] = {}

    def snapshot(self, label: str) -> Dict[str, Any]:
        load_avg = self._load_average()
        memory = self._memory_usage()

        metrics = {
            "timestamp": datetime.utcnow(),
            "label": label,
            "load_average": load_avg,
            "memory": memory,
        }

        self.snapshots.setdefault(label, []).append(metrics)
        logger.debug("Recorded stability snapshot for %s", label)
        return metrics

    def _load_average(self) -> Dict[str, float]:
        try:
            one, five, fifteen = os.getloadavg()
            return {"1m": one, "5m": five, "15m": fifteen}
        except OSError:  # pragma: no cover - not supported on all OS
            return {"1m": 0.0, "5m": 0.0, "15m": 0.0}

    def _memory_usage(self) -> Dict[str, float]:
        meminfo_path = "/proc/meminfo"
        info: Dict[str, float] = {"total_mb": 0.0, "available_mb": 0.0}

        try:
            with open(meminfo_path, "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("MemTotal"):
                        info["total_mb"] = float(line.split()[1]) / 1024
                    if line.startswith("MemAvailable"):
                        info["available_mb"] = float(line.split()[1]) / 1024
        except FileNotFoundError:  # pragma: no cover - non-Linux hosts
            logger.debug("/proc/meminfo not available; skipping memory metrics")

        if info["total_mb"]:
            used = info["total_mb"] - info.get("available_mb", 0.0)
            info["used_mb"] = used
            info["used_percent"] = round((used / info["total_mb"]) * 100, 2)
        return info

