"""Shared interface for CLI tool wrappers.

Each wrapper knows how to:
  1. build a command from (target, options),
  2. declare if its binary is installed,
  3. parse its own output into a list of normalized `Finding`s.

The actual subprocess execution happens in `app.scans.runner` so the wrappers
stay pure and unit-testable (no asyncio, no DB).
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import List, Sequence

from app.scans.models import Finding


@dataclass
class ToolResult:
    """Return type of `parse`."""
    findings: List[Finding]


class BaseWrapper:
    name: str = ""
    binary: str = ""
    description: str = ""

    # Hard cap on runtime (seconds). Subclasses can override.
    timeout_seconds: int = 30 * 60

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        """Return the argv to run. Must include the binary as argv[0]."""
        raise NotImplementedError

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        raise NotImplementedError
