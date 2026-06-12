"""Planner agent (spec §4.1).

Given the engagement state, decide the next batch of tasks: which catalog
items to run against which assets, in what order. The planner is
deterministic-first (methodology engine), with an optional LLM re-ordering
pass that is strictly constrained to the candidate tasks it is given - it can
reorder and drop, never invent. If no planner LLM is configured or its reply
doesn't parse, we keep the deterministic order. That guarantees the loop
always makes progress, with or without a model.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.llm import ROLE_PLANNER, LLMError, get_router
from app.methodology import CATALOG, CATALOG_BY_ID, PHASE_ORDER, applies
from app.orchestrator.state import Asset, EngagementState

logger = logging.getLogger("allhack.orchestrator.planner")

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Task:
    catalog_item_id: str
    asset_value: str
    tool: str
    options: List[str]
    phase: str

    @property
    def key(self) -> str:
        return f"{self.catalog_item_id}@{self.asset_value}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "catalog_item_id": self.catalog_item_id,
            "asset_value": self.asset_value,
            "tool": self.tool,
            "options": self.options,
            "phase": self.phase,
            "key": self.key,
        }


class Planner:
    def __init__(self, state: EngagementState) -> None:
        self.state = state

    async def plan(self, *, max_tasks: int = 12, use_llm: bool = True) -> List[Task]:
        """Return the next batch of uncovered, applicable tasks."""
        assets = await self.state.assets()
        tech = await self.state.technologies()

        candidates = await self._candidate_tasks(assets, tech)
        if not candidates:
            return []

        # Deterministic order: phase first, then severity of the catalog item.
        candidates.sort(key=_task_sort_key)

        # Only advance one phase at a time: take the earliest phase that still
        # has uncovered work, so we always recon/map before we exploit.
        earliest_phase = candidates[0].phase
        batch = [t for t in candidates if t.phase == earliest_phase][:max_tasks]

        if use_llm:
            batch = await self._llm_reorder(batch, tech)

        return batch

    async def _candidate_tasks(self, assets: List[Asset], tech: List[str]) -> List[Task]:
        tasks: List[Task] = []
        for item in CATALOG:
            for asset in assets:
                ctx = asset.context(tech)
                # Match the asset kind to the item's expectation.
                wants_host = bool(item.applies_when.get("is_host"))
                if wants_host and asset.kind != "host":
                    continue
                if not wants_host and asset.kind == "host" and not item.applies_when.get("always"):
                    # non-host items generally run on endpoints; allow 'always'
                    # items on the host's base URL too (handled below).
                    pass
                if not applies(item, ctx):
                    continue
                if await self.state.is_covered(item.id, asset.value):
                    continue
                tasks.append(
                    Task(
                        catalog_item_id=item.id,
                        asset_value=asset.value,
                        tool=item.tool,
                        options=list(item.default_options),
                        phase=item.phase,
                    )
                )
        return tasks

    async def _llm_reorder(self, batch: List[Task], tech: List[str]) -> List[Task]:
        if len(batch) <= 1:
            return batch
        client = get_router().get(ROLE_PLANNER)
        if not client.configured:
            return batch

        by_key = {t.key: t for t in batch}
        catalog_brief = {
            t.catalog_item_id: {
                "wstg": CATALOG_BY_ID[t.catalog_item_id].wstg_id,
                "vuln_class": CATALOG_BY_ID[t.catalog_item_id].vuln_class,
                "severity": CATALOG_BY_ID[t.catalog_item_id].severity_default,
            }
            for t in batch
        }
        payload = {
            "technologies": tech,
            "candidate_tasks": [
                {"key": t.key, "tool": t.tool, "catalog_item": t.catalog_item_id,
                 "asset": t.asset_value, "phase": t.phase}
                for t in batch
            ],
            "catalog": catalog_brief,
        }
        system = (
            "You are the planner of a web-app pentest. You are given candidate "
            "tasks for the current phase. Reorder them by likely impact and drop "
            "clearly redundant ones. You MUST only use the provided task keys; "
            "never invent tasks. Reply with JSON only: "
            '{"ordered_keys": ["key1","key2",...], "rationale": "short"}'
        )
        try:
            reply = await client.chat(
                [
                    {"role": "system", "content": system},
                    {"role": "user", "content": json.dumps(payload)},
                ],
                temperature=0.1,
                max_tokens=800,
            )
        except LLMError as exc:
            logger.warning("planner LLM unavailable, keeping deterministic order: %s", exc)
            return batch
        except Exception as exc:  # noqa: BLE001 - never let reordering break planning
            logger.warning("planner LLM error, keeping deterministic order: %s", exc)
            return batch

        ordered = _parse_ordered_keys(reply)
        if not ordered:
            return batch

        # Rebuild using only known keys, preserving the model's order, then
        # append any keys it dropped (we never silently lose coverage work).
        seen = set()
        result: List[Task] = []
        for k in ordered:
            t = by_key.get(k)
            if t and k not in seen:
                result.append(t)
                seen.add(k)
        for t in batch:
            if t.key not in seen:
                result.append(t)
        return result


def _task_sort_key(t: Task):
    phase_idx = PHASE_ORDER.index(t.phase) if t.phase in PHASE_ORDER else 99
    item = CATALOG_BY_ID.get(t.catalog_item_id)
    sev = _SEVERITY_RANK.get(item.severity_default if item else "info", 4)
    return (phase_idx, sev, t.catalog_item_id, t.asset_value)


def _parse_ordered_keys(reply: str) -> List[str]:
    text = reply.strip()
    if text.startswith("```"):
        text = text.strip("`")
        parts = text.split("\n", 1)
        if len(parts) == 2 and len(parts[0]) <= 10:
            text = parts[1]
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1:
            return []
        try:
            obj = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return []
    keys = obj.get("ordered_keys") if isinstance(obj, dict) else None
    return [str(k) for k in keys] if isinstance(keys, list) else []
