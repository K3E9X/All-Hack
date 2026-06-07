"""Pure helpers for methodology coverage + the engagement test radar.

WSTG ids (e.g. WSTG-INPV-05) roll up to a category (prefix WSTG-INPV) and to one
of six radar axes. No web/DB imports so this stays unit-testable.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Set

AXES = ["Recon", "Config", "Injection", "Auth", "Session", "API"]

# WSTG prefix -> (human label, radar axis)
WSTG_CAT = {
    "WSTG-INFO": ("Reconnaissance", "Recon"),
    "WSTG-CONF": ("Config & deploy", "Config"),
    "WSTG-CRYP": ("Cryptography", "Config"),
    "WSTG-INPV": ("Input validation", "Injection"),
    "WSTG-BUSL": ("Business logic", "Injection"),
    "WSTG-ATHN": ("Authentication", "Auth"),
    "WSTG-ATHZ": ("Authorization", "Auth"),
    "WSTG-SESS": ("Session management", "Session"),
    "WSTG-APIT": ("API", "API"),
    "WSTG-CLNT": ("Client-side", "API"),
}
_DONE = {"done", "succeeded"}


def wstg_prefix(wstg_id: str) -> str:
    parts = (wstg_id or "").split("-")
    return "-".join(parts[:2]) if len(parts) >= 2 else (wstg_id or "WSTG-INFO")


def axis_for(wstg_id: str) -> str:
    return WSTG_CAT.get(wstg_prefix(wstg_id), ("Other", "Recon"))[1]


def radar(catalog: Iterable[Any], covered_item_ids: Set[str]) -> List[int]:
    """Percentage of catalog items covered (a 'done' row) per radar axis."""
    tot = {a: 0 for a in AXES}
    hit = {a: 0 for a in AXES}
    for item in catalog:
        axis = axis_for(getattr(item, "wstg_id", ""))
        if axis not in tot:
            continue
        tot[axis] += 1
        if getattr(item, "id", None) in covered_item_ids:
            hit[axis] += 1
    return [round(hit[a] / tot[a] * 100) if tot[a] else 0 for a in AXES]


def progress_pct(catalog: Iterable[Any], covered_item_ids: Set[str]) -> int:
    items = list(catalog)
    if not items:
        return 0
    covered = sum(1 for it in items if getattr(it, "id", None) in covered_item_ids)
    return round(covered / len(items) * 100)


def covered_ids(coverage_rows: Iterable[Dict[str, Any]]) -> Set[str]:
    return {r["catalog_item_id"] for r in coverage_rows if (r.get("status") or "") in _DONE}


def coverage_groups(catalog: Iterable[Any], coverage_rows: Iterable[Dict[str, Any]],
                    finding_classes: Set[str]) -> List[Dict[str, Any]]:
    """Group the catalog by WSTG category with per-item status + hit flag."""
    rows_by_item: Dict[str, List[Dict[str, Any]]] = {}
    for r in coverage_rows:
        rows_by_item.setdefault(r["catalog_item_id"], []).append(r)

    groups: Dict[str, Dict[str, Any]] = {}
    for item in catalog:
        prefix = wstg_prefix(getattr(item, "wstg_id", ""))
        label, _axis = WSTG_CAT.get(prefix, ("Other", "Recon"))
        g = groups.setdefault(prefix, {"cat": label, "wstg": prefix, "items": []})
        rows = rows_by_item.get(item.id, [])
        statuses = {(r.get("status") or "") for r in rows}
        if "running" in statuses:
            status = "running"
        elif statuses & _DONE:
            status = "done"
        elif "skipped" in statuses:
            status = "skipped"
        else:
            status = "queued"
        g["items"].append({
            "id": item.id,
            "name": item.description,
            "attack": getattr(item, "attack_techniques", []),
            "asset": (rows[0].get("asset_value") if rows else "-"),
            "status": status,
            "hit": item.vuln_class in finding_classes,
        })
    return list(groups.values())
