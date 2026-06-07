"""WSTG -> category/axis mapping, radar and coverage grouping."""
from types import SimpleNamespace

from app import coverage_util as cu


def _item(iid, wstg, vclass):
    return SimpleNamespace(id=iid, wstg_id=wstg, vuln_class=vclass,
                           description=f"test {iid}", attack_techniques=["T1190"])


CATALOG = [
    _item("RECON-1", "WSTG-INFO-04", "recon"),
    _item("EXP-SQLI", "WSTG-INPV-05", "sql_injection"),
    _item("EXP-XSS", "WSTG-INPV-01", "xss"),
    _item("VULN-TLS", "WSTG-CRYP-01", "weak_tls"),
    _item("MAP-TAKEOVER", "WSTG-CONF-10", "subdomain_takeover"),
]


def test_wstg_prefix_and_axis():
    assert cu.wstg_prefix("WSTG-INPV-05") == "WSTG-INPV"
    assert cu.axis_for("WSTG-INPV-05") == "Injection"
    assert cu.axis_for("WSTG-INFO-04") == "Recon"
    assert cu.axis_for("WSTG-CRYP-01") == "Config"


def test_covered_ids_only_done():
    rows = [
        {"catalog_item_id": "RECON-1", "asset_value": "t", "status": "done"},
        {"catalog_item_id": "EXP-SQLI", "asset_value": "t", "status": "running"},
        {"catalog_item_id": "EXP-XSS", "asset_value": "t", "status": "succeeded"},
    ]
    assert cu.covered_ids(rows) == {"RECON-1", "EXP-XSS"}


def test_radar_axes_length_and_values():
    rows = [{"catalog_item_id": "RECON-1", "asset_value": "t", "status": "done"}]
    r = cu.radar(CATALOG, cu.covered_ids(rows))
    assert len(r) == len(cu.AXES) == 6
    assert r[cu.AXES.index("Recon")] == 100   # 1/1 recon items done
    assert r[cu.AXES.index("Injection")] == 0  # none of the 2 injection items done


def test_progress_pct():
    rows = [{"catalog_item_id": "RECON-1", "asset_value": "t", "status": "done"}]
    assert cu.progress_pct(CATALOG, cu.covered_ids(rows)) == round(1 / 5 * 100)


def test_coverage_groups_status_and_hit():
    rows = [
        {"catalog_item_id": "EXP-SQLI", "asset_value": "https://t/?p=", "status": "done"},
        {"catalog_item_id": "EXP-XSS", "asset_value": "https://t/s", "status": "running"},
    ]
    groups = cu.coverage_groups(CATALOG, rows, {"sql_injection"})
    inpv = next(g for g in groups if g["wstg"] == "WSTG-INPV")
    by_id = {i["id"]: i for i in inpv["items"]}
    assert by_id["EXP-SQLI"]["status"] == "done" and by_id["EXP-SQLI"]["hit"] is True
    assert by_id["EXP-XSS"]["status"] == "running" and by_id["EXP-XSS"]["hit"] is False
