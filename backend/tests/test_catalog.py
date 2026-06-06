"""The methodology catalog stays coherent and the exploitation phase is rich."""
from app.methodology.catalog import (
    CATALOG,
    CATALOG_BY_ID,
    PHASE_EXPLOIT,
    items_for_phase,
)
from app.reporting.mappings import category_for_class

_KNOWN_TOOLS = {
    "nuclei", "sqlmap", "ffuf", "dalfox", "nmap", "subfinder", "httpx",
    "katana", "gau", "dnsx", "naabu", "testssl", "wpscan", "commix",
    "wafw00f", "whatweb", "nikto",
}


def test_ids_are_unique():
    ids = [i.id for i in CATALOG]
    assert len(ids) == len(set(ids))
    assert len(CATALOG_BY_ID) == len(CATALOG)


def test_every_item_uses_a_known_tool():
    for item in CATALOG:
        assert item.tool in _KNOWN_TOOLS, f"{item.id} -> unknown tool {item.tool}"


def test_exploitation_phase_covers_injection_family():
    exp = {i.vuln_class for i in items_for_phase(PHASE_EXPLOIT)}
    for cls in ("sql_injection", "xss", "command_injection", "ssrf", "ssti",
                "lfi", "xxe", "open_redirect"):
        assert cls in exp, f"exploitation phase missing {cls}"


def test_dedicated_exploit_items_exist():
    for iid in ("EXP-SSRF", "EXP-SSTI", "EXP-LFI", "EXP-XXE", "EXP-REDIRECT",
                "EXP-CRLF"):
        assert iid in CATALOG_BY_ID


def test_every_exploit_class_is_mapped_to_a_real_category():
    for item in items_for_phase(PHASE_EXPLOIT):
        # "multiple" (the generic DAST item) is allowed; everything else must
        # resolve to a concrete, non-"other" category.
        if item.vuln_class == "multiple":
            continue
        assert category_for_class(item.vuln_class) != "other", item.id
