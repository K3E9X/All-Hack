"""The category taxonomy must stay internally consistent: every vuln_class the
analyzers emit maps to a known category, and the report fields are present."""
from app.reporting import mappings as m


def test_every_mapping_has_required_fields():
    for vclass, entry in m.MAPPING.items():
        assert entry.get("category") in m.CATEGORY_ORDER, f"{vclass} has unknown category"
        for key in ("wstg", "attack", "cwe", "remediation"):
            assert entry.get(key), f"{vclass} missing {key}"
        assert isinstance(entry["attack"], list) and entry["attack"]


def test_every_category_has_a_label():
    for key in m.CATEGORY_ORDER:
        assert key in m.CATEGORY_LABELS


def test_fallback_is_safe():
    unknown = m.for_class("does-not-exist")
    assert unknown["category"] == "other"
    assert m.category_for_class("does-not-exist") == "other"


def test_classes_emitted_by_analyzers_are_mapped():
    # Classes produced across the analyzers / wrappers must each resolve to a
    # real (non-fallback) mapping, or they'd land in "Other" in the UI/report.
    emitted = [
        "sql_injection", "command_injection", "xss", "ssrf", "ssti", "lfi",
        "xxe", "open_redirect", "cors", "idor", "csrf", "privilege_escalation",
        "broken_access_control", "access_control_review", "mass_assignment",
        "secret_exposure", "endpoint_discovery", "jwt", "auth",
        "exposed_resource", "weak_tls", "cms_vulnerability", "misconfiguration",
    ]
    for vclass in emitted:
        assert vclass in m.MAPPING, f"{vclass} is not mapped"
        assert m.category_for_class(vclass) != "other" or vclass == "other"
