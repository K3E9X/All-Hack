"""Deterministic kill-chain rules link the right finding classes."""
from app.validation.chaining import _deterministic_chains
from app.validation.models import ValidatedFinding


def vf(vuln_class, title="t", target="https://t/x", severity="high", fid=None):
    return ValidatedFinding(
        id=fid or f"vf_{vuln_class}", engagement_id="e", source_job_id="j",
        tool="x", vuln_class=vuln_class, severity=severity, title=title,
        target=target, status="confirmed", confidence=0.9, method="m",
        poc="", evidence="", created_at=0.0,
    )


def _titles(chains):
    return [c["title"] for c in chains]


def test_secret_plus_rce_chains_to_server_compromise():
    chains = _deterministic_chains([vf("secret_exposure"), vf("command_injection")])
    assert "Leaked secret to server compromise" in _titles(chains)


def test_secret_alone_chains_to_account_takeover():
    chains = _deterministic_chains([vf("secret_exposure")])
    assert "Leaked secret to account/infrastructure takeover" in _titles(chains)


def test_access_control_chains_to_data_exposure():
    chains = _deterministic_chains([vf("idor")])
    assert "Broken access control to bulk data exposure" in _titles(chains)


def test_jwt_with_privesc_is_critical_ato():
    chains = _deterministic_chains([vf("jwt"), vf("privilege_escalation")])
    ato = [c for c in chains if c["title"] == "Weak JWT to account takeover"]
    assert ato and ato[0]["severity"] == "critical"


def test_rce_plus_privesc_chains_to_root():
    chains = _deterministic_chains([vf("command_injection"), vf("privilege_escalation")])
    assert "RCE to root via local privilege escalation" in _titles(chains)


def test_ssrf_chains_to_cloud_creds():
    chains = _deterministic_chains([vf("ssrf")])
    assert "SSRF to cloud credential theft" in _titles(chains)


def test_subdomain_takeover_chain():
    chains = _deterministic_chains([vf("subdomain_takeover")])
    assert "Subdomain takeover to session/credential theft" in _titles(chains)


def test_graphql_needs_access_control_to_chain():
    only_gql = _deterministic_chains([vf("graphql", title="GraphQL introspection enabled")])
    assert "GraphQL introspection to authorization abuse" not in _titles(only_gql)
    both = _deterministic_chains([
        vf("graphql", title="GraphQL introspection enabled"),
        vf("privilege_escalation"),
    ])
    assert "GraphQL introspection to authorization abuse" in _titles(both)


def test_cve_file_read_chains_to_credential_compromise():
    chains = _deterministic_chains([vf("cve", title="CVE-2021-43798: Grafana file read")])
    assert "Known CVE (file read) to credential compromise" in _titles(chains)


def test_cve_plus_rce_chains_to_host_compromise():
    chains = _deterministic_chains([vf("cve"), vf("command_injection")])
    titles = _titles(chains)
    assert "Known CVE to host compromise" in titles
    assert "Known CVE (file read) to credential compromise" not in titles


def test_default_creds_chain_and_escalation():
    base = _deterministic_chains([vf("auth", title="Default creds admin:admin")])
    dc = [c for c in base if c["title"] == "Default credentials to account takeover"]
    assert dc and dc[0]["severity"] == "high"
    with_priv = _deterministic_chains([vf("auth"), vf("broken_access_control")])
    dc2 = [c for c in with_priv if c["title"] == "Default credentials to account takeover"]
    assert dc2 and dc2[0]["severity"] == "critical"


def test_full_compromise_root_with_data_access():
    none = _deterministic_chains([vf("command_injection"), vf("privilege_escalation")])
    assert "Full compromise: RCE to root with data access" not in _titles(none)
    full = _deterministic_chains([
        vf("command_injection"), vf("privilege_escalation"), vf("secret_exposure"),
    ])
    fc = [c for c in full if c["title"] == "Full compromise: RCE to root with data access"]
    assert fc and fc[0]["severity"] == "critical"


def test_no_findings_no_chains():
    assert _deterministic_chains([]) == []
