"""Pure-logic guards for the audit-pass fixes (no DB / network)."""
from app.scans.auth import auth_args, _DASH_H
from app.scans.runner import _host_of
from app.scans.models import Finding, findings_from_json, findings_to_json
from app.exploit.auth_brute import _mask_pwd


def test_host_of_parses_urls_and_bare_hosts():
    assert _host_of("https://App.Example.com/a?b=1") == "app.example.com"
    assert _host_of("http://t:8080/x") == "t"
    assert _host_of("example.com") == "example.com"
    assert _host_of("example.com:443/path") == "example.com"


def test_sqlmap_auth_uses_cookie_not_dash_h():
    # Regression: sqlmap was in _DASH_H, so Cookie went via -H and the scan ran
    # effectively unauthenticated.
    assert "sqlmap" not in _DASH_H
    args = auth_args("sqlmap", [{"name": "Cookie", "value": "SID=abc"},
                                {"name": "X-Token", "value": "t1"}])
    assert "--cookie" in args
    assert "SID=abc" in args
    assert "-H" in args and "X-Token: t1" in args
    # The cookie must NOT be passed as a -H header.
    assert "Cookie: SID=abc" not in args


def test_mask_pwd_never_reveals_full_password():
    assert _mask_pwd("admin") == "a••••"
    assert _mask_pwd("P@ssw0rd123") == "P••••••"   # capped at 6 bullets
    assert _mask_pwd("ab") == "••"
    assert "secret" not in _mask_pwd("secret")


def test_findings_from_json_ignores_unknown_keys():
    f = Finding(severity="high", title="t", description="d", target="https://x")
    raw = findings_to_json([f])
    # Inject a legacy/extra key into the serialized form.
    import json
    items = json.loads(raw)
    items[0]["legacy_field"] = "boom"
    back = findings_from_json(json.dumps(items))
    assert len(back) == 1 and back[0].title == "t"   # no TypeError, job still loads
