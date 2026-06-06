"""Proof-of-impact pure logic: target gathering, option building, output
parsing. (The actual tool execution is integration, not unit-tested.)"""
from types import SimpleNamespace

from app.exploit.proof import (
    _NIX_PROOF,
    _data_proof_options,
    _extract_dump,
    _extract_proof,
    _injection_targets,
    _proof_options,
)


def _job(tool, target, finding_targets):
    findings = [SimpleNamespace(target=t) for t in finding_targets]
    return SimpleNamespace(tool=tool, target=target, findings=findings)


def test_injection_targets_only_commix_sqlmap_and_deduped():
    jobs = [
        _job("commix", "http://t/a?x=1", ["http://t/a?x=1"]),
        _job("sqlmap", "http://t/b?id=1", ["http://t/b?id=1"]),
        _job("nuclei", "http://t/c", ["http://t/c"]),            # ignored
        _job("commix", "http://t/a?x=1", ["http://t/a?x=1"]),    # dup
    ]
    targets = _injection_targets(jobs)
    assert ("commix", "http://t/a?x=1") in targets
    assert ("sqlmap", "http://t/b?id=1") in targets
    assert all(t[0] != "nuclei" for t in targets)
    assert len(targets) == 2


def test_proof_options_commix_is_benign_os_cmd():
    opts = _proof_options("commix", allow_sql_os_cmd=False)
    assert "--os-cmd" in opts
    # the command chain is the read-only allow-list, no destructive verbs
    cmd = opts[opts.index("--os-cmd") + 1]
    assert cmd == _NIX_PROOF
    # no destructive or exfiltration verbs (2>/dev/null redirects are benign)
    for bad in ("rm ", "mkfs", "dd if=", "curl", "wget", "chmod ", "chown ",
                "> /", ">>"):
        assert bad not in cmd


def test_proof_options_sqlmap_readonly_by_default():
    opts = _proof_options("sqlmap", allow_sql_os_cmd=False)
    assert "--os-cmd" not in opts
    assert "--current-user" in opts and "--is-dba" in opts


def test_proof_options_sqlmap_os_cmd_when_allowed():
    opts = _proof_options("sqlmap", allow_sql_os_cmd=True)
    assert "--os-cmd" in opts


def test_proof_options_unknown_tool():
    assert _proof_options("dalfox", False) is None


def test_extract_proof_commix_success():
    out = "...\n[+] uid=33(www-data) gid=33(www-data) groups=33(www-data)\nweb01\n"
    ok, snippet = _extract_proof("commix", out)
    assert ok and "uid=33" in snippet


def test_extract_proof_commix_failure():
    ok, _ = _extract_proof("commix", "no command output here")
    assert not ok


def test_extract_proof_sqlmap_success():
    out = "current user: 'root@localhost'\ncurrent database: 'app'\n"
    ok, snippet = _extract_proof("sqlmap", out)
    assert ok and "current user" in snippet.lower()


def test_data_proof_options_are_bounded():
    opts = _data_proof_options()
    assert "--dump" in opts
    assert "--stop=3" in opts          # at most 3 rows
    assert "--exclude-sysdbs" in opts  # no system databases
    # no mass-dump flags
    assert "--dump-all" not in opts


def test_extract_dump_success_and_failure():
    out = "Database: app\nTable: users\n[3 entries]\n| id | email |\n"
    ok, snippet = _extract_dump(out)
    assert ok and "Table:" in snippet
    ok2, _ = _extract_dump("no rows retrieved")
    assert not ok2
