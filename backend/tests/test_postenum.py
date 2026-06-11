"""Post-exploitation enumeration parsing + privesc detection (read-only)."""
from app.exploit.postenum import (
    analyze_postexploit,
    enum_command,
    privilege_findings,
    split_sections,
)

SAMPLE = """===PRIV===
uid=33(www-data) gid=33(www-data) groups=33(www-data)
User www-data may run the following commands:
    (ALL) NOPASSWD: /usr/bin/find
===HOST===
Linux web01 5.15.0 #1 SMP x86_64 GNU/Linux
/docker/abc123
===NET===
LISTEN 0 128 0.0.0.0:22
LISTEN 0 128 127.0.0.1:3306
===CRON===
* * * * * root /opt/backup.sh
===SUID===
/usr/bin/find
/usr/bin/vim
/usr/bin/passwd
===USERS===
root:x:0:0:root:/root:/bin/bash
"""


def test_split_sections():
    s = split_sections(SAMPLE)
    assert set(s) >= {"PRIV", "HOST", "NET", "CRON", "SUID", "USERS"}
    assert "uid=33" in s["PRIV"]
    assert "/usr/bin/vim" in s["SUID"]


def test_privesc_detects_nopasswd_sudo():
    s = split_sections(SAMPLE)
    titles = [f["title"] for f in privilege_findings(s)]
    assert any("passwordless sudo" in t for t in titles)


def test_privesc_detects_dangerous_suid():
    s = split_sections(SAMPLE)
    findings = privilege_findings(s)
    titles = [f["title"] for f in findings]
    assert any("SUID find" in t for t in titles)
    assert any("SUID vim" in t for t in titles)
    # passwd is SUID but not a GTFOBins root vector -> not flagged
    assert not any("SUID passwd" in t for t in titles)
    assert all(f["vuln_class"] == "privilege_escalation" for f in findings)


def test_context_findings_detect_container():
    findings = analyze_postexploit(SAMPLE, allow_secrets=False)
    host = [f for f in findings if "host / container" in f["title"]]
    assert host and "container" in host[0]["description"].lower()


def test_secrets_gated_off_by_default():
    sample = SAMPLE + "===SECRETS===\nAWS_SECRET_ACCESS_KEY=abc\n"
    off = analyze_postexploit(sample, allow_secrets=False)
    assert not any("secrets reachable" in f["title"] for f in off)
    on = analyze_postexploit(sample, allow_secrets=True)
    assert any("secrets reachable" in f["title"] for f in on)


def test_enum_command_is_readonly():
    cmd = enum_command(allow_secrets=False)
    for bad in ("rm -rf", "rmdir", "mkfs", "dd if=", "chmod ", "chown ", "shutdown", "reboot"):
        assert bad not in cmd
    assert "find / -perm -4000" in cmd  # SUID enumeration is read-only


def test_empty_output():
    assert analyze_postexploit("", allow_secrets=False) == []


def test_privesc_proof_command_builds_benign_id_attempts():
    from app.exploit.postenum import privesc_proof_command, split_sections
    cmd = privesc_proof_command(split_sections(SAMPLE))
    # SAMPLE has NOPASSWD sudo + SUID find/vim -> expect sudo -n id and find -exec id
    assert "===PRIVESC===" in cmd
    assert "sudo -n id" in cmd
    assert "-exec id" in cmd
    # strictly benign: only proves with id, never writes/persists
    # (2>/dev/null stderr redirect is fine; flag real writes/persistence)
    for bad in ("rm -", "chmod ", "chown ", "> /", ">>", "wget", "curl",
                "useradd", "crontab", "ssh-keygen"):
        assert bad not in cmd


def test_privesc_proof_command_empty_when_no_vector():
    from app.exploit.postenum import privesc_proof_command
    assert privesc_proof_command({"PRIV": "uid=1000(app)", "SUID": "/usr/bin/passwd"}) == ""


def test_privesc_proven_detects_root():
    from app.exploit.postenum import privesc_proven
    assert privesc_proven("===PRIVESC===\nuid=0(root) gid=0(root) groups=0(root)")
    assert not privesc_proven("===PRIVESC===\nuid=1000(app)")
    assert not privesc_proven("uid=0(root)")  # must be after the marker
