"""nmap parser: open ports + NSE script (vuln) findings with CVE extraction."""
from app.scans.wrappers.nmap import NmapWrapper

_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
        <script id="vulners" output="cpe:/a:nginx:nginx:1.18.0:&#10;  CVE-2021-23017  9.8  https://vulners.com/cve/CVE-2021-23017"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
        <script id="ssh-hostkey" output="2048 aa:bb ..."/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-vuln-ms17-010" output="VULNERABLE: Remote Code Execution (CVE-2017-0143)"/>
    </hostscript>
  </host>
</nmaprun>"""


def _findings():
    return NmapWrapper().parse(_XML.encode(), b"", 0, "10.0.0.5").findings


def test_open_ports_surfaced():
    f = _findings()
    titles = [x.title for x in f]
    assert any("Open port 443/tcp" in t for t in titles)
    assert any("Open port 22/tcp" in t for t in titles)


def test_nse_vuln_script_becomes_cve_finding():
    f = _findings()
    vulners = [x for x in f if x.metadata.get("cve_id") == "CVE-2021-23017"]
    assert vulners, "vulners NSE CVE not surfaced"
    v = vulners[0]
    assert v.metadata["vuln_class"] == "cve"
    assert v.severity == "critical"  # CVSS 9.8


def test_hostscript_vuln_surfaced():
    f = _findings()
    ms17 = [x for x in f if x.metadata.get("cve_id") == "CVE-2017-0143"]
    assert ms17 and ms17[0].metadata["nse_script"] == "smb-vuln-ms17-010"


def test_benign_script_not_a_finding():
    f = _findings()
    # ssh-hostkey is not a vuln script -> no finding for it
    assert not any(x.metadata.get("nse_script") == "ssh-hostkey" for x in f)
