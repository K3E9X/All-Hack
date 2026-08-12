"""Preparing a provider's WireGuard config for use inside a container.

Both rules here exist because the stock config fails in a way that points at
the wrong culprit: one looks like a database outage, the other like a malformed
config file.
"""
from __future__ import annotations

import pathlib

import pytest

from app.network.privacy import prepare_wg_config

# A real ProtonVPN export, shortened. The DNS line and the filename are the two
# things that matter.
PROTON = """[Interface]
# Key for pentest-laptop
# NetShield = 0
# Moderate NAT = off
PrivateKey = ABCDEFprivatekeyabcdefghijklmnopqrstuvwxyz=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
# CH-FR#1
PublicKey = ZZZZpublickeyabcdefghijklmnopqrstuvwxyz123=
AllowedIPs = 0.0.0.0/0
Endpoint = 185.159.157.1:51820
"""


@pytest.fixture
def proton_conf(tmp_path):
    # The long dotted name ProtonVPN actually ships.
    p = tmp_path / "ch-fr-01.protonvpn.udp.conf"
    p.write_text(PROTON)
    return p


def test_dns_line_is_removed(proton_conf, tmp_path):
    """wg-quick would apply DNS = 10.2.0.1, replacing Docker's resolver at
    127.0.0.11. The backend would then fail to resolve `postgres` and the app
    would fall over looking like a database outage."""
    out = pathlib.Path(prepare_wg_config(str(proton_conf), dest_dir=str(tmp_path / "out")))
    body = out.read_text()
    assert "10.2.0.1" not in body
    assert not any(line.strip().lower().startswith("dns")
                   for line in body.splitlines() if not line.startswith("#"))


def test_everything_that_makes_the_tunnel_work_is_kept(proton_conf, tmp_path):
    out = pathlib.Path(prepare_wg_config(str(proton_conf), dest_dir=str(tmp_path / "out")))
    body = out.read_text()
    for essential in ("[Interface]", "[Peer]", "PrivateKey", "PublicKey",
                      "Address = 10.2.0.2/32", "AllowedIPs = 0.0.0.0/0",
                      "Endpoint = 185.159.157.1:51820"):
        assert essential in body, f"{essential} was lost"


def test_interface_name_becomes_valid(proton_conf, tmp_path):
    """The filename is the interface name. `ch-fr-01.protonvpn.udp` is over 15
    chars and contains dots, so the kernel rejects it and wg-quick reports
    "invalid interface name" - which reads like a broken config."""
    out = pathlib.Path(prepare_wg_config(str(proton_conf), dest_dir=str(tmp_path / "out")))
    iface = out.stem
    assert iface == "wg0"
    assert len(iface) <= 15
    assert "." not in iface


def test_the_original_is_never_modified(proton_conf, tmp_path):
    before = proton_conf.read_text()
    prepare_wg_config(str(proton_conf), dest_dir=str(tmp_path / "out"))
    assert proton_conf.read_text() == before
    assert "DNS = 10.2.0.1" in proton_conf.read_text()


def test_prepared_config_is_not_world_readable(proton_conf, tmp_path):
    """It carries a private key."""
    out = pathlib.Path(prepare_wg_config(str(proton_conf), dest_dir=str(tmp_path / "out")))
    assert oct(out.stat().st_mode)[-3:] == "600"


def test_a_config_without_dns_survives_unchanged(tmp_path):
    src = tmp_path / "wg-self-hosted.conf"
    src.write_text("[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n\n"
                   "[Peer]\nPublicKey = y\nEndpoint = 1.2.3.4:51820\n"
                   "AllowedIPs = 0.0.0.0/0\n")
    out = pathlib.Path(prepare_wg_config(str(src), dest_dir=str(tmp_path / "out")))
    assert "PrivateKey = x" in out.read_text()
    assert "Endpoint = 1.2.3.4:51820" in out.read_text()


@pytest.mark.parametrize("dns_line", [
    "DNS = 10.2.0.1", "dns = 10.2.0.1", "  DNS   =  10.2.0.1, 10.2.0.2",
])
def test_dns_matching_is_tolerant_of_formatting(tmp_path, dns_line):
    src = tmp_path / "c.conf"
    src.write_text(f"[Interface]\nPrivateKey = x\n{dns_line}\nAddress = 10.0.0.2/32\n")
    out = pathlib.Path(prepare_wg_config(str(src), dest_dir=str(tmp_path / "out")))
    assert "10.2.0.1" not in out.read_text()


def test_an_address_line_is_not_mistaken_for_dns(tmp_path):
    """Only the DNS key is dropped - nothing that merely mentions it."""
    src = tmp_path / "c.conf"
    src.write_text("[Interface]\nAddress = 10.2.0.2/32\n# DNS handled by docker\n")
    out = pathlib.Path(prepare_wg_config(str(src), dest_dir=str(tmp_path / "out")))
    assert "Address = 10.2.0.2/32" in out.read_text()
