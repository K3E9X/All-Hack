"""Route scan traffic through a VPN or proxy, and refuse to scan when the exit
IP is still your own.

Three mechanisms, all optional:

  SOCKS5 / HTTP proxy   No privileges. Exported to the tool subprocesses as
                        HTTP_PROXY/HTTPS_PROXY plus per-tool flags, and works
                        with Tor out of the box (socks5://127.0.0.1:9050).

  WireGuard             `wg-quick up <config>`. The backend container already
                        has cap_add: NET_ADMIN, so this works in compose; the
                        worker and orchestrator containers do not, which is
                        why the tunnel is brought up host- or backend-side and
                        the kill switch is what protects the workers.

  OpenVPN               `openvpn --config <file> --daemon`. Same caveat.

The part that actually matters is the kill switch. verify_exit_ip() compares
the current public IP against the one recorded before the tunnel came up. If
they match, traffic is not going through the tunnel and submit() refuses to
queue the job. A tunnel that drops silently mid-engagement is the failure mode
this exists to catch.

On "free VPN": most free providers log, share exit IPs between users, and get
their ranges blocklisted. That last one is not just a privacy problem - the
target blocks the range before your payload lands and you record a false
negative. Bring a WireGuard config you trust; any provider's works, including
ProtonVPN's free tier.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings

logger = logging.getLogger("allhack.network.privacy")

# Several services, because any single one can be down or blocked from the
# exit node. First usable answer wins.
IP_CHECK_URLS = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/all.json",
    "https://icanhazip.com",
]

MODE_OFF = "off"
MODE_PROXY = "proxy"
MODE_WIREGUARD = "wireguard"
MODE_OPENVPN = "openvpn"

_VALID_PROXY_SCHEMES = ("socks5://", "socks5h://", "socks4://", "http://", "https://")


@dataclass
class NetworkState:
    mode: str = MODE_OFF
    connected: bool = False
    baseline_ip: Optional[str] = None   # real IP, recorded before any tunnel
    current_ip: Optional[str] = None
    proxy_url: Optional[str] = None
    config_path: Optional[str] = None
    last_error: Optional[str] = None
    checked_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "connected": self.connected,
            "baseline_ip": self.baseline_ip,
            "current_ip": self.current_ip,
            "ip_changed": bool(
                self.baseline_ip and self.current_ip and self.baseline_ip != self.current_ip
            ),
            "proxy_url": self.redacted_proxy(),
            "config_path": self.config_path,
            "last_error": self.last_error,
            "checked_at": self.checked_at,
        }

    def redacted_proxy(self) -> Optional[str]:
        """Never echo proxy credentials back to the API"""
        if not self.proxy_url:
            return None
        if "@" in self.proxy_url:
            scheme, _, rest = self.proxy_url.partition("://")
            _, _, host = rest.rpartition("@")
            return f"{scheme}://***@{host}"
        return self.proxy_url


class NetworkPrivacyManager:
    def __init__(self) -> None:
        self.state = NetworkState()
        if settings.scan_proxy:
            # Configured in .env: adopt it without waiting for an API call.
            self.state.mode = MODE_PROXY
            self.state.proxy_url = settings.scan_proxy

    # ---- Public IP ----

    async def get_public_ip(self, through_proxy: bool = True) -> Optional[str]:
        proxy = self.state.proxy_url if (through_proxy and self.state.mode == MODE_PROXY) else None
        try:
            async with httpx.AsyncClient(timeout=15.0, proxy=proxy) as client:
                for url in IP_CHECK_URLS:
                    try:
                        resp = await client.get(url)
                        if resp.status_code != 200:
                            continue
                        text = resp.text.strip()
                        if text.startswith("{"):
                            data = json.loads(text)
                            ip = data.get("ip") or data.get("ip_addr")
                            if ip:
                                return str(ip).strip()
                        elif text:
                            return text
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("ip check via %s failed: %s", url, exc)
                        continue
        except Exception as exc:  # noqa: BLE001 - bad proxy URL, unreachable, ...
            logger.warning("ip check client failed: %s", exc)
        return None

    async def record_baseline(self) -> Optional[str]:
        """Record the real IP, bypassing any proxy, to compare against later"""
        ip = await self.get_public_ip(through_proxy=False)
        self.state.baseline_ip = ip
        logger.info("baseline IP recorded: %s", ip)
        return ip

    async def verify_exit_ip(self) -> Dict[str, Any]:
        """Kill switch check: is traffic really leaving through the tunnel?"""
        current = await self.get_public_ip()
        self.state.current_ip = current
        self.state.checked_at = time.time()

        if self.state.mode == MODE_OFF:
            return {
                "safe": True,
                "reason": "no VPN requested, scanning from the local IP",
                "current_ip": current,
            }

        if not current:
            self.state.last_error = "could not determine the public IP"
            return {
                "safe": False,
                "reason": "public IP unreadable, cannot confirm the tunnel is up",
                "current_ip": None,
            }

        if self.state.baseline_ip and current == self.state.baseline_ip:
            self.state.last_error = "exit IP equals the pre-VPN IP"
            return {
                "safe": False,
                "reason": f"traffic is NOT going through the tunnel (still {current})",
                "current_ip": current,
                "baseline_ip": self.state.baseline_ip,
            }

        self.state.last_error = None
        return {
            "safe": True,
            "reason": f"traffic exits via {current}",
            "current_ip": current,
            "baseline_ip": self.state.baseline_ip,
        }

    # ---- Proxy ----

    async def set_proxy(self, proxy_url: str) -> Dict[str, Any]:
        proxy_url = (proxy_url or "").strip()
        if not proxy_url:
            return {"ok": False, "error": "empty proxy URL"}
        if not proxy_url.startswith(_VALID_PROXY_SCHEMES):
            return {
                "ok": False,
                "error": f"proxy must start with one of {', '.join(_VALID_PROXY_SCHEMES)}",
            }

        if not self.state.baseline_ip:
            await self.record_baseline()

        previous_mode, previous_proxy = self.state.mode, self.state.proxy_url
        self.state.mode = MODE_PROXY
        self.state.proxy_url = proxy_url

        check = await self.verify_exit_ip()
        self.state.connected = check["safe"]
        if not check["safe"]:
            self.state.mode, self.state.proxy_url = previous_mode, previous_proxy
            return {"ok": False, "error": check["reason"], **self.state.to_dict()}

        return {"ok": True, **self.state.to_dict()}

    # ---- VPN ----

    async def connect_vpn(self, config_path: str, mode: str = MODE_WIREGUARD) -> Dict[str, Any]:
        if not os.path.isfile(config_path):
            return {"ok": False, "error": f"config not found: {config_path}"}

        binary = "wg-quick" if mode == MODE_WIREGUARD else "openvpn"
        if not shutil.which(binary):
            return {
                "ok": False,
                "error": f"{binary} is not installed in this container. "
                         f"Use proxy mode, which needs no privileges, or bring the "
                         f"tunnel up on the host.",
            }

        if not self.state.baseline_ip:
            await self.record_baseline()

        cmd: List[str] = (
            ["wg-quick", "up", config_path] if mode == MODE_WIREGUARD
            else ["openvpn", "--config", config_path, "--daemon"]
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=45)
            if proc.returncode != 0:
                err = (stderr or b"").decode(errors="replace")[:300]
                self.state.last_error = err
                return {"ok": False, "error": f"{binary} failed: {err}"}
        except asyncio.TimeoutError:
            return {"ok": False, "error": f"{binary} timed out after 45s"}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

        self.state.mode = mode
        self.state.config_path = config_path

        # Let the tunnel settle before reading the exit IP
        await asyncio.sleep(3)
        check = await self.verify_exit_ip()
        self.state.connected = check["safe"]
        if not check["safe"]:
            return {"ok": False, "error": check["reason"], **self.state.to_dict()}

        return {"ok": True, **self.state.to_dict()}

    async def disconnect(self) -> Dict[str, Any]:
        if self.state.mode == MODE_WIREGUARD and self.state.config_path:
            await self._run_quiet(["wg-quick", "down", self.state.config_path], 30)
        elif self.state.mode == MODE_OPENVPN:
            await self._run_quiet(["pkill", "-f", "openvpn --config"], 15)

        baseline = self.state.baseline_ip
        self.state = NetworkState(baseline_ip=baseline)
        self.state.current_ip = await self.get_public_ip(through_proxy=False)
        return {"ok": True, **self.state.to_dict()}

    @staticmethod
    async def _run_quiet(cmd: List[str], timeout: int) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            logger.warning("%s failed: %s", cmd[0], exc)

    # ---- Used by the scan path ----

    def proxy_for_tools(self) -> Optional[str]:
        """Proxy URL to hand to tool subprocesses, or None"""
        if self.state.mode == MODE_PROXY and self.state.proxy_url:
            return self.state.proxy_url
        return None

    async def guard_scan(self) -> Dict[str, Any]:
        """
        Called before any job is queued.

        With require_vpn on, a scan is refused unless the exit IP is confirmed
        different from the baseline. This is what stops a dropped tunnel from
        silently leaking the real IP in the middle of an engagement.
        """
        if not settings.require_vpn:
            return {"allowed": True, "reason": "require_vpn is off"}

        if self.state.mode == MODE_OFF:
            return {
                "allowed": False,
                "reason": "REQUIRE_VPN is on but no VPN or proxy is configured",
            }

        check = await self.verify_exit_ip()
        return {
            "allowed": check["safe"],
            "reason": check["reason"],
            "current_ip": check.get("current_ip"),
        }


_manager: Optional[NetworkPrivacyManager] = None


def get_network_manager() -> NetworkPrivacyManager:
    global _manager
    if _manager is None:
        _manager = NetworkPrivacyManager()
    return _manager
