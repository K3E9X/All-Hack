"""VPN / proxy control and the exit-IP kill switch."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.config import settings
from app.network.privacy import (MODE_OPENVPN, MODE_WIREGUARD,
                                 get_network_manager)

router = APIRouter(prefix="/api/network", tags=["network"])


class ProxyRequest(BaseModel):
    proxy_url: str


class VpnRequest(BaseModel):
    config_path: str = ""
    mode: str = ""


@router.get("/status")
async def network_status() -> dict:
    """Current VPN/proxy state, exit IP, and the identity policy in force"""
    state = get_network_manager().state.to_dict()
    state["require_vpn"] = settings.require_vpn
    state["user_agent_mode"] = settings.user_agent_mode
    state["pentest_id"] = settings.pentest_id or None
    return state


@router.post("/check")
async def network_check() -> dict:
    """Read the public exit IP now and compare it against the baseline"""
    manager = get_network_manager()
    if not manager.state.baseline_ip:
        await manager.record_baseline()
    return await manager.verify_exit_ip()


@router.get("/guard")
async def network_guard() -> dict:
    """Whether a scan may start under the current require_vpn policy"""
    return await get_network_manager().guard_scan()


@router.post("/proxy")
async def set_proxy(req: ProxyRequest) -> dict:
    """Route scan traffic through a SOCKS5/HTTP proxy. Needs no privileges."""
    result = await get_network_manager().set_proxy(req.proxy_url)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "proxy setup failed"))
    return result


@router.post("/vpn/connect")
async def connect_vpn(req: VpnRequest) -> dict:
    """Bring up a WireGuard/OpenVPN tunnel from a config file"""
    config_path = req.config_path or settings.vpn_config_path
    mode = req.mode or settings.vpn_mode
    if not config_path:
        raise HTTPException(status_code=400, detail="no config_path given and VPN_CONFIG_PATH is unset")
    if mode not in (MODE_WIREGUARD, MODE_OPENVPN):
        raise HTTPException(status_code=400, detail="mode must be wireguard or openvpn")

    result = await get_network_manager().connect_vpn(config_path, mode)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "VPN connection failed"))
    return result


@router.post("/vpn/disconnect")
async def disconnect_vpn() -> dict:
    """Tear down the tunnel or clear the proxy"""
    return await get_network_manager().disconnect()
