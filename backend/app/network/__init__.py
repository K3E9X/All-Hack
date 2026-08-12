"""Network privacy: VPN/proxy control and the exit-IP kill switch."""
from app.network.privacy import (  # noqa: F401
    MODE_OFF,
    MODE_OPENVPN,
    MODE_PROXY,
    MODE_WIREGUARD,
    NetworkPrivacyManager,
    get_network_manager,
)
