#!/usr/bin/env bash
# Pin egress to the engagement scope, then give up the privilege to change it.
#
# Order matters and is the whole point. We are root here, long enough to write
# firewall rules, and then we are not. The PoC runs as `poc`, which has no
# CAP_NET_ADMIN, so code that turns out to be hostile cannot widen the rules
# that contain it. A runner that kept root would be a runner with no egress
# policy at all.
#
# SANDBOX_ALLOWED_HOSTS is a comma-separated list of hostnames/IPs (the
# engagement scope). Empty means DENY ALL outbound, which is the right default:
# a misconfigured sandbox that silently allows the whole internet is worse than
# one that fails visibly.
set -euo pipefail

ALLOWED="${SANDBOX_ALLOWED_HOSTS:-}"

if ! command -v iptables >/dev/null 2>&1; then
  echo "[sandbox] iptables missing: cannot enforce egress, refusing to start" >&2
  exit 1
fi

echo "[sandbox] applying egress policy"

# Loopback and established replies always allowed; DNS to the docker resolver
# only, so a PoC cannot use an arbitrary resolver as a covert channel.
iptables -F OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.11 -j ACCEPT

# The backend reaches us; we never need to reach it. No rule for it on purpose.
if [ -n "$ALLOWED" ]; then
  IFS=',' read -ra HOSTS <<< "$ALLOWED"
  for h in "${HOSTS[@]}"; do
    h="$(echo "$h" | xargs)"
    [ -z "$h" ] && continue
    # Resolve now, while we still can, and pin the addresses. Resolving later
    # would let a rebinding trick point the allowlisted name somewhere else.
    for ip in $(getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | sort -u); do
      iptables -A OUTPUT -d "$ip" -j ACCEPT
      echo "[sandbox]   allow $h -> $ip"
    done
  done
else
  echo "[sandbox]   no SANDBOX_ALLOWED_HOSTS: outbound denied"
fi

iptables -A OUTPUT -j REJECT --reject-with icmp-port-unreachable

# Marker the /health endpoint reports, so the backend can refuse to send work
# to a runner whose egress was never locked.
mkdir -p /run && touch /run/egress.locked

echo "[sandbox] dropping privileges to 'poc'"
exec gosu poc "$@"
