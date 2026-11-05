#!/bin/sh
# Restricts the honeypot bridge (br-honeypot, docker-compose.honeypot.yml) to one destination: the SentinelAI
# ingest port. Everything else the honeypot containers try to open (Cowrie's real wget/curl downloads, port
# forwarding, scans, escape attempts) is dropped. Replies to attackers still flow (ESTABLISHED).
#
# UNTESTED: written without a Linux/Docker host. Run as root after `docker compose up`; rules are not
# persistent (save them with iptables-save / your distribution's firewall tooling).
#
#   sudo BACKEND_IP=172.30.66.1 BACKEND_PORT=5000 ./egress-rules.sh          # apply
#   sudo ./egress-rules.sh --remove                                           # undo
set -eu
BRIDGE=br-honeypot
BACKEND_IP=${BACKEND_IP:-172.30.66.1}
BACKEND_PORT=${BACKEND_PORT:-5000}

# One rule per line: "<chain> <match and target>". Order is evaluation order.
# FORWARD path (traffic leaving the host) is filtered in DOCKER-USER, which Docker evaluates before its own
# rules; INPUT covers traffic to this host itself (e.g. a backend bound to the bridge gateway).
RULES="DOCKER-USER -i $BRIDGE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
DOCKER-USER -i $BRIDGE -d $BACKEND_IP -p tcp --dport $BACKEND_PORT -j RETURN
DOCKER-USER -i $BRIDGE -j DROP
INPUT -i $BRIDGE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
INPUT -i $BRIDGE -d $BACKEND_IP -p tcp --dport $BACKEND_PORT -j ACCEPT
INPUT -i $BRIDGE -j DROP"

remove() {
  echo "$RULES" | while read -r chain rule; do
    while iptables -D "$chain" $rule 2>/dev/null; do :; done
  done
}

if [ "${1:-}" = "--remove" ]; then
  remove
  echo "Removed honeypot egress rules"
  exit 0
fi

ip link show "$BRIDGE" >/dev/null 2>&1 || { echo "$BRIDGE not found: start docker-compose.honeypot.yml first" >&2; exit 1; }
remove   # idempotent: drop any previous copy first
# Insert at the top in reverse order, so the rules run in the order listed and before DOCKER-USER's
# trailing RETURN (appended rules would never be reached).
echo "$RULES" | tac | while read -r chain rule; do
  iptables -I "$chain" 1 $rule
done
echo "Honeypot bridge $BRIDGE may reach only $BACKEND_IP:$BACKEND_PORT"
