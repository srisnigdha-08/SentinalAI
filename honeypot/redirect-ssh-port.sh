#!/bin/sh
# Sends inbound TCP 22 to Cowrie on 2222 (L7): internet SSH scanners target port 22, and Cowrie runs as a
# non-root user, so it cannot bind 22 itself. Move the host's real sshd to another port FIRST (and allow it in
# your firewall), or you will lock yourself out of the honeypot host.
#
# Not needed with docker-compose.honeypot.yml: publish COWRIE_BIND=0.0.0.0 COWRIE_PORT=22 there instead.
# UNTESTED (written without a Linux host with root). Rules are not persistent; save them with your
# distribution's firewall tooling.
#
#   sudo IFACE=eth0 ./redirect-ssh-port.sh            # apply
#   sudo IFACE=eth0 ./redirect-ssh-port.sh --remove   # undo
set -eu
IFACE=${IFACE:?set IFACE to the internet-facing interface, e.g. eth0}
COWRIE_PORT=${COWRIE_PORT:-2222}
RULE="PREROUTING -i $IFACE -p tcp --dport 22 -j REDIRECT --to-port $COWRIE_PORT"

if [ "${1:-}" = "--remove" ]; then
  while iptables -t nat -D $RULE 2>/dev/null; do :; done
  echo "Removed 22 -> $COWRIE_PORT redirect on $IFACE"
  exit 0
fi

if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE '(^|:)22$'; then
  echo "Something still listens on port 22 (the real sshd?). Move it to another port first." >&2
  exit 1
fi
iptables -t nat -C $RULE 2>/dev/null || iptables -t nat -A $RULE
echo "Inbound $IFACE:22 now goes to Cowrie on $COWRIE_PORT"
