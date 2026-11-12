#!/usr/bin/env bash
# Switches the WSL Cowrie install between its safe local-only binding and the demo binding.
#
#   bash scripts/demo/cowrie-demo-mode.sh on      # listen on the WSL IP (reachable from this Windows host only)
#   bash scripts/demo/cowrie-demo-mode.sh off     # restore listen on 127.0.0.1 (the safe default)
#   bash scripts/demo/cowrie-demo-mode.sh status
#   bash scripts/demo/cowrie-demo-mode.sh restart   # restart Cowrie, keeping the current binding
#   bash scripts/demo/cowrie-demo-mode.sh rotate --once [--force]
#        apply the Q-learner's recommended persona now (honeypot/deception_rotator.py): rewrites cowrie.cfg
#        (same binding, per-persona filesystem), restarts Cowrie and records the persona. Without --once it
#        repeats every --interval minutes (default 60); that loop is what scripts/rotator/sentinel-rotator.service
#        supervises (refused on a wildcard binding). It waits while attacker sessions are open unless --force.
#
# Why "on" is needed for the containment demo: on 127.0.0.1 every attacker appears as 127.0.0.1, and
# containmentPolicyService refuses to block loopback addresses, so the auto-block can never fire. On the WSL
# address, connections from Windows arrive from the Windows host's WSL-side IP (e.g. 172.29.32.1), which can be
# deny-listed. WSL's NAT network is not reachable from your LAN, so this does not expose Cowrie to other machines.
#
# Both modes start Cowrie as a daemon with HONEYPOT_API_KEY (read from backend/.env, never printed) and
# SENTINEL_API_URL pointing at the backend on the Windows host, so the blocker plugin can sync the deny-list.
set -euo pipefail

COWRIE_HOME="${COWRIE_HOME:-$HOME/sentinelai-cowrie-test/cowrie}"
COWRIE_ENV="${COWRIE_ENV:-$(dirname "$COWRIE_HOME")/env}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="$REPO_ROOT/backend/.env"
CFG="$COWRIE_HOME/etc/cowrie.cfg"
WIN_IP="$(ip route show default | awk '{print $3; exit}')"
WSL_IP="$(hostname -I | awk '{print $1}')"
BACKEND_PORT="${BACKEND_PORT:-5000}"

[ -f "$CFG" ] || { echo "cowrie.cfg not found at $CFG (set COWRIE_HOME)"; exit 1; }
[ -f "$ENV_FILE" ] || { echo "backend/.env not found at $ENV_FILE"; exit 1; }
export PATH="$COWRIE_ENV/bin:$PATH"
export HONEYPOT_API_KEY="${HONEYPOT_API_KEY:-$(grep -E '^HONEYPOT_API_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '\r')}"
export SENTINEL_API_URL="http://$WIN_IP:$BACKEND_PORT/api"
# Backend the rotator talks to (ROTATOR_BACKEND overrides it, e.g. a mock backend in an isolated test)
ROTATOR_BACKEND="${ROTATOR_BACKEND:-http://$WIN_IP:$BACKEND_PORT}"

set_listen() {
  sed -i "s#^listen_endpoints .*#listen_endpoints     = tcp:2222:interface=$1#" "$CFG"
}

restart_cowrie() {
  cd "$COWRIE_HOME"
  cowrie stop >/dev/null 2>&1 || true
  pkill -f "twistd.*cowrie" 2>/dev/null || true
  sleep 2
  rm -f var/run/cowrie.pid
  cowrie start >/dev/null 2>&1
  sleep 5
}

status() {
  cd "$COWRIE_HOME"
  echo "listen      : $(grep '^listen_endpoints' "$CFG" | sed 's/.*= *//')"
  echo "cowrie      : $(cowrie status 2>&1 | tail -1)"
  if [ -f var/run/cowrie.pid ] && [ -d "/proc/$(cat var/run/cowrie.pid)" ]; then
    echo "threads     : $(ls "/proc/$(cat var/run/cowrie.pid)/task" | wc -l)  (2 = blocker sync thread alive)"
  fi
  echo "backend     : $SENTINEL_API_URL"
  code="$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H "X-API-Key: $HONEYPOT_API_KEY" "$SENTINEL_API_URL/honeypot/ingest/check-block" || true)"
  echo "check-block : HTTP $code  (200 = the blocker can read the deny-list)"
  echo "attack from Windows with:  ssh -p 2222 root@$(grep '^listen_endpoints' "$CFG" | sed 's/.*interface=//')"
}

case "${1:-status}" in
  on)
    set_listen "$WSL_IP"
    restart_cowrie
    echo "Demo mode ON: Cowrie listens on $WSL_IP:2222"
    status
    ;;
  off)
    set_listen "127.0.0.1"
    restart_cowrie
    echo "Demo mode OFF: Cowrie listens on 127.0.0.1:2222 only"
    status
    ;;
  status)
    status
    ;;
  restart)
    restart_cowrie
    status
    ;;
  rotate)
    shift
    # switch_profile regenerates the whole cowrie.cfg: carry over the current binding and persona filesystems,
    # otherwise a rotation would silently move Cowrie to its 0.0.0.0 default.
    LISTEN="$(grep '^listen_endpoints' "$CFG" | sed 's/.*interface=//' | tr -d '\r')"
    ROTATOR=("$COWRIE_ENV/bin/python" "$REPO_ROOT/honeypot/deception_rotator.py"
             --backend "$ROTATOR_BACKEND" --cfg "$CFG"
             --restart-cmd "bash $REPO_ROOT/scripts/demo/cowrie-demo-mode.sh restart" "$@")
    export COWRIE_LISTEN_ADDR="$LISTEN" COWRIE_PERSONA_FS=personas
    if [[ " $* " == *" --once "* ]]; then
      "${ROTATOR[@]}"
      echo "persona now: $(head -1 "$CFG" | sed -n 's/.*switch_profile.py (\(.*\)).*/\1/p')"
      status
    else
      # Loop mode (scripts/rotator/sentinel-rotator.service): never on a wildcard binding, which could expose
      # Cowrie beyond this host; exec so the supervisor's SIGTERM reaches the rotator (it finishes a switch first).
      case "$LISTEN" in
        ""|0.0.0.0|::|"[::]") echo "refusing the rotation loop: Cowrie listens on '${LISTEN:-?}' (use 'on' or 'off')" >&2; exit 3 ;;
      esac
      exec "${ROTATOR[@]}"
    fi
    ;;
  *)
    echo "usage: $0 on|off|status|restart|rotate [--once] [--force]"; exit 2
    ;;
esac
