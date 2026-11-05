#!/usr/bin/env bash
# WSL side of `run_integration.cjs --cowrie`: drives the local Cowrie lab install for one integration run.
# Cowrie listens on 127.0.0.1 only for the run; `restore` puts the original cowrie.cfg back and leaves Cowrie in
# the state it was found in (running or stopped). Secrets come from the environment and are never printed.
#
#   cowrie_lab.sh backup <tag>     copy etc/cowrie.cfg to etc/cowrie.cfg.integ-<tag>; record whether Cowrie ran
#   cowrie_lab.sh start            (re)start Cowrie bound to 127.0.0.1:2222 (HONEYPOT_API_KEY, SENTINEL_API_URL)
#   cowrie_lab.sh restart          restart keeping the current cowrie.cfg (the rotator's --restart-cmd)
#   cowrie_lab.sh attack <out>     one SSH session from 127.0.0.1; its Cowrie events are written to <out>
#   cowrie_lab.sh persona          persona named in the cowrie.cfg header
#   cowrie_lab.sh restore <tag>    stop, restore the backup, restart only if Cowrie was running before
set -euo pipefail

COWRIE_HOME="${COWRIE_HOME:-$HOME/sentinelai-cowrie-test/cowrie}"
COWRIE_ENV="${COWRIE_ENV:-$(dirname "$COWRIE_HOME")/env}"
CFG="$COWRIE_HOME/etc/cowrie.cfg"
LOG="$COWRIE_HOME/var/log/cowrie/cowrie.json"
export PATH="$COWRIE_ENV/bin:$PATH"
cd "$COWRIE_HOME"

running() { [ -f var/run/cowrie.pid ] && kill -0 "$(cat var/run/cowrie.pid)" 2>/dev/null; }
stop_cowrie() {
  cowrie stop >/dev/null 2>&1 || true
  pkill -f "twistd.*cowrie" 2>/dev/null || true
  for _ in $(seq 1 20); do pgrep -f "twistd.*cowrie" >/dev/null || break; sleep 0.5; done
  rm -f var/run/cowrie.pid
}
start_cowrie() {
  cowrie start >/dev/null 2>&1
  for _ in $(seq 1 40); do (exec 3<>/dev/tcp/127.0.0.1/2222) 2>/dev/null && return 0; sleep 0.5; done
  echo "Cowrie did not open 127.0.0.1:2222" >&2
  return 1
}

case "${1:-}" in
  backup)
    cp -p "$CFG" "$CFG.integ-$2"
    if running; then echo running > "$CFG.integ-$2.state"; else echo stopped > "$CFG.integ-$2.state"; fi
    sha256sum "$CFG" | cut -c1-16
    ;;
  start)
    sed -i "s#^listen_endpoints .*#listen_endpoints     = tcp:2222:interface=127.0.0.1#" "$CFG"
    stop_cowrie
    start_cowrie
    ;;
  restart)
    tr -d '\015' < "$CFG" | grep -qE '^listen_endpoints .*interface=127\.0\.0\.1$' || { echo "refusing: cowrie.cfg not bound to 127.0.0.1" >&2; exit 3; }
    stop_cowrie
    start_cowrie
    ;;
  attack)
    before=$(cat "$LOG" 2>/dev/null | wc -l)
    sshpass -p 123456 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      -o ConnectTimeout=10 -p 2222 root@127.0.0.1 'uname -a; hostname; cat /etc/os-release; cat /etc/passwd' || true
    sleep 2
    tail -n +"$((before + 1))" "$LOG" > "$2"
    ;;
  persona)
    head -1 "$CFG" | tr -d '\015' | sed -n 's/.*switch_profile.py (\(.*\)).*/\1/p'
    ;;
  restore)
    stop_cowrie
    cp -p "$CFG.integ-$2" "$CFG"
    [ "$(cat "$CFG.integ-$2.state" 2>/dev/null)" = running ] && start_cowrie || true
    rm -f "$CFG.integ-$2" "$CFG.integ-$2.state"
    sha256sum "$CFG" | cut -c1-16
    ;;
  *)
    echo "usage: $0 backup|start|restart|attack|persona|restore" >&2; exit 2
    ;;
esac
