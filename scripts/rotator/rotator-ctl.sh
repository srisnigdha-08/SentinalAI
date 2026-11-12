#!/usr/bin/env bash
# Control the supervised deception rotator (systemd user unit) for the WSL Cowrie lab. Run inside WSL.
#
#   bash scripts/rotator/rotator-ctl.sh install     # install the unit (NOT enabled, NOT started)
#   bash scripts/rotator/rotator-ctl.sh enable      # start it now and at every WSL start (explicit opt-in)
#   bash scripts/rotator/rotator-ctl.sh status      # unit state, last rotation, persona served, binding
#   bash scripts/rotator/rotator-ctl.sh logs        # recent rotator log lines
#   bash scripts/rotator/rotator-ctl.sh disable     # stop it (a switch in progress finishes first) and disable
#   bash scripts/rotator/rotator-ctl.sh recover     # after "needs_recovery": stop the unit, restart Cowrie, show state
#   bash scripts/rotator/rotator-ctl.sh uninstall   # disable and remove the unit file
#
# Nothing here enables the unit implicitly. See scripts/rotator/README.md.
set -euo pipefail

UNIT=sentinel-rotator.service
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
STATUS_FILE="$HOME/.local/state/sentinelai/rotator-status.json"
COWRIE_HOME="${COWRIE_HOME:-$HOME/sentinelai-cowrie-test/cowrie}"
CFG="$COWRIE_HOME/etc/cowrie.cfg"
SCTL=(systemctl --user)

need_systemd() {
  "${SCTL[@]}" show-environment >/dev/null 2>&1 || { echo "systemd user manager not available (WSL: [boot] systemd=true in /etc/wsl.conf)" >&2; exit 2; }
}
installed() { [ -f "$UNIT_DIR/$UNIT" ]; }

case "${1:-status}" in
  install)
    need_systemd
    mkdir -p "$UNIT_DIR"
    sed "s#@REPO_ROOT@#$REPO_ROOT#g" "$REPO_ROOT/scripts/rotator/$UNIT" > "$UNIT_DIR/$UNIT"
    "${SCTL[@]}" daemon-reload
    echo "installed $UNIT_DIR/$UNIT (disabled, not started). Enable explicitly with: $0 enable"
    ;;
  enable)
    need_systemd
    installed || { echo "not installed: run '$0 install' first" >&2; exit 2; }
    # An explicit enable starts with a full crash-restart budget (StartLimitBurst counts every start, manual ones
    # included, so a recovery within the hour could otherwise leave no automatic restart for a later crash).
    "${SCTL[@]}" reset-failed "$UNIT" 2>/dev/null || true
    "${SCTL[@]}" enable --now "$UNIT"
    "${SCTL[@]}" --no-pager --lines=0 status "$UNIT" || true
    ;;
  disable)
    need_systemd
    installed || { echo "not installed"; exit 0; }
    "${SCTL[@]}" disable --now "$UNIT" || true
    echo "rotator stopped and disabled"
    ;;
  status)
    if "${SCTL[@]}" show-environment >/dev/null 2>&1 && installed; then
      echo "unit        : $("${SCTL[@]}" is-enabled "$UNIT" 2>/dev/null || true) / $("${SCTL[@]}" is-active "$UNIT" 2>/dev/null || true)"
    else
      echo "unit        : not installed"
    fi
    echo "persona     : $(head -1 "$CFG" 2>/dev/null | tr -d '\r' | sed -n 's/.*switch_profile.py (\(.*\)).*/\1/p')"
    echo "listen      : $(grep '^listen_endpoints' "$CFG" 2>/dev/null | tr -d '\r' | sed 's/.*= *//')"
    if [ -f "$STATUS_FILE" ]; then echo "last status : $STATUS_FILE"; cat "$STATUS_FILE"; echo; else echo "last status : none yet"; fi
    ;;
  logs)
    journalctl --user -u "$UNIT" --no-pager -n "${2:-50}"
    ;;
  recover)
    # The loop exits with code 3 ("needs_recovery") when a switch failed AND Cowrie did not restart with the restored
    # cowrie.cfg. systemd does not restart it then. Bring Cowrie back, check it, and only then enable again.
    if "${SCTL[@]}" show-environment >/dev/null 2>&1 && installed; then "${SCTL[@]}" stop "$UNIT" || true; fi
    bash "$REPO_ROOT/scripts/demo/cowrie-demo-mode.sh" restart
    echo
    "$0" status
    echo "If Cowrie answers again, re-enable with: $0 enable   (the failed decision is already FAILED in the backend)"
    ;;
  uninstall)
    if "${SCTL[@]}" show-environment >/dev/null 2>&1 && installed; then
      "${SCTL[@]}" disable --now "$UNIT" || true
      rm -f "$UNIT_DIR/$UNIT"
      "${SCTL[@]}" daemon-reload
    fi
    echo "uninstalled"
    ;;
  *)
    echo "usage: $0 install|enable|status|logs|disable|recover|uninstall" >&2; exit 2
    ;;
esac
