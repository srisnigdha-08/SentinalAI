#!/bin/sh
# Cowrie data retention (M5): Cowrie rotates cowrie.json daily but never deletes anything, and TTY recordings
# and captured downloads grow without bound. Deletes, under the Cowrie install, files older than the limits:
#   var/log/cowrie/cowrie.json.YYYY-MM-DD (and cowrie.log.*)   COWRIE_LOG_DAYS       (default 30)
#   var/lib/cowrie/tty/*                                       COWRIE_TTY_DAYS       (default 90)
#   var/lib/cowrie/downloads/*                                 COWRIE_DOWNLOAD_DAYS  (default 30)
# The live cowrie.json is never touched. The parser must have read a rotated log before it is deleted: keep
# COWRIE_LOG_DAYS well above any parser outage you expect (its state records which file it is reading).
#
#   COWRIE_DIR=~/cowrie ./retention.sh --dry-run     # list what would be deleted
#   COWRIE_DIR=~/cowrie ./retention.sh               # delete
# Schedule it daily, e.g. crontab:  17 3 * * *  COWRIE_DIR=/home/cowrie/cowrie /path/to/retention.sh
set -eu
COWRIE_DIR=${COWRIE_DIR:?set COWRIE_DIR to the Cowrie install (the directory holding var/ and etc/)}
LOG_DAYS=${COWRIE_LOG_DAYS:-30}
TTY_DAYS=${COWRIE_TTY_DAYS:-90}
DOWNLOAD_DAYS=${COWRIE_DOWNLOAD_DAYS:-30}
ACTION=-delete
[ "${1:-}" = "--dry-run" ] && ACTION=-print

for n in "$LOG_DAYS" "$TTY_DAYS" "$DOWNLOAD_DAYS"; do
  case $n in ''|*[!0-9]*) echo "retention days must be whole numbers" >&2; exit 2 ;; esac
done

prune() { # dir, days, name pattern
  [ -d "$1" ] || return 0
  find "$1" -maxdepth 1 -type f -name "$3" ! -name .gitignore -mtime +"$2" $ACTION
}

prune "$COWRIE_DIR/var/log/cowrie" "$LOG_DAYS" 'cowrie.json.*'
prune "$COWRIE_DIR/var/log/cowrie" "$LOG_DAYS" 'cowrie.log.*'
prune "$COWRIE_DIR/var/lib/cowrie/tty" "$TTY_DAYS" '*'
prune "$COWRIE_DIR/var/lib/cowrie/downloads" "$DOWNLOAD_DAYS" '*'
