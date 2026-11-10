#!/bin/sh
# Starts MongoDB as a single-node replica set for docker-compose.replicaset.yml.
#
# MongoDB refuses a keyfile readable by anyone else, and a host file's owner cannot be relied on, so the mounted secret
# is copied into the container's own filesystem, owned by the mongodb user with mode 400.
#
# The configure step runs beside mongod rather than as a separate one-shot service. It initiates the replica set and
# reapplies deployment/mongo-init.js, which gives an existing volume the current role definitions. The healthcheck needs
# both this step's marker and a writable primary, so the backend never starts before the role update has landed.
set -eu

KEYFILE=/data/mongo-keyfile
CONFIGURED=/tmp/sentinel-mongo-configured
rm -f "$CONFIGURED"
install -o mongodb -g mongodb -m 400 /run/secrets/mongo_keyfile "$KEYFILE"

mongo_admin() {
  mongosh --quiet --host 127.0.0.1 -u root -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin "$@"
}

configure() {
  attempt=0
  while [ "$attempt" -lt 150 ]; do
    if mongo_admin --file /usr/local/bin/mongo-replicaset-init.js 2>/dev/null \
      && mongo_admin --file /docker-entrypoint-initdb.d/mongo-init.js 2>/dev/null; then
      touch "$CONFIGURED"
      echo '[mongo-replicaset] Configuration complete.'
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  echo '[mongo-replicaset] Configuration failed; the healthcheck will stay unhealthy.' >&2
  return 1
}

configure &
exec docker-entrypoint.sh "$@"
