/**
 * Initiates the single-node replica set once, and waits until this node can accept writes. Safe to run on every start.
 * Run by deployment/mongo-replicaset-entrypoint.sh. On MongoDB's temporary first-boot server rs.status() fails with
 * NoReplicationEnabled, so this exits non-zero and the entrypoint tries again once the real server is up.
 */
/* global rs, db, process, quit, sleep, print */
const member = process.env.MONGO_RS_MEMBER || 'mongo:27017';

try {
  rs.status();
} catch (e) {
  if (e.codeName !== 'NotYetInitialized') throw e;
  rs.initiate({ _id: 'rs0', members: [{ _id: 0, host: member }] });
  print(`[mongo-replicaset] Initiated rs0 with member ${member}.`);
}

for (let waited = 0; waited < 60; waited++) {
  if (db.hello().isWritablePrimary) {
    print('[mongo-replicaset] Primary is ready.');
    quit(0);
  }
  sleep(1000);
}
print('[mongo-replicaset] No primary after 60 seconds.');
quit(1);
