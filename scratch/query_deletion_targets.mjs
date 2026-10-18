import mongoose from '../backend/node_modules/mongoose/index.js';

async function run() {
  await mongoose.connect('mongodb://localhost:27017/sentinel-db');
  const db = mongoose.connection.db;
  const now = new Date();

  // 1. users: testanalyst6866@sentinel.io
  const userFilter = { email: 'testanalyst6866@sentinel.io' };
  const matchedUsers = await db.collection('users').find(userFilter).toArray();

  // 2. honeypotsessions: sessionId matching ^audit-live- or ^sess-analyst-feed-proof
  const sessionFilter = { sessionId: { $regex: '^(audit-live-|sess-analyst-feed-proof)' } };
  const matchedSessions = await db.collection('honeypotsessions').find(sessionFilter).toArray();

  // 3. threatlogs: sourceIP in (203.0.113.195, 198.51.100.77)
  const threatFilter = { sourceIP: { $in: ['203.0.113.195', '198.51.100.77'] } };
  const matchedThreats = await db.collection('threatlogs').find(threatFilter).toArray();

  // 4. blockedips: 198.51.100.77
  const blockedFilter = { ip: '198.51.100.77' };
  const matchedBlocked = await db.collection('blockedips').find(blockedFilter).toArray();

  // 5. authsessions: expired or revoked
  const authSessionFilter = {
    $or: [
      { revokedAt: { $ne: null } },
      { expiresAt: { $lt: now } }
    ]
  };
  const matchedAuthSessions = await db.collection('authsessions').find(authSessionFilter).toArray();
  const totalAuthSessions = await db.collection('authsessions').countDocuments();

  console.log(JSON.stringify({
    users: {
      filter: userFilter,
      matchedCount: matchedUsers.length,
      docs: matchedUsers.map(u => ({ id: u._id, email: u.email, name: u.name, role: u.role, status: u.status }))
    },
    honeypotsessions: {
      filter: { sessionId: { $regex: '^(audit-live-|sess-analyst-feed-proof)' } },
      matchedCount: matchedSessions.length,
      sampleSessionIds: matchedSessions.map(s => s.sessionId)
    },
    threatlogs: {
      filter: threatFilter,
      matchedCount: matchedThreats.length,
      threats: matchedThreats.map(t => ({ id: t._id, sourceIP: t.sourceIP, attackType: t.attackType, severity: t.severity, status: t.status }))
    },
    blockedips: {
      filter: blockedFilter,
      matchedCount: matchedBlocked.length,
      docs: matchedBlocked.map(b => ({ id: b._id, ip: b.ip, reason: b.reason }))
    },
    authsessions: {
      filter: {
        $or: [
          { revokedAt: { $ne: null } },
          { expiresAt: { $lt: '$NOW' } }
        ]
      },
      matchedCount: matchedAuthSessions.length,
      totalCount: totalAuthSessions
    }
  }, null, 2));

  await mongoose.disconnect();
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
