import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');

async function testPartialTTL() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db-test-ttl-verify');
  const db = mongoose.connection.db;
  const col = db.collection('test_sessions');
  await col.deleteMany({});

  // 1. Create partial TTL index: expireAfterSeconds: 1 (1 second)
  // Filtering for revokedAt: { $type: 'date' }
  await col.createIndex(
    { revokedAt: 1 },
    {
      name: 'revokedAt_1_ttl',
      expireAfterSeconds: 1,
      partialFilterExpression: { revokedAt: { $type: 'date' } },
    }
  );

  // Insert active session (revokedAt: null) and revoked session (revokedAt: 10s ago)
  const now = new Date();
  const past = new Date(now.getTime() - 10000); // 10 seconds ago
  await col.insertOne({ _id: 'active-session-1', revokedAt: null, user: 'user-1' });
  await col.insertOne({ _id: 'revoked-session-old', revokedAt: past, user: 'user-1' });
  await col.insertOne({ _id: 'revoked-session-fresh', revokedAt: now, user: 'user-1' });

  console.log('Inserted 3 test sessions: 1 active, 1 revoked-old, 1 revoked-fresh');
  const initialDocs = await col.find({}).toArray();
  console.log('Initial doc IDs:', initialDocs.map(d => d._id));

  // Verify explain plan
  const expActive = await col.find({ revokedAt: null }).explain('executionStats');
  console.log('Explain find({ revokedAt: null }) winning plan:', expActive.queryPlanner.winningPlan.stage);
  // It won't use the partial index for revokedAt: null, which is correct!

  await db.dropDatabase();
  await mongoose.disconnect();
}

testPartialTTL().catch(console.error);
