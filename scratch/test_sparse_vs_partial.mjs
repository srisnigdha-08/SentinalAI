import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');

async function verifySparseVsPartial() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db-test-ttl');
  const db = mongoose.connection.db;

  const col = db.collection('test_sessions');
  await col.deleteMany({});

  // Insert 1 active session (revokedAt: null) and 1 revoked session (revokedAt: Date)
  await col.insertOne({ _id: 'active-1', revokedAt: null });
  await col.insertOne({ _id: 'revoked-1', revokedAt: new Date() });

  // 1. Create sparse index
  await col.createIndex({ revokedAt: 1 }, { name: 'sparse_idx', sparse: true });
  // Check explain on sparse index
  const expSparse = await col.find({ revokedAt: null }).hint('sparse_idx').explain('executionStats');
  console.log('Sparse index keys examined for revokedAt: null ->', expSparse.executionStats.totalKeysExamined);

  // 2. Create partialFilterExpression index
  await col.createIndex(
    { revokedAt: 1 },
    {
      name: 'partial_ttl_idx',
      expireAfterSeconds: 48 * 3600,
      partialFilterExpression: { revokedAt: { $type: 'date' } },
    }
  );
  
  const idxs = await col.indexes();
  console.log('Indexes created successfully:');
  idxs.forEach(i => console.log(' -', i.name, JSON.stringify(i.key), i.partialFilterExpression || 'no partial', i.expireAfterSeconds));

  await db.dropDatabase();
  await mongoose.disconnect();
}

verifySparseVsPartial().catch(console.error);
