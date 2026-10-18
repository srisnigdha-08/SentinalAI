import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');

async function testSparseNull() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  // Query live authsessions in sentinel-db
  const total = await db.collection('authsessions').countDocuments();
  const nullCount = await db.collection('authsessions').countDocuments({ revokedAt: null });
  const dateCount = await db.collection('authsessions').countDocuments({ revokedAt: { $type: 'date' } });

  console.log('Total authsessions in DB:', total);
  console.log('Sessions with revokedAt: null:', nullCount);
  console.log('Sessions with revokedAt type Date:', dateCount);

  await mongoose.disconnect();
}

testSparseNull().catch(console.error);
