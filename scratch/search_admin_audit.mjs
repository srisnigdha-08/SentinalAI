import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');

async function searchAudit() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  const logs = await db.collection('auditlogs').find({
    $or: [
      { 'actor.email': 'admin@sentinel.local' },
      { 'target.identifier': 'admin@sentinel.local' },
      { 'target.id': '6ad481835d17085d4036a633' },
      { action: { $regex: 'USER', $options: 'i' } }
    ]
  }).toArray();

  console.log(`Found ${logs.length} audit logs matching user:`);
  logs.forEach(l => {
    console.log(`[${l.createdAt.toISOString()}] action=${l.action}, status=${l.status}, actor=${l.actor?.email}, target=${l.target?.identifier} (${l.target?.id})`);
  });

  await mongoose.disconnect();
}

searchAudit().catch(console.error);
