import mongoose from '../backend/node_modules/mongoose/index.js';

await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
const db = mongoose.connection.db;

const threats = await db.collection('threatlogs').find({}).toArray();
console.log('Total threats:', threats.length);

for (const t of threats) {
  // Check if any honeypot session links to this threat
  const hp = await db.collection('honeypotsessions').findOne({ linkedThreatLog: t._id });
  console.log(JSON.stringify({
    id: t._id,
    sourceIP: t.sourceIP,
    attackType: t.attackType,
    severity: t.severity,
    status: t.status,
    targetService: t.targetService,
    aiScore: t.aiScore,
    notes: t.notes,
    createdAt: t.createdAt,
    linkedHoneypotSessionId: hp ? hp.sessionId : null
  }, null, 2));
}

await mongoose.disconnect();
