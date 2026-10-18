import mongoose from '../backend/node_modules/mongoose/index.js';
import crypto from 'crypto';
import fs from 'fs';

async function generateFingerprint() {
  await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db');
  const db = mongoose.connection.db;

  const collections = (await db.listCollections().toArray())
    .map(c => c.name)
    .filter(name => !name.startsWith('system.'))
    .sort();

  const report = {};

  for (const collName of collections) {
    const coll = db.collection(collName);
    const count = await coll.countDocuments();
    
    if (collName === 'auditlogs') {
      const latest = await coll.find({}, { projection: { _id: 1, createdAt: 1 } }).sort({ _id: -1 }).limit(1).toArray();
      report[collName] = {
        count,
        latestId: latest[0]?._id?.toString() || null,
        latestCreatedAt: latest[0]?.createdAt?.toISOString() || null
      };
    } else {
      const docs = await coll.find({}, { projection: { _id: 1, updatedAt: 1, createdAt: 1 } }).sort({ _id: 1 }).toArray();
      const hash = crypto.createHash('sha256');
      for (const d of docs) {
        const ts = d.updatedAt ? d.updatedAt.toISOString() : (d.createdAt ? d.createdAt.toISOString() : '');
        hash.update(`${d._id.toString()}:${ts};`);
      }
      report[collName] = {
        count,
        fingerprint: count > 0 ? hash.digest('hex') : 'empty'
      };
    }
  }

  await mongoose.disconnect();
  return report;
}

const outputFile = process.argv[2] || 'scratch/evidence/fingerprint_before.json';
generateFingerprint().then(report => {
  fs.mkdirSync('scratch/evidence', { recursive: true });
  fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));
  console.log(`=== Fingerprint written to ${outputFile} ===`);
  console.log(JSON.stringify(report, null, 2));
}).catch(console.error);
