import mongoose from 'mongoose';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, '../backend/.env') });

const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db';

async function dump() {
  await mongoose.connect(mongoUri);
  console.log('Connected to MongoDB');

  const AuditLog = mongoose.model('AuditLog', new mongoose.Schema({}, { strict: false }));
  
  const distinctActions = await AuditLog.distinct('action');
  console.log('Found distinct actions in DB:', distinctActions);

  const samples = {};
  for (const action of distinctActions) {
    const doc = await AuditLog.findOne({ action }).sort({ createdAt: -1 }).lean();
    samples[action] = doc;
  }

  console.log('--- AUDIT SAMPLES ---');
  console.log(JSON.stringify(samples, null, 2));

  await mongoose.disconnect();
}

dump().catch((err) => {
  console.error(err);
  process.exit(1);
});
