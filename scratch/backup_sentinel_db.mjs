import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import mongoose from '../backend/node_modules/mongoose/index.js';
import BSON from '../backend/node_modules/bson/lib/bson.cjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

async function dumpDatabase() {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupDir = path.join(rootDir, 'backups', `sentinel-db-${timestamp}`);
  fs.mkdirSync(backupDir, { recursive: true });

  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db';
  console.log(`Connecting to ${mongoUri}...`);
  await mongoose.connect(mongoUri);

  const db = mongoose.connection.db;
  const collections = await db.listCollections().toArray();

  console.log(`Found ${collections.length} collections to dump.`);
  const summary = {};

  for (const collInfo of collections) {
    const collName = collInfo.name;
    const coll = db.collection(collName);

    // 1. Fetch indexes & metadata
    const indexes = await coll.indexes();
    const metadata = {
      indexes: indexes.map(idx => ({
        v: idx.v,
        key: idx.key,
        name: idx.name,
        unique: idx.unique || undefined,
        background: idx.background || undefined
      }))
    };
    fs.writeFileSync(
      path.join(backupDir, `${collName}.metadata.json`),
      JSON.stringify(metadata, null, 2),
      'utf8'
    );

    // 2. Fetch documents and write .bson
    const docs = await coll.find({}).toArray();
    const bsonBuffers = [];
    for (const doc of docs) {
      bsonBuffers.push(BSON.serialize(doc));
    }
    const fullBsonBuffer = Buffer.concat(bsonBuffers);
    fs.writeFileSync(path.join(backupDir, `${collName}.bson`), fullBsonBuffer);

    // 3. Also write readable JSON for quick inspection
    fs.writeFileSync(
      path.join(backupDir, `${collName}.json`),
      JSON.stringify(docs, null, 2),
      'utf8'
    );

    summary[collName] = {
      count: docs.length,
      bsonBytes: fullBsonBuffer.length
    };
    console.log(`  -> Dumped ${collName}: ${docs.length} docs (${fullBsonBuffer.length} bytes BSON)`);
  }

  await mongoose.disconnect();
  console.log(`\n=== BACKUP COMPLETE ===`);
  console.log(`Backup Folder: ${backupDir}`);
  return { backupDir, summary };
}

dumpDatabase().catch((err) => {
  console.error('Backup failed:', err);
  process.exit(1);
});
