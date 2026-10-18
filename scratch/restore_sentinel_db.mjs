import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import mongoose from '../backend/node_modules/mongoose/index.js';
import BSON from '../backend/node_modules/bson/lib/bson.cjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const args = process.argv.slice(2);
const backupFolderArg = args[0];
const targetDbIndex = args.indexOf('--target-db');
const targetDbArg = targetDbIndex !== -1 ? args[targetDbIndex + 1] : null;
const hasConfirm = args.includes('--confirm');

if (!backupFolderArg || !targetDbArg || !hasConfirm) {
  console.error('\n[SAFETY RESTRICTION] Database restore requires explicit parameters.');
  console.error('Usage: node scratch/restore_sentinel_db.mjs <backup-folder> --target-db <targetDbName> --confirm');
  console.error('Example: node scratch/restore_sentinel_db.mjs backups/pre-db-fixes-20261018-210748 --target-db sentinel-db-test --confirm\n');
  process.exit(1);
}

const backupDir = path.isAbsolute(backupFolderArg)
  ? backupFolderArg
  : path.join(rootDir, backupFolderArg);

if (!fs.existsSync(backupDir)) {
  console.error(`Backup directory does not exist: ${backupDir}`);
  process.exit(1);
}

async function restoreDatabase() {
  const mongoUri = process.env.MONGO_URI || `mongodb://localhost:27017/${targetDbArg}`;
  console.log(`Connecting to ${mongoUri} (target database: ${targetDbArg})...`);
  await mongoose.connect(mongoUri);
  const db = mongoose.connection.db;

  if (db.databaseName !== targetDbArg) {
    throw new Error(`Connected database (${db.databaseName}) does not match target database argument (${targetDbArg}). Aborting.`);
  }

  const files = fs.readdirSync(backupDir).filter(f => f.endsWith('.bson'));
  console.log(`Found ${files.length} BSON collections to restore from ${backupDir} into ${targetDbArg}`);

  for (const file of files) {
    const collName = path.basename(file, '.bson');
    const bsonBuffer = fs.readFileSync(path.join(backupDir, file));
    const coll = db.collection(collName);

    // Drop existing documents in target collection
    await coll.deleteMany({});

    if (bsonBuffer.length > 0) {
      const docs = [];
      let offset = 0;
      while (offset < bsonBuffer.length) {
        const size = bsonBuffer.readInt32LE(offset);
        const docBuffer = bsonBuffer.subarray(offset, offset + size);
        docs.push(BSON.deserialize(docBuffer));
        offset += size;
      }
      if (docs.length > 0) {
        await coll.insertMany(docs);
      }
      console.log(`  -> Restored ${collName}: ${docs.length} documents.`);
    } else {
      console.log(`  -> Restored ${collName}: 0 documents (empty collection).`);
    }

    // Re-create indexes if metadata file exists
    const metaFile = path.join(backupDir, `${collName}.metadata.json`);
    if (fs.existsSync(metaFile)) {
      try {
        const meta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
        if (Array.isArray(meta.indexes)) {
          for (const idx of meta.indexes) {
            if (idx.name !== '_id_') {
              const options = {};
              if (idx.unique) options.unique = true;
              if (idx.name) options.name = idx.name;
              await coll.createIndex(idx.key, options);
            }
          }
        }
      } catch (idxErr) {
        console.warn(`  Warning recreating indexes for ${collName}: ${idxErr.message}`);
      }
    }
  }

  await mongoose.disconnect();
  console.log('\n=== RESTORE COMPLETE ===');
}

restoreDatabase().catch(err => {
  console.error('Restore failed:', err);
  process.exit(1);
});
