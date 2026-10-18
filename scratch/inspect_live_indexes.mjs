import mongoose from '../backend/node_modules/mongoose/index.js';

async function checkIndexes() {
  await mongoose.connect('mongodb://localhost:27017/sentinel-db');
  const db = mongoose.connection.db;

  const collections = ['alerts', 'authsessions', 'honeypotsessions', 'auditlogs', 'threatlogs'];

  for (const collName of collections) {
    console.log(`\n=== Indexes for ${collName} ===`);
    const indexes = await db.collection(collName).indexes();
    for (const idx of indexes) {
      console.log(`  Name: ${idx.name} | Key: ${JSON.stringify(idx.key)} ${idx.expireAfterSeconds !== undefined ? `| TTL: ${idx.expireAfterSeconds}s` : ''} ${idx.unique ? '| UNIQUE' : ''}`);
    }
  }

  await mongoose.disconnect();
}

checkIndexes().catch(console.error);
