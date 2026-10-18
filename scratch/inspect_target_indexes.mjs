import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');

async function inspectIndexes() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const collections = ['threatlogs', 'alerts', 'auditlogs', 'honeypotsessions'];
  for (const c of collections) {
    const idxs = await mongoose.connection.db.collection(c).indexes();
    console.log(`=== ${c} (${idxs.length} indexes) ===`);
    idxs.forEach(i => {
      console.log(`  - name: "${i.name}", key: ${JSON.stringify(i.key)}${i.unique ? ', unique: true' : ''}${i.expireAfterSeconds !== undefined ? `, TTL: ${i.expireAfterSeconds}s` : ''}`);
    });
  }
  await mongoose.disconnect();
}
inspectIndexes().catch(console.error);
