import mongoose from '../backend/node_modules/mongoose/index.js';

await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
const db = mongoose.connection.db;

const collections = await db.listCollections().toArray();
const counts = {};
for (const col of collections) {
  counts[col.name] = await db.collection(col.name).countDocuments();
}
console.log('COLLECTION_COUNTS:' + JSON.stringify(counts));

await mongoose.disconnect();
