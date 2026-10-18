import mongoose from '../backend/node_modules/mongoose/index.js';

await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
const db = mongoose.connection.db;

const before = {"blockedips":0,"campaigns":1,"trainingsamples":0,"auditlogs":105,"containmentactions":0,"systemsettings":1,"authsessions":57,"users":6,"aipredictions":9,"threatlogs":10,"alerts":5,"honeypotsessions":8};

const collections = await db.listCollections().toArray();
const after = {};
const diff = {};
let totalDiff = 0;

for (const col of collections) {
  const count = await db.collection(col.name).countDocuments();
  after[col.name] = count;
  const b = before[col.name] || 0;
  diff[col.name] = count - b;
  totalDiff += Math.abs(count - b);
}

console.log('=== COLLECTION COUNTS AFTER TEST ===');
console.log('BEFORE:', JSON.stringify(before));
console.log('AFTER: ', JSON.stringify(after));
console.log('DIFF:  ', JSON.stringify(diff));
console.log('TOTAL MUTATIONS DETECTED:', totalDiff);

await mongoose.disconnect();
