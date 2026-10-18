import mongoose from '../backend/node_modules/mongoose/index.js';

await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
const sessions = await mongoose.connection.db.collection('honeypotsessions').find({}).project({ sessionId: 1, credentials: 1 }).toArray();

for (const s of sessions) {
  console.log(`Session: ${s.sessionId}, credentials count: ${s.credentials?.length}`);
  if (s.credentials && s.credentials.length > 0) {
    console.log('Sample credential:', JSON.stringify(s.credentials[0]));
  }
}

await mongoose.disconnect();
