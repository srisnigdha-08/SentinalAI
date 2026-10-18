import mongoose from '../backend/node_modules/mongoose/index.js';

await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
const db = mongoose.connection.db;

const u = await db.collection('users').findOne({ email: 'admin@sentinel.local' });
console.log('User admin@sentinel.local:', JSON.stringify(u, null, 2));

// Also check all users to see their creation timestamps and structure
const allUsers = await db.collection('users').find({}).toArray();
for (const user of allUsers) {
  console.log(`User: ${user.email} | createdAt: ${user.createdAt} | authVersion: ${user.authVersion} | tokenVersion: ${user.tokenVersion}`);
}

await mongoose.disconnect();
