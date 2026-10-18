import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');

async function inspectUsers() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  const users = await db.collection('users').find({}).toArray();
  console.log(`Total users in DB: ${users.length}`);
  users.forEach(u => {
    console.log({
      _id: u._id,
      email: u.email,
      name: u.name,
      role: u.role,
      status: u.status,
      authVersion: u.authVersion,
      tokenVersion: u.tokenVersion,
      mustChangePassword: u.mustChangePassword,
      hasPasswordHash: Boolean(u.password),
      passwordHashPrefix: u.password ? u.password.slice(0, 7) : null,
      createdAt: u.createdAt,
      updatedAt: u.updatedAt
    });
  });

  await mongoose.disconnect();
}

inspectUsers().catch(console.error);
