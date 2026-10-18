import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');
const bcrypt = require('../backend/node_modules/bcryptjs');

async function checkAdminPassword() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  const adminLocal = await db.collection('users').findOne({ email: 'admin@sentinel.local' });
  if (!adminLocal) {
    console.log('admin@sentinel.local not found');
    await mongoose.disconnect();
    return;
  }

  const adminIo = await db.collection('users').findOne({ email: 'admin@sentinel.io' });

  // Test against candidate passwords without printing
  const candidates = [
    'Admin@1234',
    'Admin123!',
    'Password123!',
    'Sentinel@2026',
    'admin123',
    'sentinel',
    'CHANGE_ME_secure_initial_password_min_8_chars'
  ];

  let matchedCandidate = false;
  for (const c of candidates) {
    const isMatch = await bcrypt.compare(c, adminLocal.password);
    if (isMatch) {
      console.log('admin@sentinel.local password matches candidate:', c);
      matchedCandidate = true;
      break;
    }
  }

  if (!matchedCandidate) {
    console.log('admin@sentinel.local password does not match common candidate list.');
  }

  // Compare with admin@sentinel.io password hash
  if (adminIo) {
    const isSameAsAdminIo = adminLocal.password === adminIo.password;
    console.log('Does admin@sentinel.local have identical hash to admin@sentinel.io?', isSameAsAdminIo);
    if (await bcrypt.compare('Admin@1234', adminIo.password)) {
      console.log('admin@sentinel.io matches Admin@1234');
    }
  }

  await mongoose.disconnect();
}

checkAdminPassword().catch(console.error);
