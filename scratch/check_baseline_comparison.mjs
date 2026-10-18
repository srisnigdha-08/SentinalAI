import mongoose from '../backend/node_modules/mongoose/index.js';
import fs from 'fs';
import path from 'path';
import BSON from '../backend/node_modules/bson/lib/bson.cjs';

async function compareWithBackup() {
  await mongoose.connect('mongodb://localhost:27017/sentinel-db');
  const db = mongoose.connection.db;

  const backupDir = 'backups/pre-db-fixes-20261018-210748';

  function readBackupCollection(collName) {
    const filePath = path.join(backupDir, `${collName}.bson`);
    const buf = fs.readFileSync(filePath);
    const docs = [];
    let offset = 0;
    while (offset < buf.length) {
      const size = buf.readInt32LE(offset);
      docs.push(BSON.deserialize(buf.subarray(offset, offset + size)));
      offset += size;
    }
    return docs;
  }

  // 1. Check users
  console.log('=== 1. USERS COLLECTION AUDIT ===');
  const liveUsers = await db.collection('users').find({}).toArray();
  const backupUsers = readBackupCollection('users');
  console.log(`Live users count: ${liveUsers.length} | Backup users count: ${backupUsers.length}`);

  for (const bUser of backupUsers) {
    const lUser = liveUsers.find(u => u._id.toString() === bUser._id.toString());
    if (!lUser) {
      console.log(`  MISSING user in live DB: ${bUser.email} (${bUser._id})`);
      continue;
    }
    // Compare fields
    const bKeys = Object.keys(bUser).sort();
    const lKeys = Object.keys(lUser).sort();
    const diffKeys = lKeys.filter(k => !bKeys.includes(k)).concat(bKeys.filter(k => !lKeys.includes(k)));
    if (diffKeys.length > 0) {
      console.log(`  Key drift on ${bUser.email}:`, diffKeys);
    }
    // Check tokenVersion specifically
    if (bUser.email === 'admin@sentinel.local') {
      console.log(`  admin@sentinel.local raw disk fields:`);
      console.log(`    Backup tokenVersion: ${bUser.tokenVersion} (exists on disk: ${'tokenVersion' in bUser})`);
      console.log(`    Live   tokenVersion: ${lUser.tokenVersion} (exists on disk: ${'tokenVersion' in lUser})`);
    }
  }

  // 2. Check honeypotsessions credentials
  console.log('\n=== 2. HONEYPOT SESSIONS CREDENTIALS AUDIT ===');
  const liveHPS = await db.collection('honeypotsessions').find({}).toArray();
  const backupHPS = readBackupCollection('honeypotsessions');
  console.log(`Live honeypotsessions count: ${liveHPS.length} | Backup honeypotsessions count: ${backupHPS.length}`);

  let liveTotalCreds = 0;
  let liveUnredactedCreds = 0;
  let liveRedactedCreds = 0;

  for (const sess of liveHPS) {
    const creds = sess.credentials || [];
    liveTotalCreds += creds.length;
    for (const c of creds) {
      if (c.password === '***REDACTED***') {
        liveRedactedCreds++;
      } else {
        liveUnredactedCreds++;
      }
    }
  }

  let backupTotalCreds = 0;
  let backupUnredactedCreds = 0;
  let backupRedactedCreds = 0;

  for (const sess of backupHPS) {
    const creds = sess.credentials || [];
    backupTotalCreds += creds.length;
    for (const c of creds) {
      if (c.password === '***REDACTED***') {
        backupRedactedCreds++;
      } else {
        backupUnredactedCreds++;
      }
    }
  }

  console.log(`Live Credentials:   Total: ${liveTotalCreds} | Unredacted: ${liveUnredactedCreds} | Redacted: ${liveRedactedCreds}`);
  console.log(`Backup Credentials: Total: ${backupTotalCreds} | Unredacted: ${backupUnredactedCreds} | Redacted: ${backupRedactedCreds}`);

  // 3. Check authsessions
  console.log('\n=== 3. AUTHSESSIONS AUDIT ===');
  const liveSessions = await db.collection('authsessions').find({}).toArray();
  const backupSessions = readBackupCollection('authsessions');
  console.log(`Live authsessions count: ${liveSessions.length} | Backup authsessions count: ${backupSessions.length}`);

  const liveRevoked = liveSessions.filter(s => s.revokedAt !== null && s.revokedAt !== undefined).length;
  const backupRevoked = backupSessions.filter(s => s.revokedAt !== null && s.revokedAt !== undefined).length;
  console.log(`Live Revoked: ${liveRevoked} | Backup Revoked: ${backupRevoked}`);

  await mongoose.disconnect();
}

compareWithBackup().catch(console.error);
