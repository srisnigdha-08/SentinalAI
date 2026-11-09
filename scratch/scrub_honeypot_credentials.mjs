import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');

async function main() {
  const isApply = process.argv.includes('--apply');
  const isDryRun = !isApply || process.argv.includes('--dry-run');

  console.log(`=== HONEYPOT CREDENTIAL SCRUB SCRIPT ===`);
  console.log(`Mode: ${isDryRun ? 'DRY-RUN (Read-Only)' : 'APPLY (Write)'}`);

  // If apply mode, verify backup exists
  if (!isDryRun) {
    const backupDir = path.resolve('backups');
    if (!fs.existsSync(backupDir)) {
      console.error('[ERROR] Backups directory does not exist! Aborting scrub.');
      process.exit(1);
    }
    const backups = fs.readdirSync(backupDir).filter(f => f.startsWith('pre-db-fixes-'));
    if (backups.length === 0) {
      console.error('[ERROR] No pre-db-fixes backup directory found! Aborting scrub.');
      process.exit(1);
    }
    console.log(`[SAFETY CHECK] Verified existing backup: ${backups[backups.length - 1]}`);
  }

  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;
  const col = db.collection('honeypotsessions');

  const sessions = await col.find({ 'credentials.0': { $exists: true } }).toArray();

  let affectedDocs = 0;
  let affectedCredentials = 0;
  const perSessionStats = [];

  for (const s of sessions) {
    if (!Array.isArray(s.credentials) || s.credentials.length === 0) continue;

    let unredactedCountInSession = 0;
    const scrubbedCredentials = s.credentials.map(c => {
      if (c && c.password !== '***REDACTED***') {
        unredactedCountInSession++;
        affectedCredentials++;
        return {
          username: typeof c.username === 'string' ? c.username.slice(0, 100) : '',
          password: '***REDACTED***',
          success: Boolean(c.success),
        };
      }
      return {
        username: typeof c?.username === 'string' ? c.username.slice(0, 100) : '',
        password: '***REDACTED***',
        success: Boolean(c?.success),
      };
    });

    if (unredactedCountInSession > 0) {
      affectedDocs++;
      perSessionStats.push({
        sessionId: s.sessionId,
        totalCreds: s.credentials.length,
        unredactedCreds: unredactedCountInSession,
      });

      if (!isDryRun) {
        await col.updateOne(
          { _id: s._id },
          { $set: { credentials: scrubbedCredentials } }
        );
      }
    }
  }

  console.log(`\n=== SCRUB AUDIT REPORT ===`);
  console.log(`Total sessions scanned: ${sessions.length}`);
  console.log(`Documents with unredacted credentials: ${affectedDocs}`);
  console.log(`Total credential entries with unredacted passwords: ${affectedCredentials}`);
  console.log('\nPer-Session Breakdown (Counts only, zero secrets printed):');
  perSessionStats.forEach(stat => {
    console.log(`  - Session ${stat.sessionId}: ${stat.unredactedCreds} / ${stat.totalCreds} entries unredacted`);
  });

  if (isDryRun) {
    console.log(`\n[DRY-RUN RESULT] ZERO database modifications were performed.`);
    console.log(`To execute this change, run with --apply after administrative approval.`);
  } else {
    console.log(`\n[APPLY RESULT] Successfully scrubbed ${affectedDocs} documents and ${affectedCredentials} credential entries.`);
  }

  await mongoose.disconnect();
}

main().catch(err => {
  console.error('[FATAL ERROR]:', err);
  process.exit(1);
});
