import mongoose from '../backend/node_modules/mongoose/index.js';

await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
const db = mongoose.connection.db;

console.log('=== ITEM 1: SESSION 9b21e8e00dd7 DETAILS ===');
const s = await db.collection('honeypotsessions').findOne({ sessionId: '9b21e8e00dd7' });
if (s) {
  console.log('Session ID:', s.sessionId);
  console.log('Source IP:', s.sourceIP);
  console.log('Source Port:', s.sourcePort);
  console.log('Honeypot Node:', s.honeypotNode);
  console.log('Protocol:', s.protocol);
  console.log('Start Time:', s.startTime);
  console.log('End Time:', s.endTime);
  console.log('Duration Seconds:', s.durationSeconds);
  console.log('Commands Count:', s.commands?.length);
  console.log('Commands Sample:', JSON.stringify(s.commands?.slice(0, 5)));
  console.log('Credentials Count:', s.credentials?.length);
  console.log('Credentials Sample Usernames:', s.credentials?.slice(0, 10).map(c => c.username));
  console.log('Files Accessed:', s.filesAccessed);
  console.log('IOC Extracted:', s.iocExtracted);
  console.log('Closure State:', s.closureAnalysisState);
} else {
  console.log('Session 9b21e8e00dd7 not found!');
}

console.log('\n=== ITEM 2: PASSWORD REDACTION AUDIT ACROSS ALL SESSIONS ===');
const allSessions = await db.collection('honeypotsessions').find({}).toArray();
for (const sess of allSessions) {
  const creds = sess.credentials || [];
  let redactedCount = 0;
  let nonRedactedCount = 0;
  for (const c of creds) {
    if (c.password === '***REDACTED***') {
      redactedCount++;
    } else {
      nonRedactedCount++;
    }
  }
  console.log(`Session: ${sess.sessionId} (IP: ${sess.sourceIP}, Node: ${sess.honeypotNode})`);
  console.log(`  Total Credentials: ${creds.length}`);
  console.log(`  Redacted ('***REDACTED***'): ${redactedCount}`);
  console.log(`  NON-Redacted (Plaintext):    ${nonRedactedCount}`);
}

await mongoose.disconnect();
