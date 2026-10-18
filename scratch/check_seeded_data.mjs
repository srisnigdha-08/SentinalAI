import mongoose from '../backend/node_modules/mongoose/index.js';

async function checkSeededData() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  console.log('=== CHECK 11: SEEDED VS REAL DATA AUDIT ===\n');

  // 1. Users
  const users = await db.collection('users').find({}).toArray();
  console.log('Users in DB (' + users.length + '):');
  users.forEach(u => {
    const isSynthetic = /demo|test|seed|sentinel\.local/i.test(u.email) || /demo|test/i.test(u.name);
    console.log(`  - ${u.email} (${u.role}, status: ${u.status}) => ${isSynthetic ? 'SYNTHETIC/SEED' : 'STANDARD_SYSTEM'}`);
  });

  // 2. ThreatLogs
  const threats = await db.collection('threatlogs').find({}).toArray();
  console.log('\nThreatLogs in DB (' + threats.length + '):');
  let testNetThreats = 0;
  let privateIpThreats = 0;
  let publicRealThreats = 0;

  threats.forEach(t => {
    const ip = t.sourceIP;
    const isTestNet = /^198\.51\.100\./.test(ip) || /^203\.0\.113\./.test(ip) || /^192\.0\.2\./.test(ip); // RFC 5737 Documentation IPs
    const isPrivate = /^10\./.test(ip) || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) || /^192\.168\./.test(ip) || ip === '127.0.0.1';
    if (isTestNet) testNetThreats++;
    else if (isPrivate) privateIpThreats++;
    else publicRealThreats++;
    console.log(`  - ID: ${t._id} | IP: ${ip} | Type: ${t.attackType} | Severity: ${t.severity} | Classification: ${isTestNet ? 'RFC5737_TESTNET' : isPrivate ? 'PRIVATE_OR_CONTAINER' : 'PUBLIC_INTERNET'}`);
  });
  console.log(`Threats breakdown: Test-Net (RFC 5737): ${testNetThreats}, Private/Docker: ${privateIpThreats}, Public Internet: ${publicRealThreats}`);

  // 3. HoneypotSessions
  const sessions = await db.collection('honeypotsessions').find({}).toArray();
  console.log('\nHoneypotSessions in DB (' + sessions.length + '):');
  sessions.forEach(s => {
    const isSynthetic = /^demo|^test|RFC5737/i.test(s.sessionId) || /^198\.51\.100\./.test(s.sourceIP) || /^172\./.test(s.sourceIP);
    console.log(`  - Session: ${s.sessionId} | IP: ${s.sourceIP} | Node: ${s.honeypotNode} | Commands: ${s.commands?.length || 0} | Credentials: ${s.credentials?.length || 0}`);
  });

  // 4. Alerts
  const alerts = await db.collection('alerts').find({}).toArray();
  console.log('\nAlerts in DB (' + alerts.length + '):');
  alerts.forEach(a => {
    console.log(`  - Alert ID: ${a._id} | Title: "${a.title}" | Severity: ${a.severity} | Type: ${a.type} | isRead: ${a.isRead}`);
  });

  // 5. AuditLogs
  const audits = await db.collection('auditlogs').find({}).toArray();
  const testAudits = audits.filter(a =>
    /test|probe|mock|fixture|audit-live/i.test(a.action) ||
    /test|probe|mock|fixture/i.test(a.actor?.email || '') ||
    /test|probe|mock|fixture/i.test(JSON.stringify(a.details || {}))
  );
  console.log(`\nAuditLogs in DB (${audits.length}): Synthetic / Verification entries: ${testAudits.length} (${Math.round((testAudits.length / audits.length) * 100)}%)`);
  console.log('Sample synthetic audit actions:');
  testAudits.slice(0, 5).forEach(a => console.log(`  - Action: ${a.action} | Actor: ${a.actor?.email} | Status: ${a.status}`));

  await mongoose.disconnect();
}

checkSeededData().catch(console.error);
