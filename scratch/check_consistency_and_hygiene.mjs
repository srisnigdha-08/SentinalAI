import mongoose from '../backend/node_modules/mongoose/index.js';

async function runAudit() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  console.log('=== CHECK 5: CONSISTENCY BETWEEN COLLECTIONS ===');
  // A. Block state consistency
  const blockedIPs = await db.collection('blockedips').find({}).toArray();
  const threatsBlocked = await db.collection('threatlogs').find({ status: 'BLOCKED' }).toArray();
  const containmentActions = await db.collection('containmentactions').find({ enforcementStatus: 'ACTIVE' }).toArray();
  console.log('Active BlockedIPs count:', blockedIPs.length);
  console.log('ThreatLogs with status BLOCKED count:', threatsBlocked.length);
  console.log('ContainmentActions with status ACTIVE count:', containmentActions.length);
  
  // Check if any threat is BLOCKED while not in BlockedIPs
  const blockedIPSet = new Set(blockedIPs.map(b => b.ip));
  const threatsWithoutBlockedIP = threatsBlocked.filter(t => !blockedIPSet.has(t.sourceIP));
  console.log('ThreatLogs marked BLOCKED but missing from blockedips:', threatsWithoutBlockedIP.length);
  threatsWithoutBlockedIP.forEach(t => console.log('  Threat', t._id, 'IP:', t.sourceIP));

  // B. User status vs live authsessions
  const users = await db.collection('users').find({}).toArray();
  const userMap = new Map(users.map(u => [String(u._id), u]));
  const now = new Date();
  const activeSessions = await db.collection('authsessions').find({
    revokedAt: null,
    expiresAt: { $gt: now }
  }).toArray();
  console.log('Active (non-expired, non-revoked) sessions count:', activeSessions.length);

  let activeSessionsForInactiveUser = 0;
  let authVersionMismatches = 0;
  for (const s of activeSessions) {
    const user = userMap.get(String(s.user));
    if (!user || user.status !== 'active') {
      activeSessionsForInactiveUser++;
      console.log('  Session', s._id, 'belongs to inactive/missing user:', s.user);
    }
    if (user && s.authVersion !== user.authVersion) {
      authVersionMismatches++;
      console.log('  Session', s._id, 'authVersion (' + s.authVersion + ') != user.authVersion (' + user.authVersion + ')');
    }
  }
  console.log('Active sessions for inactive/missing users:', activeSessionsForInactiveUser);
  console.log('Active sessions with stale authVersion:', authVersionMismatches);

  // Check User tokenVersion vs authVersion
  let userVersionDrift = 0;
  for (const u of users) {
    if (u.tokenVersion !== u.authVersion) {
      userVersionDrift++;
      console.log('  User', u.email, 'tokenVersion (' + u.tokenVersion + ') != authVersion (' + u.authVersion + ')');
    }
  }
  console.log('Users where tokenVersion != authVersion:', userVersionDrift);

  console.log('\n=== CHECK 6: DUPLICATES ===');
  // Duplicate users by email (case variants)
  const emailLowerCounts = {};
  users.forEach(u => {
    const lower = u.email.toLowerCase();
    emailLowerCounts[lower] = (emailLowerCounts[lower] || 0) + 1;
  });
  const dupeEmails = Object.entries(emailLowerCounts).filter(([k, v]) => v > 1);
  console.log('Duplicate emails (case variants):', dupeEmails.length ? JSON.stringify(dupeEmails) : 'None');

  // Duplicate blockedips
  const ipCounts = {};
  blockedIPs.forEach(b => { ipCounts[b.ip] = (ipCounts[b.ip] || 0) + 1; });
  const dupeIPs = Object.entries(ipCounts).filter(([k, v]) => v > 1);
  console.log('Duplicate blocked IPs:', dupeIPs.length ? JSON.stringify(dupeIPs) : 'None');

  // Duplicate honeypot sessionIds
  const hpSessions = await db.collection('honeypotsessions').find({}).toArray();
  const hpSessionIdCounts = {};
  hpSessions.forEach(s => { hpSessionIdCounts[s.sessionId] = (hpSessionIdCounts[s.sessionId] || 0) + 1; });
  const dupeHpSessionIds = Object.entries(hpSessionIdCounts).filter(([k, v]) => v > 1);
  console.log('Duplicate honeypot sessionIds:', dupeHpSessionIds.length ? JSON.stringify(dupeHpSessionIds) : 'None');

  // Duplicate threats for the same event
  const allThreats = await db.collection('threatlogs').find({}).toArray();
  const threatEventKeyCounts = {};
  allThreats.forEach(t => {
    const k = `${t.sourceIP}|${t.attackType}|${t.createdAt?.toISOString()}`;
    threatEventKeyCounts[k] = (threatEventKeyCounts[k] || 0) + 1;
  });
  const dupeThreats = Object.entries(threatEventKeyCounts).filter(([k, v]) => v > 1);
  console.log('Duplicate threats for same event (sourceIP+attackType+createdAt):', dupeThreats.length ? JSON.stringify(dupeThreats) : 'None');

  console.log('\n=== CHECK 7: TIMESTAMPS & TIMEZONE AUDIT ===');
  const collections = ['users', 'authsessions', 'threatlogs', 'honeypotsessions', 'campaigns', 'alerts', 'aipredictions', 'auditlogs'];
  let futureCreatedAt = 0;
  let updatedBeforeCreated = 0;
  let missingTimestamps = 0;

  for (const c of collections) {
    const docs = await db.collection(c).find({}).toArray();
    for (const d of docs) {
      if (!d.createdAt || !d.updatedAt) {
        missingTimestamps++;
      } else {
        const cTime = new Date(d.createdAt).getTime();
        const uTime = new Date(d.updatedAt).getTime();
        if (cTime > Date.now() + 60000) futureCreatedAt++;
        if (uTime < cTime - 1000) updatedBeforeCreated++;
      }
    }
  }
  console.log('Documents with createdAt in the future (>1m):', futureCreatedAt);
  console.log('Documents with updatedAt before createdAt (>1s):', updatedBeforeCreated);
  console.log('Documents missing createdAt or updatedAt:', missingTimestamps);

  console.log('\n=== CHECK 8: AUTH DATA HYGIENE ===');
  const allSessions = await db.collection('authsessions').find({}).toArray();
  const expiredSessions = allSessions.filter(s => new Date(s.expiresAt) <= now);
  const revokedSessions = allSessions.filter(s => s.revokedAt !== null);
  const expiredAndRevoked = allSessions.filter(s => new Date(s.expiresAt) <= now && s.revokedAt !== null);
  const expiredNotRevoked = allSessions.filter(s => new Date(s.expiresAt) <= now && s.revokedAt === null);

  console.log('Total AuthSessions in DB:', allSessions.length);
  console.log('Expired sessions still stored:', expiredSessions.length);
  console.log('Revoked sessions still stored:', revokedSessions.length);
  console.log('Expired AND revoked sessions:', expiredAndRevoked.length);
  console.log('Expired but NOT marked revoked:', expiredNotRevoked.length);
  console.log('Active (valid) sessions:', activeSessions.length);

  // Sessions per user
  const sessionsPerUser = {};
  allSessions.forEach(s => {
    const uid = String(s.user);
    sessionsPerUser[uid] = (sessionsPerUser[uid] || 0) + 1;
  });
  console.log('Sessions count per user:');
  for (const [uid, count] of Object.entries(sessionsPerUser)) {
    const u = userMap.get(uid);
    console.log(`  User ${u ? u.email : 'UNKNOWN (' + uid + ')'}: ${count} sessions stored`);
  }

  // Users password hygiene (counts only, zero hashes)
  let usersNoPassword = 0;
  let usersMustChangePassword = 0;
  let usersNeverLoggedIn = 0;
  for (const u of users) {
    if (!u.password) usersNoPassword++;
    if (u.mustChangePassword) usersMustChangePassword++;
    if (!u.lastLogin && (!u.loginCount || u.loginCount === 0)) usersNeverLoggedIn++;
  }
  console.log('Users with missing password hash:', usersNoPassword);
  console.log('Users flagged mustChangePassword:', usersMustChangePassword);
  console.log('User accounts that have never logged in:', usersNeverLoggedIn);

  await mongoose.disconnect();
}

runAudit().catch(console.error);
