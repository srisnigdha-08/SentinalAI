import http from 'http';
import mongoose from '../backend/node_modules/mongoose/index.js';

function requireEnv(name) {
  const value = process.env[name];
  if (!value || !value.trim()) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

const ADMIN_PASSWORD = requireEnv('VERIFY_ADMIN_PASSWORD');

async function adminRequest(method, endpoint, body = null, token = null, csrfToken = null, cookie = null) {
  return new Promise((resolve, reject) => {
    const postData = body ? JSON.stringify(body) : null;
    const headers = {
      'Content-Type': 'application/json',
      'Origin': 'http://localhost:3000',
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    if (cookie) headers['Cookie'] = cookie;
    if (postData) headers['Content-Length'] = Buffer.byteLength(postData);

    const req = http.request({
      hostname: '127.0.0.1',
      port: 5000,
      path: endpoint,
      method,
      headers
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, body: data });
        }
      });
    });
    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

async function runCleanup() {
  console.log('=== STARTING CONTROLLED DATABASE CLEANUP ===\n');

  await mongoose.connect('mongodb://localhost:27017/sentinel-db');
  const db = mongoose.connection.db;

  // 1. Initial counts
  const before = {
    users: await db.collection('users').countDocuments(),
    honeypotsessions: await db.collection('honeypotsessions').countDocuments(),
    threatlogs: await db.collection('threatlogs').countDocuments(),
    blockedips: await db.collection('blockedips').countDocuments(),
    authsessions: await db.collection('authsessions').countDocuments(),
    auditlogs: await db.collection('auditlogs').countDocuments()
  };
  console.log('BEFORE COUNTS:', JSON.stringify(before, null, 2));

  // Step 2A: Unblock 198.51.100.77 via POST /api/threats/unblock-ip as Admin
  console.log('\n[Step 2A] Unblocking 198.51.100.77 via Admin API...');
  const csrfRes = await adminRequest('GET', '/api/auth/csrf');
  const csrfToken = csrfRes.body?.data?.csrfToken;
  const csrfCookie = (csrfRes.headers['set-cookie'] || []).find(c => c.includes('sentinel_csrf'));

  const loginRes = await adminRequest('POST', '/api/auth/login', {
    email: 'admin@sentinel.io',
    password: ADMIN_PASSWORD
  }, null, csrfToken, csrfCookie);

  const adminToken = loginRes.body?.data?.token;
  if (!adminToken) {
    throw new Error('Admin login failed: ' + JSON.stringify(loginRes.body));
  }

  const unblockRes = await adminRequest('POST', '/api/threats/unblock-ip', {
    ip: '198.51.100.77',
    reason: 'Cleanup pass approved by user'
  }, adminToken, csrfToken, csrfCookie);

  console.log(`  -> Unblock API Response: HTTP ${unblockRes.status}`, JSON.stringify(unblockRes.body));
  if (unblockRes.status !== 200) {
    throw new Error(`Failed to unblock IP via API: ${JSON.stringify(unblockRes.body)}`);
  }

  // Step 2B: Delete honeypotsessions matching ^(audit-live-|sess-analyst-feed-proof)
  console.log('\n[Step 2B] Deleting test honeypotsessions matching ^(audit-live-|sess-analyst-feed-proof)...');
  const hpDeleteRes = await db.collection('honeypotsessions').deleteMany({
    sessionId: { $regex: '^(audit-live-|sess-analyst-feed-proof)' }
  });
  console.log(`  -> Deleted honeypotsessions: ${hpDeleteRes.deletedCount}`);

  // Step 2C: Delete threatlogs matching sourceIP in (203.0.113.195, 198.51.100.77)
  console.log('\n[Step 2C] Deleting test threatlogs matching sourceIP in (203.0.113.195, 198.51.100.77)...');
  const threatDeleteRes = await db.collection('threatlogs').deleteMany({
    sourceIP: { $in: ['203.0.113.195', '198.51.100.77'] }
  });
  console.log(`  -> Deleted threatlogs: ${threatDeleteRes.deletedCount}`);

  // Step 2D: Delete users: testanalyst6866@sentinel.io, plus its authsessions
  console.log('\n[Step 2D] Deleting user testanalyst6866@sentinel.io and its sessions...');
  const targetUser = await db.collection('users').findOne({ email: 'testanalyst6866@sentinel.io' });
  let userSessionDeleteCount = 0;
  let userDeleteCount = 0;
  if (targetUser) {
    const sRes = await db.collection('authsessions').deleteMany({ user: targetUser._id });
    userSessionDeleteCount = sRes.deletedCount;
    const uRes = await db.collection('users').deleteOne({ _id: targetUser._id });
    userDeleteCount = uRes.deletedCount;
  }
  console.log(`  -> Deleted test user: ${userDeleteCount}, deleted user sessions: ${userSessionDeleteCount}`);

  // Step 2E: Delete authsessions: revokedAt not null OR expiresAt in the past
  console.log('\n[Step 2E] Deleting expired or revoked authsessions...');
  const now = new Date();
  const authSessionDeleteRes = await db.collection('authsessions').deleteMany({
    $or: [
      { revokedAt: { $ne: null } },
      { expiresAt: { $lt: now } }
    ]
  });
  console.log(`  -> Deleted expired/revoked authsessions: ${authSessionDeleteRes.deletedCount}`);

  // 3. Final counts
  const after = {
    users: await db.collection('users').countDocuments(),
    honeypotsessions: await db.collection('honeypotsessions').countDocuments(),
    threatlogs: await db.collection('threatlogs').countDocuments(),
    blockedips: await db.collection('blockedips').countDocuments(),
    authsessions: await db.collection('authsessions').countDocuments(),
    auditlogs: await db.collection('auditlogs').countDocuments()
  };
  console.log('\nAFTER COUNTS:', JSON.stringify(after, null, 2));

  // 4. Verification of untouchables & expected values
  console.log('\n=== VERIFICATION OF UNTOUCHABLES & CONSTRAINTS ===');

  // Verify demo sessions
  const demoSessions = await db.collection('honeypotsessions').find({ sessionId: { $regex: '^demo-' } }).toArray();
  console.log(`  -> demo-* honeypot sessions preserved: ${demoSessions.length} (Expected: 7)`);

  // Verify 172.18.0.1 records
  const ip172Sessions = await db.collection('honeypotsessions').find({ sourceIP: '172.18.0.1' }).toArray();
  const ip172Threats = await db.collection('threatlogs').find({ sourceIP: '172.18.0.1' }).toArray();
  console.log(`  -> 172.18.0.1 honeypot sessions: ${ip172Sessions.length} (Expected: 1)`);
  console.log(`  -> 172.18.0.1 threats: ${ip172Threats.length} (Expected: 1)`);

  // Verify retained threats for decision: 198.51.100.88 and 192.168.100.99
  const retainedThreats = await db.collection('threatlogs').find({
    sourceIP: { $in: ['198.51.100.88', '192.168.100.99'] }
  }).toArray();
  console.log(`  -> Retained decision threats count: ${retainedThreats.length} (Expected: 2)`);
  for (const t of retainedThreats) {
    console.log(`     - [${t._id}] ${t.sourceIP} (${t.attackType}, ${t.status})`);
  }

  // Verify remaining users
  const remainingUsers = await db.collection('users').find({}, { projection: { email: 1, role: 1 } }).toArray();
  console.log(`  -> Remaining users (${remainingUsers.length}):`, remainingUsers.map(u => `${u.email} [${u.role}]`).join(', '));

  await mongoose.disconnect();

  console.log('\n=== CLEANUP COMPLETED SUCCESSFULLY ===');
}

runCleanup().catch((err) => {
  console.error('\n[CLEANUP FAILED]:', err);
  process.exit(1);
});
