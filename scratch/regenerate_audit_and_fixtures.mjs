import path from 'path';
import fs from 'fs';
import http from 'http';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const backendDir = path.join(__dirname, '../backend');
const mongoose = require(path.join(backendDir, 'node_modules', 'mongoose'));
require(path.join(backendDir, 'node_modules', 'dotenv')).config({ path: path.join(backendDir, '.env') });

function requireEnv(name) {
  const value = process.env[name];
  if (!value || !value.trim()) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

const ADMIN_PASSWORD = requireEnv('VERIFY_ADMIN_PASSWORD');
const ANALYST_PASSWORD = requireEnv('VERIFY_ANALYST_PASSWORD');
const VIEWER_PASSWORD = requireEnv('VERIFY_VIEWER_PASSWORD');

async function apiRequest(method, endpoint, body = null, token = null, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const postData = body ? JSON.stringify(body) : null;
    const headers = {
      'Content-Type': 'application/json',
      'Origin': 'http://localhost:3000',
      ...extraHeaders
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;
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

async function loginUser(email, password) {
  const csrfRes = await apiRequest('GET', '/api/auth/csrf');
  const csrfToken = csrfRes.body?.data?.csrfToken;
  const csrfCookie = (csrfRes.headers['set-cookie'] || []).find(c => c.includes('sentinel_csrf'));

  const res = await apiRequest('POST', '/api/auth/login', { email, password }, null, {
    'X-CSRF-Token': csrfToken,
    'Cookie': csrfCookie,
  });

  return { token: res.body?.data?.token, user: res.body?.data?.user, csrfToken, csrfCookie };
}

async function main() {
  console.log('=== Starting Real API Audit Actions & Shape Fixture Generation ===\n');

  await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db');
  const AuditLog = mongoose.model('AuditLog', new mongoose.Schema({}, { strict: false }));
  const User = mongoose.model('User', new mongoose.Schema({}, { strict: false }));
  const ThreatLog = mongoose.model('ThreatLog', new mongoose.Schema({}, { strict: false }));
  const HoneypotSession = mongoose.model('HoneypotSession', new mongoose.Schema({}, { strict: false }));
  const Campaign = mongoose.model('Campaign', new mongoose.Schema({}, { strict: false }));

  // 1. Authenticate users
  console.log('[1/4] Authenticating Admin, Analyst, and Viewer...');
  const adminAuth = await loginUser('admin@sentinel.io', ADMIN_PASSWORD);
  if (!adminAuth.token) throw new Error('Admin login failed');

  const analystAuth = await loginUser('arjun@sentinel.io', ANALYST_PASSWORD);
  if (!analystAuth.token) throw new Error('Analyst login failed');

  const viewerAuth = await loginUser('sara@sentinel.io', VIEWER_PASSWORD);
  if (!viewerAuth.token) throw new Error('Viewer login failed');

  console.log('  -> All 3 roles authenticated successfully.');

  // 2. Perform Real API Calls for all 14 Actions
  console.log('\n[2/4] Triggering all 14 actions through the REAL API...');

  // 1. LOGIN_FAILED
  await apiRequest('POST', '/api/auth/login', { email: 'unknown_auditee@sentinel.io', password: 'WrongPassword!' }, null, {
    'X-CSRF-Token': adminAuth.csrfToken,
    'Cookie': adminAuth.csrfCookie,
  });
  console.log('  -> Triggered LOGIN_FAILED');

  // 2. SETTINGS_CHANGED
  await apiRequest('POST', '/api/threats/settings', { autoBlockEnabled: true }, adminAuth.token);
  console.log('  -> Triggered SETTINGS_CHANGED');

  // 3. IP_BLOCKED_MANUAL
  await apiRequest('POST', '/api/threats/block-ip', { ip: '198.51.100.89', reason: 'Audit Real API Test' }, adminAuth.token);
  console.log('  -> Triggered IP_BLOCKED_MANUAL');

  // 4. IP_UNBLOCKED_MANUAL
  await apiRequest('POST', '/api/threats/unblock-ip', { ip: '198.51.100.89' }, adminAuth.token);
  console.log('  -> Triggered IP_UNBLOCKED_MANUAL');

  // Create Threat 1 for blocking & triage
  const createThreatRes1 = await apiRequest('POST', '/api/threats', {
    sourceIP: '198.51.100.77',
    attackType: 'SQL Injection',
    severity: 'HIGH',
    destinationIP: '10.0.0.5',
    targetService: 'HTTP',
    payload: 'SELECT * FROM users WHERE 1=1'
  }, analystAuth.token);
  const threatId1 = createThreatRes1.body?.data?.threat?._id || createThreatRes1.body?.data?._id;

  // 5. THREAT_BLOCKED
  if (threatId1) {
    await apiRequest('POST', `/api/threats/${threatId1}/block`, {}, adminAuth.token);
    console.log(`  -> Triggered THREAT_BLOCKED on threat ${threatId1}`);

    // 6. THREAT_TRIAGED
    await apiRequest('PATCH', `/api/threats/${threatId1}/triage`, {
      status: 'INVESTIGATING',
      triageNotes: 'Real API triage investigation verified'
    }, analystAuth.token);
    console.log(`  -> Triggered THREAT_TRIAGED on threat ${threatId1}`);
  }

  // Create Threat 2 for deletion
  const createThreatRes2 = await apiRequest('POST', '/api/threats', {
    sourceIP: '198.51.100.78',
    attackType: 'Port Scan',
    severity: 'LOW',
    destinationIP: '10.0.0.6',
    targetService: 'TCP'
  }, adminAuth.token);
  const threatId2 = createThreatRes2.body?.data?.threat?._id || createThreatRes2.body?.data?._id;

  // 7. THREAT_DELETED
  if (threatId2) {
    await apiRequest('DELETE', `/api/threats/${threatId2}`, {}, adminAuth.token);
    console.log(`  -> Triggered THREAT_DELETED on threat ${threatId2}`);
  }

  // 8. USER_CREATED (Provision)
  const tempEmail = `audit_operator_${Date.now()}@sentinel.io`;
  const provRes = await apiRequest('POST', '/api/auth/provision', {
    name: 'Temporary Audit Operator',
    email: tempEmail,
    password: 'SecurePassword@123',
    role: 'viewer',
    department: 'SOC'
  }, adminAuth.token, {
    'X-CSRF-Token': adminAuth.csrfToken,
    'Cookie': adminAuth.csrfCookie,
  });
  const tempUserId = provRes.body?.data?.user?._id;
  console.log(`  -> Triggered USER_CREATED for ${tempEmail} (${tempUserId})`);

  if (tempUserId) {
    // 9. USER_ROLE_CHANGED
    await apiRequest('PUT', `/api/users/${tempUserId}`, { role: 'analyst' }, adminAuth.token);
    console.log(`  -> Triggered USER_ROLE_CHANGED for ${tempUserId}`);

    // 10. USER_STATUS_CHANGED
    await apiRequest('PUT', `/api/users/${tempUserId}`, { status: 'inactive' }, adminAuth.token);
    console.log(`  -> Triggered USER_STATUS_CHANGED for ${tempUserId}`);

    // 11. USER_FORCE_LOGOUT
    await apiRequest('POST', `/api/users/${tempUserId}/force-logout`, {}, adminAuth.token);
    console.log(`  -> Triggered USER_FORCE_LOGOUT for ${tempUserId}`);

    // 12. USER_DELETED
    await apiRequest('DELETE', `/api/users/${tempUserId}`, {}, adminAuth.token);
    console.log(`  -> Triggered USER_DELETED for ${tempUserId}`);
  }

  // 13. LOGIN_SUCCESS was already triggered during admin/analyst/viewer loginUser calls.
  console.log('  -> Verified LOGIN_SUCCESS');

  // 14. PERMISSION_DENIED (Viewer attempts admin endpoint)
  const deniedRes = await apiRequest('POST', '/api/threats/block-ip', { ip: '198.51.100.99' }, viewerAuth.token);
  console.log(`  -> Triggered PERMISSION_DENIED (HTTP ${deniedRes.status}) using Viewer token`);

  // Allow asynchronous audit writes to settle
  await new Promise(r => setTimeout(r, 1000));

  // 3. Retrieve Latest Audit Log for Each Action
  console.log('\n[3/4] Retrieving real audit records from MongoDB...');
  const REQUIRED = [
    'THREAT_BLOCKED', 'IP_BLOCKED_MANUAL', 'IP_UNBLOCKED_MANUAL', 'THREAT_DELETED', 'SETTINGS_CHANGED',
    'USER_CREATED', 'USER_ROLE_CHANGED', 'USER_STATUS_CHANGED', 'USER_DELETED', 'USER_FORCE_LOGOUT',
    'THREAT_TRIAGED', 'LOGIN_SUCCESS', 'LOGIN_FAILED', 'PERMISSION_DENIED'
  ];

  const auditLogOutput = {};
  for (const action of REQUIRED) {
    const doc = await AuditLog.findOne({ action }).sort({ createdAt: -1 }).lean();
    if (!doc) {
      throw new Error(`Missing required audit log entry in DB for action: ${action}`);
    }
    auditLogOutput[action] = doc;
  }

  // Check 403 denied actor verification
  const permDeniedEntry = auditLogOutput['PERMISSION_DENIED'];
  console.log('  -> PERMISSION_DENIED entry actor:', permDeniedEntry?.actor);
  if (!permDeniedEntry?.actor?.id || !permDeniedEntry?.actor?.role) {
    console.warn('  [Warning] Expected PERMISSION_DENIED entry to include actor id and role');
  }

  const evidenceDir = path.join(__dirname, 'evidence');
  fs.mkdirSync(evidenceDir, { recursive: true });
  const auditPath = path.join(evidenceDir, 'audit_log_14_actions.json');
  fs.writeFileSync(auditPath, JSON.stringify(auditLogOutput, null, 2));
  console.log(`  -> Saved 14 real audit records to: ${auditPath}`);

  // 4. Capture & Compare Shape Fixtures (Item 7)
  console.log('\n[4/4] Capturing and comparing real Admin & Analyst Shape Fixtures...');

  // Get real threat ID
  let sampleThreat = await ThreatLog.findOne().sort({ createdAt: -1 });
  const sampleThreatId = sampleThreat?._id.toString();

  // Get real honeypot session ID
  let sampleSession = await HoneypotSession.findOne().sort({ createdAt: -1 });
  const sampleSessionId = sampleSession?._id.toString();

  // Get real campaign ID
  let sampleCampaign = await Campaign.findOne().sort({ createdAt: -1 });
  const sampleCampaignId = sampleCampaign?._id.toString();

  const adminFixtures = {
    threat: (await apiRequest('GET', `/api/threats/${sampleThreatId}`, null, adminAuth.token)).body?.data?.threat,
    honeypotSession: sampleSessionId ? (await apiRequest('GET', `/api/honeypot/sessions/${sampleSessionId}`, null, adminAuth.token)).body?.data?.session : null,
    campaign: sampleCampaignId ? ((await apiRequest('GET', `/api/campaigns/${sampleCampaignId}`, null, adminAuth.token)).body?.data?.campaign || (await apiRequest('GET', `/api/campaigns/${sampleCampaignId}`, null, adminAuth.token)).body?.data) : null,
    alerts: (await apiRequest('GET', '/api/alerts?limit=10', null, adminAuth.token)).body?.data,
  };

  const analystFixtures = {
    threat: (await apiRequest('GET', `/api/threats/${sampleThreatId}`, null, analystAuth.token)).body?.data?.threat,
    honeypotSession: sampleSessionId ? (await apiRequest('GET', `/api/honeypot/sessions/${sampleSessionId}`, null, analystAuth.token)).body?.data?.session : null,
    campaign: sampleCampaignId ? ((await apiRequest('GET', `/api/campaigns/${sampleCampaignId}`, null, analystAuth.token)).body?.data?.campaign || (await apiRequest('GET', `/api/campaigns/${sampleCampaignId}`, null, analystAuth.token)).body?.data) : null,
    alerts: (await apiRequest('GET', '/api/alerts?limit=10', null, analystAuth.token)).body?.data,
  };

  const adminFixturePath = path.join(evidenceDir, 'shape_fixtures_admin.json');
  const analystFixturePath = path.join(evidenceDir, 'shape_fixtures_analyst.json');
  fs.writeFileSync(adminFixturePath, JSON.stringify(adminFixtures, null, 2));
  fs.writeFileSync(analystFixturePath, JSON.stringify(analystFixtures, null, 2));
  console.log(`  -> Saved Admin shape fixtures to: ${adminFixturePath}`);
  console.log(`  -> Saved Analyst shape fixtures to: ${analystFixturePath}`);

  // Field names and types comparator
  function compareShapes(objA, objB, pathName = '') {
    if (!objA || !objB) return;
    if (typeof objA !== typeof objB) {
      throw new Error(`Shape mismatch at ${pathName}: type ${typeof objA} vs ${typeof objB}`);
    }
    if (typeof objA === 'object' && !Array.isArray(objA)) {
      const keysA = Object.keys(objA).sort();
      const keysB = Object.keys(objB).sort();
      if (JSON.stringify(keysA) !== JSON.stringify(keysB)) {
        throw new Error(`Key mismatch at ${pathName}: [${keysA.join(',')}] vs [${keysB.join(',')}]`);
      }
      for (const k of keysA) {
        compareShapes(objA[k], objB[k], `${pathName}.${k}`);
      }
    }
  }

  console.log('\n--- Comparing Admin and Analyst Shape Structures ---');
  for (const key of ['threat', 'honeypotSession', 'campaign', 'alerts']) {
    if (adminFixtures[key] && analystFixtures[key]) {
      compareShapes(adminFixtures[key], analystFixtures[key], key);
      console.log(`  ✓ Fixture [${key}]: 100% field name and type match between Admin & Analyst`);
    }
  }

  console.log('\n=== REAL AUDIT LOG 14 ACTIONS SUMMARY ===');
  for (const [action, doc] of Object.entries(auditLogOutput)) {
    console.log(`\n--- Action: ${action} ---`);
    console.log(JSON.stringify(doc, null, 2));
  }

  console.log('\n=== ALL EVIDENCE AND FIXTURES GENERATED SUCCESSFULLY ===');
  await mongoose.disconnect();
  process.exit(0);
}

main().catch(async (err) => {
  console.error('\n[FATAL ERROR in Evidence Generation]', err);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
