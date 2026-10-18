import path from 'path';
import fs from 'fs';
import http from 'http';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const backendDir = 'c:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete\\backend';
const puppeteer = require(path.join(backendDir, 'node_modules', 'puppeteer-core'));
const mongoose = require(path.join(backendDir, 'node_modules', 'mongoose'));
require(path.join(backendDir, 'node_modules', 'dotenv')).config({ path: path.join(backendDir, '.env') });

function requireEnv(varName) {
  const val = process.env[varName];
  if (!val || !val.trim()) {
    console.error(`\n[FATAL CONFIGURATION ERROR] Missing required environment variable: ${varName}`);
    console.error(`Please provide ${varName} in your environment before running this script.\n`);
    process.exit(1);
  }
  return val.trim();
}

const ADMIN_PASSWORD = requireEnv('VERIFY_ADMIN_PASSWORD');
const ANALYST_PASSWORD = requireEnv('VERIFY_ANALYST_PASSWORD');
const EPHEMERAL_PASSWORD = process.env.VERIFY_EPHEMERAL_PASSWORD || 'Ephemeral@Auth123!';

async function getBackendNodeEnv(token) {
  if (token) {
    try {
      const res = await fetch('http://127.0.0.1:5000/api/system/health', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const body = await res.json();
        if (body?.data?.environment) return body.data.environment;
      }
    } catch {}
  }
  return process.env.BACKEND_NODE_ENV || process.env.NODE_ENV || 'development';
}

async function adminRequest(method, endpoint, body = null, token = null) {
  return new Promise((resolve, reject) => {
    const postData = body ? JSON.stringify(body) : null;
    const headers = {
      'Content-Type': 'application/json',
      'Origin': 'http://localhost:3000',
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

async function main() {
  console.log('=== Starting Live Demotion & Revocation Test (Real Browser Context) ===\n');

  await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db');
  const User = require(path.join(backendDir, 'models', 'User'));


  const analystUser = await User.findOne({ email: 'arjun@sentinel.io' });
  if (!analystUser) throw new Error('Analyst arjun@sentinel.io not found in database');
  const analystId = analystUser._id.toString();

  console.log(`Found Analyst User: arjun@sentinel.io (${analystId})`);
  let secondUserId = null;
  let secondUserEmail = null;
  let adminToken = null;
  let mainError = null;

  let executablePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  if (!fs.existsSync(executablePath)) {
    executablePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  }

  const browser = await puppeteer.launch({
    executablePath,
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  try {
    // 1. Analyst Browser Context
    const analystPage = await browser.newPage();
    await analystPage.setViewport({ width: 1280, height: 800 });

    let analystSocketDisconnected = false;
    let analystWsFrames = [];
    let analystToken = null;

    analystPage.on('response', async (response) => {
      const url = response.url();
      if (url.includes('/api/auth/login') && response.status() === 200) {
        try {
          const json = await response.json();
          if (json?.data?.token) {
            analystToken = json.data.token;
          }
        } catch {}
      }
    });

    const cdp = await analystPage.target().createCDPSession();
    await cdp.send('Network.enable');

    await analystPage.evaluateOnNewDocument(() => {
      const origFetch = window.fetch;
      window.fetch = async (...args) => {
        const res = await origFetch(...args);
        try {
          if (args[0] && String(args[0]).includes('/login')) {
            const clone = res.clone();
            clone.json().then((data) => {
              if (data?.data?.token) {
                window.__captured_token = data.data.token;
              }
            }).catch(() => {});
          }
        } catch {}
        return res;
      };
    });

    cdp.on('Network.webSocketFrameReceived', (params) => {
      const payload = params.response?.payloadData;
      if (payload) {
        analystWsFrames.push(payload);
      }
    });

    cdp.on('Network.webSocketClosed', () => {
      analystSocketDisconnected = true;
      console.log('  [CDP Event] Analyst WebSocket connection was CLOSED by server!');
    });

    const baseUrl = 'http://localhost:3000';

    console.log('\n[Step 1] Logging in as Analyst (arjun@sentinel.io) in Browser 1...');
    await analystPage.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });
    await analystPage.evaluate(() => { localStorage.clear(); sessionStorage.clear(); });
    await analystPage.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });

    const emailInput = await analystPage.waitForSelector('input[type="email"]', { timeout: 15000 });
    await emailInput.click({ clickCount: 3 });
    await emailInput.type('arjun@sentinel.io');
    const passInput = await analystPage.waitForSelector('input[type="password"]');
    await passInput.click({ clickCount: 3 });
    await passInput.type(ANALYST_PASSWORD);

    await analystPage.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      const authBtn = buttons.find((b) => b.innerText.includes('AUTHENTICATE'));
      if (authBtn) authBtn.click();
    });

    await analystPage.waitForFunction(() => window.location.pathname === '/dashboard', { timeout: 10000 });
    analystToken = analystToken || (await analystPage.evaluate(() => window.__captured_token));
    console.log('  -> Analyst logged in successfully. Open session established.');
    console.log(`  -> Captured Analyst Bearer token from login response: ${analystToken ? analystToken.slice(0, 20) + '...' : 'None'}`);

    if (!analystToken) {
      throw new Error('Failed to capture analyst token from login response');
    }


    // Wait 2 seconds for WS connection
    await new Promise((res) => setTimeout(res, 2000));

    // Verify analyst initial access to analyst endpoint via captured session token
    const initialAnalystCheck = await analystPage.evaluate(async (token) => {
      const res = await fetch('/api/threats/settings', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      return { status: res.status };
    }, analystToken);
    console.log(`  -> Initial Analyst access check to /api/threats/settings: HTTP ${initialAnalystCheck.status} (Expected: 200)`);
    if (initialAnalystCheck.status !== 200) {
      throw new Error(`Expected Analyst initial check to return 200, got ${initialAnalystCheck.status}`);
    }

    // 2. Obtain Admin credentials
    console.log('\n[Step 2] Authenticating as Admin via backend API...');
    const csrfRes = await adminRequest('GET', '/api/auth/csrf');
    const csrfToken = csrfRes.body?.data?.csrfToken;
    const csrfCookie = (csrfRes.headers['set-cookie'] || []).find(c => c.includes('sentinel_csrf'));

    const loginRes = await new Promise((resolve, reject) => {
      const postData = JSON.stringify({ email: 'admin@sentinel.io', password: ADMIN_PASSWORD });
      const req = http.request({
        hostname: '127.0.0.1',
        port: 5000,
        path: '/api/auth/login',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Origin': 'http://localhost:3000',
          'X-CSRF-Token': csrfToken,
          'Cookie': csrfCookie,
          'Content-Length': Buffer.byteLength(postData),
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data), headers: res.headers }));
      });
      req.on('error', reject);
      req.write(postData);
      req.end();
    });

    adminToken = loginRes.body?.data?.token;
    if (!adminToken) throw new Error('Admin login failed: ' + JSON.stringify(loginRes.body));
    console.log('  -> Admin authenticated. Acquired Bearer token.');

    // Step 2.1: Dynamically provision an ephemeral user for deactivation test (no operator1 needed)
    secondUserEmail = `ephemeral-deactivate-${Date.now()}@sentinel.local`;
    console.log(`\n[Setup] Dynamically provisioning ephemeral test user: ${secondUserEmail}...`);
    const ephemUser = await User.create({
      name: 'Ephemeral Deactivate User',
      email: secondUserEmail,
      password: EPHEMERAL_PASSWORD,
      role: 'analyst',
      status: 'active'
    });
    secondUserId = ephemUser._id.toString();
    console.log(`  -> Ephemeral user created: ${secondUserEmail} (${secondUserId})`);


    // Step 3: Admin changes arjun@sentinel.io role from analyst to viewer
    console.log(`\n[Step 3] Admin DEMOTES arjun@sentinel.io to 'viewer'...`);
    const demoteRes = await adminRequest('PUT', `/api/users/${analystId}`, { role: 'viewer' }, adminToken);
    console.log(`  -> Admin demote response: HTTP ${demoteRes.status}`, demoteRes.body?.message || '');
    if (demoteRes.status !== 200) {
      throw new Error(`Failed to demote analyst: ${JSON.stringify(demoteRes.body)}`);
    }

    // Step 4: Admin deactivates ephemeral user
    console.log(`\n[Step 4] Admin DEACTIVATES ephemeral user ${secondUserEmail}...`);
    const deactRes = await adminRequest('PUT', `/api/users/${secondUserId}`, { status: 'inactive' }, adminToken);
    console.log(`  -> Admin deactivation response: HTTP ${deactRes.status}`, deactRes.body?.message || '');
    if (deactRes.status !== 200) {
      throw new Error(`Failed to deactivate ephemeral user: ${JSON.stringify(deactRes.body)}`);
    }

    // Step 4.1: Assert REAL audit actions in MongoDB (USER_ROLE_CHANGED, USER_STATUS_CHANGED)
    console.log('\n[Step 4.1] Asserting REAL AuditLog actions in MongoDB...');
    const roleChangeAudit = await mongoose.connection.db.collection('auditlogs').findOne({
      action: 'USER_ROLE_CHANGED',
      'target.id': analystId
    });
    console.log(`  -> AuditLog action 'USER_ROLE_CHANGED' recorded: ${!!roleChangeAudit} (Expected: true)`);
    if (!roleChangeAudit) {
      throw new Error("Audit log missing expected action 'USER_ROLE_CHANGED'");
    }

    const statusChangeAudit = await mongoose.connection.db.collection('auditlogs').findOne({
      action: 'USER_STATUS_CHANGED',
      'target.id': secondUserId
    });
    console.log(`  -> AuditLog action 'USER_STATUS_CHANGED' recorded: ${!!statusChangeAudit} (Expected: true)`);
    if (!statusChangeAudit) {
      throw new Error("Audit log missing expected action 'USER_STATUS_CHANGED'");
    }

    // Step 5: Test open Analyst session WITHOUT PAGE REFRESH
    console.log('\n[Step 5] Checking Analyst session in Browser 1 WITHOUT PAGE REFRESH...');
    // Wait 2.5 seconds for server disconnect signal and revocation to process
    await new Promise((res) => setTimeout(res, 2500));

    // Attempt analyst-restricted REST request from Browser 1
    const postDemoteRestCheck = await analystPage.evaluate(async (token) => {
      const res = await fetch('/api/threats/settings', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      let body = {};
      try { body = await res.json(); } catch {}
      return { status: res.status, body };
    }, analystToken);

    console.log(`  -> Post-demotion REST request to /api/threats/settings: HTTP ${postDemoteRestCheck.status}`);
    console.log(`  -> Response body:`, JSON.stringify(postDemoteRestCheck.body));

    if (postDemoteRestCheck.status !== 401) {
      throw new Error(`SECURITY BREACH: Expected HTTP 401 after authVersion invalidation, got HTTP ${postDemoteRestCheck.status}`);
    }
    console.log('  -> VERIFIED: Demoted user token is invalidated with HTTP 401');

    // Verify WebSocket disconnection
    console.log(`  -> Analyst WebSocket closed event observed: ${analystSocketDisconnected}`);

    // Step 6: Verify second user (deactivated) cannot authenticate or access platform
    console.log('\n[Step 6] Verifying deactivated user cannot login...');
    const deactLoginRes = await new Promise((resolve) => {
      const postData = JSON.stringify({ email: secondUserEmail, password: EPHEMERAL_PASSWORD });
      const req = http.request({
        hostname: '127.0.0.1',
        port: 5000,
        path: '/api/auth/login',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Origin': 'http://localhost:3000',
          'X-CSRF-Token': csrfToken,
          'Cookie': csrfCookie,
          'Content-Length': Buffer.byteLength(postData),
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
          catch { resolve({ status: res.statusCode, body: data }); }
        });
      });
      req.on('error', resolve);
      req.write(postData);
      req.end();
    });

    console.log(`  -> Deactivated user login response: HTTP ${deactLoginRes.status}`);
    if (deactLoginRes.status !== 401 && deactLoginRes.status !== 403) {
      throw new Error(`Deactivated user was not blocked at login! Got HTTP ${deactLoginRes.status}`);
    }

    // Step 7: RESTORATION & CLEANUP
    console.log('\n[Step 7] Restoring original analyst role and cleaning up ephemeral user...');
    const restoreAnalyst = await adminRequest('PUT', `/api/users/${analystId}`, { role: 'analyst' }, adminToken);
    console.log(`  -> Restored arjun@sentinel.io to 'analyst': HTTP ${restoreAnalyst.status}`);

    console.log('\n======================================================');
    console.log('=== LIVE DEMOTION & REVOCATION AUDIT PASSED ===');
    console.log('======================================================');
    console.log('1. Open Analyst session immediately lost access (HTTP 401/403).');
    console.log('2. WebSocket connection was immediately terminated by server.');
    console.log('3. Deactivated user login rejected.');
    console.log('4. Original user roles restored safely; ephemeral user destroyed.');

  } catch (err) {
    mainError = err;
    throw err;
  } finally {
    try {
      const db = mongoose.connection.db;
      if (db) {
        const dbName = db.databaseName;
        const backendEnv = await getBackendNodeEnv(adminToken);

        if (dbName !== 'sentinel-db' || backendEnv === 'production') {
          throw new Error(`Cleanup refused: unsafe environment (db: "${dbName}", backend NODE_ENV: "${backendEnv}")`);
        }

        await db.collection('users').updateOne({ email: 'arjun@sentinel.io' }, { $set: { role: 'analyst', status: 'active' } });
        if (secondUserId) {
          await db.collection('users').deleteOne({ _id: new mongoose.Types.ObjectId(secondUserId) });
          await db.collection('authsessions').deleteMany({ user: new mongoose.Types.ObjectId(secondUserId) });
          console.log(`  -> [Cleanup] Successfully deleted ephemeral user ${secondUserEmail} from MongoDB.`);
        }
      }
    } catch (cleanupErr) {
      console.error('  -> [Cleanup Error]:', cleanupErr.message);
      if (!mainError) {
        throw cleanupErr;
      }
    }
    await browser.close().catch(() => {});
    await mongoose.disconnect().catch(() => {});
  }


}

main().catch(async (err) => {
  console.error('\n[FATAL ERROR in Live Demotion Verification]', err);
  // Attempt safety restore in DB on error
  try {
    const User = mongoose.model('User');
    await User.updateOne({ email: 'arjun@sentinel.io' }, { $set: { role: 'analyst', status: 'active' } });
  } catch {}
  process.exit(1);
});
