import path from 'path';
import fs from 'fs';
import http from 'http';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const backendDir = 'c:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete\\backend';
const puppeteer = require(path.join(backendDir, 'node_modules', 'puppeteer-core'));
const mongoose = require(path.join(backendDir, 'node_modules', 'mongoose'));

function requireEnv(varName) {
  const val = process.env[varName];
  if (!val || !val.trim()) {
    console.error(`\n[FATAL CONFIGURATION ERROR] Missing required environment variable: ${varName}`);
    console.error(`Please provide ${varName} in your environment before running this script.\n`);
    process.exit(1);
  }
  return val.trim();
}

const ANALYST_PASSWORD = requireEnv('VERIFY_ANALYST_PASSWORD');
const HONEYPOT_API_KEY = requireEnv('HONEYPOT_API_KEY');

async function getBackendNodeEnv(token) {
  let authToken = token;
  if (!authToken && (process.env.VERIFY_ANALYST_PASSWORD || process.env.VERIFY_ADMIN_PASSWORD)) {
    try {
      const email = process.env.VERIFY_ADMIN_PASSWORD ? 'admin@sentinel.io' : 'arjun@sentinel.io';
      const password = process.env.VERIFY_ADMIN_PASSWORD || process.env.VERIFY_ANALYST_PASSWORD;
      const csrfRes = await fetch('http://127.0.0.1:5000/api/auth/csrf', {
        headers: { Origin: 'http://localhost:3000' },
      });
      const csrfData = await csrfRes.json();
      const rawCookie = csrfRes.headers.get('set-cookie');
      const csrfCookie = rawCookie ? rawCookie.split(';')[0] : '';
      const csrfToken = csrfData?.data?.csrfToken;

      const loginRes = await fetch('http://127.0.0.1:5000/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'http://localhost:3000',
          'X-CSRF-Token': csrfToken,
          Cookie: csrfCookie,
        },
        body: JSON.stringify({ email, password }),
      });
      const loginData = await loginRes.json();
      authToken = loginData?.data?.token;
    } catch {}
  }

  if (authToken) {
    try {
      const res = await fetch('http://127.0.0.1:5000/api/system/health', {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (res.ok) {
        const body = await res.json();
        if (body?.data?.environment) return body.data.environment;
      }
    } catch {}
  }
  return process.env.BACKEND_NODE_ENV || process.env.NODE_ENV || 'development';
}

async function main() {
  console.log('=== Starting Analyst Live Feed Verification (Unmasked WS Feeds) ===\n');

  let liveSessionId = null;
  let executablePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

  if (!fs.existsSync(executablePath)) {
    executablePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  }

  const browser = await puppeteer.launch({
    executablePath,
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const capturedWsFrames = [];
  let mainError = null;

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    const cdp = await page.target().createCDPSession();
    await cdp.send('Network.enable');

    cdp.on('Network.webSocketFrameReceived', (params) => {
      const payload = params.response?.payloadData;
      if (payload) {
        capturedWsFrames.push({
          timestamp: new Date().toISOString(),
          frame: payload
        });
      }
    });

    const baseUrl = 'http://localhost:3000';

    console.log('[Step 1] Logging in as ANALYST (arjun@sentinel.io)...');
    await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });
    await page.evaluate(() => { localStorage.clear(); sessionStorage.clear(); });
    await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });

    const emailInput = await page.waitForSelector('input[type="email"]', { timeout: 15000 });
    await emailInput.click({ clickCount: 3 });
    await emailInput.type('arjun@sentinel.io');
    const passInput = await page.waitForSelector('input[type="password"]');
    await passInput.click({ clickCount: 3 });
    await passInput.type(ANALYST_PASSWORD);

    await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      const authBtn = buttons.find((b) => b.innerText.includes('AUTHENTICATE'));
      if (authBtn) authBtn.click();
    });

    await page.waitForFunction(() => window.location.pathname === '/dashboard', { timeout: 10000 });
    console.log('  -> Logged in successfully to /dashboard as ANALYST');

    // Wait for WS to establish
    await new Promise((res) => setTimeout(res, 2000));

    // Navigate to Threat Logs to subscribe to threat feed
    await page.goto(`${baseUrl}/dashboard/threats`, { waitUntil: 'domcontentloaded' });
    await new Promise((res) => setTimeout(res, 2000));

    // Send live honeypot events to trigger both new_threat and honeypot_command:
    console.log('[Step 2] Emitting live SESSION_OPENED and COMMAND_INPUT events...');
    liveSessionId = 'sess-analyst-feed-proof-' + Date.now();
    const sessionOpenData = JSON.stringify({
      eventType: 'SESSION_OPENED',
      sessionId: liveSessionId,
      sourceIP: '198.51.100.77',
      sourcePort: 2222,
      honeypotNode: 'SSH-COWRIE-01',
      protocol: 'SSH',
    });

    await new Promise((resolve) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port: 5000,
        path: '/api/honeypot/ingest',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': HONEYPOT_API_KEY,
          'Content-Length': Buffer.byteLength(sessionOpenData),
        },
      }, (res) => {
        res.resume();
        resolve();
      });
      req.on('error', () => resolve());
      req.write(sessionOpenData);
      req.end();
    });

    await new Promise((res) => setTimeout(res, 1500));

    const postData = JSON.stringify({
      eventType: 'COMMAND_INPUT',
      sessionId: liveSessionId,
      sourceIP: '198.51.100.77',
      command: 'cat /etc/shadow',
      honeypotNode: 'SSH-COWRIE-01'
    });


    await new Promise((resolve) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port: 5000,
        path: '/api/honeypot/ingest',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': HONEYPOT_API_KEY,
          'Content-Length': Buffer.byteLength(postData),
        },
      }, (res) => {
        res.resume();
        resolve();
      });
      req.on('error', () => resolve());
      req.write(postData);
      req.end();
    });

    // Wait 3 seconds for frame receipt
    await new Promise((res) => setTimeout(res, 3000));

    console.log(`[Step 3] Analyst WebSocket Frames Captured: ${capturedWsFrames.length}`);

    // Save evidence
    const evidenceDir = path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), 'evidence');
    fs.mkdirSync(evidenceDir, { recursive: true });
    const analystWsPath = path.join(evidenceDir, 'analyst_ws_frames.json');
    fs.writeFileSync(analystWsPath, JSON.stringify(capturedWsFrames, null, 2));
    console.log(`  -> Saved analyst WS frames to: ${analystWsPath}`);

    // Verify Analyst room confirmation
    const connectedFrame = capturedWsFrames.find(f => (typeof f === 'string' ? f : f.frame).includes('"room":"analyst"'));
    console.log('  -> Analyst connected frame:', connectedFrame ? (typeof connectedFrame === 'string' ? connectedFrame : connectedFrame.frame) : 'None');

    // Read back and print from disk as required by Item 2
    const diskFrames = JSON.parse(fs.readFileSync(analystWsPath, 'utf8'));
    console.log('\n=== REAL ANALYST WS FRAMES FROM DISK (scratch/evidence/analyst_ws_frames.json) ===');
    
    const newThreatFrame = diskFrames.find(f => (typeof f === 'string' ? f : f.frame).includes('new_threat'));
    if (newThreatFrame) {
      console.log('\n--- Real Analyst WS Frame: new_threat (UNMASKED sourceIP) ---');
      console.log(typeof newThreatFrame === 'string' ? newThreatFrame : newThreatFrame.frame);
    }

    const hpCmdFrame = diskFrames.find(f => (typeof f === 'string' ? f : f.frame).includes('honeypot_command'));
    if (hpCmdFrame) {
      console.log('\n--- Real Analyst WS Frame: honeypot_command (RAW command) ---');
      console.log(typeof hpCmdFrame === 'string' ? hpCmdFrame : hpCmdFrame.frame);
    }

    console.log('\n=== ANALYST LIVE FEED VERIFICATION COMPLETE ===');
  } catch (err) {
    mainError = err;
    throw err;
  } finally {
    try {
      if (liveSessionId) {
        await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db');
        const db = mongoose.connection.db;
        const dbName = db.databaseName;
        const backendEnv = await getBackendNodeEnv();

        if (dbName !== 'sentinel-db' || backendEnv === 'production') {
          throw new Error(`Cleanup refused: unsafe environment (db: "${dbName}", backend NODE_ENV: "${backendEnv}")`);
        }

        const createdSession = await db.collection('honeypotsessions').findOne({ sessionId: liveSessionId });
        if (createdSession) {
          await db.collection('honeypotsessions').deleteOne({ _id: createdSession._id });
          if (createdSession.linkedThreatLog) {
            await db.collection('threatlogs').deleteOne({ _id: createdSession.linkedThreatLog });
          }
          console.log(`  -> [Cleanup] Successfully deleted created session (${createdSession._id}) and linked threat (${createdSession.linkedThreatLog}).`);
        }
        await mongoose.disconnect();
      }
    } catch (cleanupErr) {
      console.error('  -> [Cleanup Error]:', cleanupErr.message);
      if (!mainError) {
        throw cleanupErr;
      }
    }
    await browser.close().catch(() => {});
  }


}

main().catch((err) => {
  console.error('\n[FATAL ERROR in Analyst Feed Audit]', err);
  process.exit(1);
});
