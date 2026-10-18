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

const VIEWER_PASSWORD = requireEnv('VERIFY_VIEWER_PASSWORD');
const HONEYPOT_API_KEY = requireEnv('HONEYPOT_API_KEY');

async function getBackendNodeEnv(token) {
  let authToken = token;
  if (!authToken && (process.env.VERIFY_ADMIN_PASSWORD || process.env.VERIFY_ANALYST_PASSWORD)) {
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


// Unmasked IPv4 regex: must not match 127.0.0.1 or 0.0.0.0
// Masked IPs like 198.51.100.xxx or ::xxxx do not match because 4th octet is xxx, not digits.
const IPV4_REGEX = /\b(?!127\.0\.0\.1\b)(?!0\.0\.0\.0\b)(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;

async function main() {
  console.log('=== Starting Extended Viewer Audit (REST & WebSocket Redaction Verification) ===\n');

  let executablePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  if (!fs.existsSync(executablePath)) {
    executablePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  }

  const browser = await puppeteer.launch({
    executablePath,
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const capturedRest = [];
  const capturedWsFrames = [];
  const forbiddenResponses = [];
  const consoleErrors = [];
  const sensitiveLeaks = [];
  let liveSessionId = null;


  function inspectPayload(payloadText, context) {
    if (typeof payloadText !== 'string' || !payloadText) return;

    // 1. Check for unmasked IPv4
    const ipMatches = payloadText.match(IPV4_REGEX) || [];
    for (const ip of ipMatches) {
      // Exclude localhost/loopback or client url
      if (ip === '127.0.0.1' || ip === '0.0.0.0') continue;
      sensitiveLeaks.push({
        type: 'UNMASKED_IPV4',
        value: ip,
        context,
        sample: payloadText.slice(Math.max(0, payloadText.indexOf(ip) - 25), payloadText.indexOf(ip) + ip.length + 25)
      });
      console.error(`  [LEAK DETECTED: UNMASKED IPv4] in ${context}: ${ip}`);
    }

    // 2. Check for raw honeypot commands
    const rawCommands = ['cat /etc/shadow', 'uname -a', 'wget http', 'curl -O', 'chmod +x', '/bin/bash'];
    for (const cmd of rawCommands) {
      if (payloadText.includes(cmd)) {
        sensitiveLeaks.push({
          type: 'RAW_COMMAND',
          value: cmd,
          context,
          sample: payloadText.slice(Math.max(0, payloadText.indexOf(cmd) - 20), payloadText.indexOf(cmd) + cmd.length + 20)
        });
        console.error(`  [LEAK DETECTED: RAW COMMAND] in ${context}: ${cmd}`);
      }
    }

    // 3. Check for raw passwords or credentials
    if (payloadText.includes('"password"') &&
        !payloadText.includes('[REDACTED_CREDENTIAL]') &&
        !payloadText.includes('***REDACTED***') &&
        !context.includes('/login')) {
      sensitiveLeaks.push({
        type: 'RAW_PASSWORD',
        value: 'unredacted password',
        context
      });
      console.error(`  [LEAK DETECTED: RAW PASSWORD] in ${context}`);
    }

    // 4. Check for unredacted threat payloads
    try {
      const parsed = JSON.parse(payloadText);
      const checkObj = (obj) => {
        if (!obj || typeof obj !== 'object') return;
        if (typeof obj.payload === 'string' &&
            obj.payload !== '[REDACTED_PAYLOAD]' &&
            obj.payload.length > 0 &&
            !context.includes('/login') &&
            !context.includes('/csrf')) {
          sensitiveLeaks.push({
            type: 'RAW_PAYLOAD',
            value: obj.payload,
            context
          });
          console.error(`  [LEAK DETECTED: RAW PAYLOAD] in ${context}: ${obj.payload}`);
        }
        if (Array.isArray(obj)) obj.forEach(checkObj);
        else Object.values(obj).forEach(val => {
          if (val && typeof val === 'object') checkObj(val);
        });
      };
      checkObj(parsed);
    } catch {}
  }

  let mainError = null;
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    // Enable Chrome DevTools Protocol to capture WebSocket frames
    const cdp = await page.target().createCDPSession();
    await cdp.send('Network.enable');

    cdp.on('Network.webSocketFrameReceived', (params) => {
      const payload = params.response?.payloadData;
      if (payload) {
        capturedWsFrames.push(payload);
        // Only inspect Socket.IO event payloads (starts with 42)
        if (payload.startsWith('42')) {
          inspectPayload(payload, `WebSocket Event Frame #${capturedWsFrames.length}`);
        }
      }
    });

    page.on('response', async (response) => {
      const status = response.status();
      const url = response.url();
      if ((status === 401 || status === 403) && url.includes('/api/')) {
        forbiddenResponses.push({ status, url });
        console.error(`  [Network ${status}] ${url}`);
      }

      if (url.includes('/api/') && !url.includes('/auth/login') && !url.includes('/auth/csrf')) {
        try {
          const contentType = response.headers()['content-type'] || '';
          if (contentType.includes('application/json')) {
            const body = await response.text();
            let parsedBody = null;
            try {
              parsedBody = JSON.parse(body);
            } catch {
              parsedBody = body;
            }
            capturedRest.push({
              timestamp: new Date().toISOString(),
              url,
              status,
              headers: response.headers(),
              body: parsedBody,
            });
            inspectPayload(body, `REST [${status}] ${url}`);
          }
        } catch {}
      }
    });

    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const text = msg.text();
        if (!text.includes('favicon.ico')) {
          consoleErrors.push(text);
          console.error(`  [Console Error] ${text}`);
        }
      }
    });

    page.on('pageerror', (err) => {
      consoleErrors.push(err.message);
      console.error(`  [Page Error] ${err.message}`);
    });

    const baseUrl = 'http://localhost:3000';

    console.log('[Step 1] Logging in as VIEWER (sara@sentinel.io)...');
    await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });
    await page.evaluate(() => { localStorage.clear(); sessionStorage.clear(); });
    await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });

    const emailInput = await page.waitForSelector('input[type="email"]', { timeout: 15000 });
    await emailInput.click({ clickCount: 3 });
    await emailInput.type('sara@sentinel.io');
    const passInput = await page.waitForSelector('input[type="password"]');
    await passInput.click({ clickCount: 3 });
    await passInput.type(VIEWER_PASSWORD);

    await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      const authBtn = buttons.find((b) => b.innerText.includes('AUTHENTICATE'));
      if (authBtn) authBtn.click();
    });

    await page.waitForFunction(() => window.location.pathname === '/dashboard', { timeout: 10000 });
    console.log('  -> Logged in successfully to /dashboard\n');

    // Clear initial login frames/responses
    forbiddenResponses.length = 0;
    consoleErrors.length = 0;
    sensitiveLeaks.length = 0;

    const routes = [
      { name: 'Dashboard', path: '/dashboard' },
      { name: 'Threat Logs', path: '/dashboard/threats' },
      { name: 'Honeypot Analytics', path: '/dashboard/honeypot' },
      { name: 'Campaigns', path: '/dashboard/campaigns' },
      { name: 'AI Analytics', path: '/dashboard/ai' },
    ];

    for (const r of routes) {
      console.log(`[Audit] Navigating to ${r.name} (${r.path})...`);
      const routeForbiddenBefore = forbiddenResponses.length;
      const routeErrorsBefore = consoleErrors.length;
      const routeLeaksBefore = sensitiveLeaks.length;

      await page.goto(`${baseUrl}${r.path}`, { waitUntil: 'domcontentloaded' });
      await page.waitForSelector('main', { timeout: 10000 });
      // Allow async data fetching to settle
      await new Promise((res) => setTimeout(res, 2500));

      const newForbidden = forbiddenResponses.length - routeForbiddenBefore;
      const newErrors = consoleErrors.length - routeErrorsBefore;
      const newLeaks = sensitiveLeaks.length - routeLeaksBefore;

      console.log(`  -> Page verified. Forbidden: ${newForbidden}, Console Errors: ${newErrors}, Leaks: ${newLeaks}`);
    }

    // Step 3: Trigger live WebSocket events and verify real-time frame redaction
    console.log('\n[Step 3] Testing Live WebSocket broadcast to Viewer socket...');
    const wsFrameCountBefore = capturedWsFrames.length;

    // Send honeypot events to port 5000 via internal API key:
    // 1. SESSION_OPENED triggers emitNewThreat -> 'new_threat' event
    // 2. COMMAND_INPUT triggers emitHoneypotEvent -> 'honeypot_command' event
    try {
      liveSessionId = 'audit-live-session-viewer-test-' + Date.now();
      const openSessionData = JSON.stringify({
        eventType: 'SESSION_OPENED',
        sessionId: liveSessionId,
        sourceIP: '203.0.113.195',
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
            'Content-Length': Buffer.byteLength(openSessionData),
          },
        }, (res) => {
          res.resume();
          resolve();
        });
        req.on('error', () => resolve());
        req.write(openSessionData);
        req.end();
      });

      await new Promise((res) => setTimeout(res, 1500));

      const postData = JSON.stringify({
        eventType: 'COMMAND_INPUT',
        sessionId: liveSessionId,
        sourceIP: '203.0.113.195',
        command: 'cat /etc/shadow',
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

      // Wait 3 seconds to capture all broadcast frames
      await new Promise((res) => setTimeout(res, 3000));
    } catch (e) {
      console.warn('  [Live WS Event notice]:', e.message);
    }

    console.log(`  -> Total WebSocket frames captured via CDP: ${capturedWsFrames.length}`);
    console.log(`  -> Total REST responses inspected: ${capturedRest.length}`);

    // Save raw evidence files
    const evidenceDir = path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), 'evidence');
    fs.mkdirSync(evidenceDir, { recursive: true });
    const netPath = path.join(evidenceDir, 'viewer_network.json');
    const wsPath = path.join(evidenceDir, 'viewer_ws_frames.json');
    fs.writeFileSync(netPath, JSON.stringify(capturedRest, null, 2));
    fs.writeFileSync(wsPath, JSON.stringify(capturedWsFrames, null, 2));
    console.log(`  -> Saved raw network log to: ${netPath}`);
    console.log(`  -> Saved raw WS frames to: ${wsPath}`);

    // Read and print real REST responses from disk as requested in Item 1
    const savedRest = JSON.parse(fs.readFileSync(netPath, 'utf8'));
    console.log('\n=== REAL REST RESPONSES FROM DISK (scratch/evidence/viewer_network.json) ===');
    
    const threatsRes = savedRest.find((item) => item.url.includes('/api/threats') && !item.url.includes('/settings') && item.status === 200);
    if (threatsRes) {
      console.log(`\n--- Real REST Response: /api/threats [${threatsRes.status}] ---`);
      console.log(JSON.stringify(threatsRes.body, null, 2).slice(0, 600) + '\n...');
    }

    const honeypotRes = savedRest.find((item) => item.url.includes('/api/honeypot') && item.status === 200);
    if (honeypotRes) {
      console.log(`\n--- Real REST Response: honeypot [${honeypotRes.status}] ${honeypotRes.url} ---`);
      console.log(JSON.stringify(honeypotRes.body, null, 2).slice(0, 600) + '\n...');
    }

    // Read and print real WS frames from disk as requested in Item 1
    const savedWs = JSON.parse(fs.readFileSync(wsPath, 'utf8'));
    console.log('\n=== REAL WEBSOCKET FRAMES FROM DISK (scratch/evidence/viewer_ws_frames.json) ===');
    
    const newThreatFrame = savedWs.find((f) => (typeof f === 'string' ? f : f.frame || '').includes('new_threat'));
    if (newThreatFrame) {
      console.log('\n--- Real WS Frame: new_threat ---');
      console.log(typeof newThreatFrame === 'string' ? newThreatFrame : newThreatFrame.frame);
    }

    const hpCmdFrame = savedWs.find((f) => (typeof f === 'string' ? f : f.frame || '').includes('honeypot_command'));
    if (hpCmdFrame) {
      console.log('\n--- Real WS Frame: honeypot_command ---');
      console.log(typeof hpCmdFrame === 'string' ? hpCmdFrame : hpCmdFrame.frame);
    }

    // Summary Report
    console.log('\n======================================================');
    console.log('=== VIEWER REAL-TIME AUDIT SUMMARY REPORT ===');
    console.log('======================================================');
    console.log(`REST Responses Inspected: ${capturedRest.length}`);
    console.log(`WebSocket Frames Captured: ${capturedWsFrames.length}`);
    console.log(`401/403 Forbidden Responses: ${forbiddenResponses.length}`);
    console.log(`Browser Console Errors:     ${consoleErrors.length}`);
    console.log(`Sensitive Data Leaks:       ${sensitiveLeaks.length}`);

    if (sensitiveLeaks.length > 0) {
      console.error('\n[FATAL AUDIT FAILURE] Detected sensitive data leaks:');
      sensitiveLeaks.forEach((leak, i) => {
        console.error(`  ${i + 1}. [${leak.type}] in ${leak.context}: ${leak.value}`);
        if (leak.sample) console.error(`     Snippet: "...${leak.sample}..."`);
      });
      process.exit(1);
    }

    if (forbiddenResponses.length > 0 || consoleErrors.length > 0) {
      console.error(`\n[FATAL AUDIT FAILURE] Found ${forbiddenResponses.length} forbidden network responses or ${consoleErrors.length} console errors.`);
      process.exit(1);
    }

    console.log('\n=== LIVE VIEWER PROOF PASSED: ZERO UNMASKED IPs, ZERO RAW COMMANDS/PASSWORDS, ZERO 403s ===\n');

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
  console.error('\n[FATAL ERROR in Viewer Audit]', err);
  process.exit(1);
});
