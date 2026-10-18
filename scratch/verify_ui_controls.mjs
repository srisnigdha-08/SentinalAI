import path from 'path';
import fs from 'fs';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const backendDir = 'c:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete\\backend';
const puppeteer = require(path.join(backendDir, 'node_modules', 'puppeteer-core'));

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
const VIEWER_PASSWORD = requireEnv('VERIFY_VIEWER_PASSWORD');

function assert(condition, message) {
  if (!condition) {
    console.error(`  [ASSERTION FAILED] ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
}

async function main() {
  console.log('=== Verifying Role-Specific Buttons & Observation Mode ===\n');

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
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    const baseUrl = 'http://localhost:3000';

    async function loginAs(email, password) {
      await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });
      await page.evaluate(() => { localStorage.clear(); sessionStorage.clear(); });
      await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });
      const emailInput = await page.waitForSelector('input[type="email"]', { timeout: 15000 });
      await emailInput.click({ clickCount: 3 });
      await emailInput.type(email);
      const passInput = await page.waitForSelector('input[type="password"]');
      await passInput.click({ clickCount: 3 });
      await passInput.type(password);
      await page.evaluate(() => {
        const buttons = Array.from(document.querySelectorAll('button'));
        const authBtn = buttons.find(b => b.innerText.includes('AUTHENTICATE'));
        if (authBtn) authBtn.click();
      });
      await page.waitForFunction(() => window.location.pathname === '/dashboard', { timeout: 10000 });
    }

    // 1. Check VIEWER
    console.log('[Test 1] Logging in as VIEWER (sara@sentinel.io)...');
    await loginAs('sara@sentinel.io', VIEWER_PASSWORD);
    
    // Check Dashboard
    await page.waitForSelector('main', { timeout: 10000 });
    const viewerDashText = await page.evaluate(() => document.querySelector('main').innerText);
    const viewerHasDashBlockBtn = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Block IP');
    });
    const viewerHasDashTriageBtn = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Triage');
    });
    console.log(`  -> Viewer Dashboard contains 'Block IP' button: ${viewerHasDashBlockBtn} (Expected: false)`);
    console.log(`  -> Viewer Dashboard contains 'Triage' button: ${viewerHasDashTriageBtn} (Expected: false)`);
    console.log(`  -> Viewer Dashboard contains 'OBSERVATION WORKSPACE': ${viewerDashText.includes('OBSERVATION WORKSPACE')} (Expected: true)`);
    assert(!viewerHasDashBlockBtn, "Viewer Dashboard must not contain 'Block IP' button");
    assert(!viewerHasDashTriageBtn, "Viewer Dashboard must not contain 'Triage' button");
    assert(viewerDashText.includes('OBSERVATION WORKSPACE'), "Viewer Dashboard must contain 'OBSERVATION WORKSPACE' header");

    // Check Threat Logs
    console.log('  -> Navigating to /dashboard/threats as VIEWER...');
    await page.goto(`${baseUrl}/dashboard/threats`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('main', { timeout: 10000 });
    await page.waitForFunction(() => {
      const main = document.querySelector('main');
      return main && !main.innerText.includes('LOADING THREAT LOGS');
    }, { timeout: 10000 });
    const viewerThreatsBlockBtn = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Block');
    });
    const viewerThreatsTriageBtn = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Triage');
    });
    const viewerThreatsText = await page.evaluate(() => document.querySelector('main').innerText);
    console.log(`  -> Viewer Threat Logs contains 'Block' button: ${viewerThreatsBlockBtn} (Expected: false)`);
    console.log(`  -> Viewer Threat Logs contains 'Triage' button: ${viewerThreatsTriageBtn} (Expected: false)`);
    console.log(`  -> Viewer Threat Logs contains 'OBSERVATION MODE': ${viewerThreatsText.includes('OBSERVATION MODE')} (Expected: true)`);
    assert(!viewerThreatsBlockBtn, "Viewer Threat Logs must not contain 'Block' button");
    assert(!viewerThreatsTriageBtn, "Viewer Threat Logs must not contain 'Triage' button");
    assert(viewerThreatsText.includes('OBSERVATION MODE'), "Viewer Threat Logs must display 'OBSERVATION MODE' badge");

    // 2. Check ANALYST
    console.log('\n[Test 2] Logging in as ANALYST (arjun@sentinel.io)...');
    await loginAs('arjun@sentinel.io', ANALYST_PASSWORD);

    await page.waitForSelector('main', { timeout: 10000 });
    await page.waitForFunction(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Block IP');
    }, { timeout: 10000 });
    const analystDashText = await page.evaluate(() => document.querySelector('main').innerText);
    const analystHasDashBlockBtn = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Block IP');
    });
    console.log(`  -> Analyst Dashboard contains 'DEFENSE WORKSPACE': ${analystDashText.includes('DEFENSE WORKSPACE')} (Expected: true)`);
    console.log(`  -> Analyst Dashboard contains 'Block IP' button: ${analystHasDashBlockBtn} (Expected: true)`);
    assert(analystDashText.includes('DEFENSE WORKSPACE'), "Analyst Dashboard must contain 'DEFENSE WORKSPACE' header");
    assert(analystHasDashBlockBtn, "Analyst Dashboard must contain 'Block IP' button");

    // Check Analyst Threat Logs
    console.log('  -> Navigating to /dashboard/threats as ANALYST...');
    await page.goto(`${baseUrl}/dashboard/threats`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('main', { timeout: 10000 });
    await page.waitForFunction(() => {
      const main = document.querySelector('main');
      return main && !main.innerText.includes('LOADING THREAT LOGS');
    }, { timeout: 10000 });
    const analystThreatsBlockBtn = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Block');
    });
    const analystThreatsTriageBtn = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Triage');
    });
    console.log(`  -> Analyst Threat Logs contains 'Block' button: ${analystThreatsBlockBtn} (Expected: true)`);
    console.log(`  -> Analyst Threat Logs contains 'Triage' button: ${analystThreatsTriageBtn} (Expected: true)`);
    assert(analystThreatsBlockBtn, "Analyst Threat Logs must contain active 'Block' button");
    assert(analystThreatsTriageBtn, "Analyst Threat Logs must contain active 'Triage' button");

    // 3. Check ADMIN
    console.log('\n[Test 3] Logging in as ADMIN (admin@sentinel.io)...');
    await loginAs('admin@sentinel.io', ADMIN_PASSWORD);

    await page.waitForSelector('main', { timeout: 10000 });
    await page.waitForFunction(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Block IP');
    }, { timeout: 10000 });
    const adminDashText = await page.evaluate(() => document.querySelector('main').innerText);
    const adminHasDashBlockBtn = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Block IP');
    });
    console.log(`  -> Admin Dashboard contains 'CONTROL WORKSPACE': ${adminDashText.includes('CONTROL WORKSPACE')} (Expected: true)`);
    console.log(`  -> Admin Dashboard contains 'Block IP' button: ${adminHasDashBlockBtn} (Expected: true)`);
    assert(adminDashText.includes('CONTROL WORKSPACE'), "Admin Dashboard must contain 'CONTROL WORKSPACE' header");
    assert(adminHasDashBlockBtn, "Admin Dashboard must contain 'Block IP' button");

    // Check Admin Threat Logs
    console.log('  -> Navigating to /dashboard/threats as ADMIN...');
    await page.goto(`${baseUrl}/dashboard/threats`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('main', { timeout: 10000 });
    await page.waitForFunction(() => {
      const main = document.querySelector('main');
      return main && !main.innerText.includes('LOADING THREAT LOGS');
    }, { timeout: 10000 });
    const adminThreatsBlockBtn = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Block');
    });
    const adminThreatsTriageBtn = await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      return buttons.some(b => b.innerText.trim() === 'Triage');
    });
    console.log(`  -> Admin Threat Logs contains 'Block' button: ${adminThreatsBlockBtn} (Expected: true)`);
    console.log(`  -> Admin Threat Logs contains 'Triage' button: ${adminThreatsTriageBtn} (Expected: true)`);
    assert(adminThreatsBlockBtn, "Admin Threat Logs must contain active 'Block' button");
    assert(adminThreatsTriageBtn, "Admin Threat Logs must contain active 'Triage' button");

    console.log('\n=== ALL UI CONTROL & OBSERVATION MODE CHECKS PASSED ===\n');
  } finally {
    await browser.close();
  }
}

main().catch(err => {
  console.error('[Error in UI control check]', err);
  process.exit(1);
});
