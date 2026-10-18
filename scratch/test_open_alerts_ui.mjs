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
    process.exit(1);
  }
  return val.trim();
}

const ADMIN_PASSWORD = requireEnv('VERIFY_ADMIN_PASSWORD');

async function main() {
  console.log('=== Opening Alerts in UI as Admin ===\n');

  let executablePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  if (!fs.existsSync(executablePath)) {
    executablePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  }

  const browser = await puppeteer.launch({
    executablePath,
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 800 });

  const consoleErrors = [];
  const pageErrors = [];
  const failedRequests = [];

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
      console.log('  [Browser Console Error]:', msg.text());
    }
  });

  page.on('pageerror', (err) => {
    pageErrors.push(err.message);
    console.error('  [Browser Page Error]:', err.message);
  });

  page.on('response', (res) => {
    if (res.status() >= 400 && res.url().includes('/api/')) {
      failedRequests.push({ url: res.url(), status: res.status() });
      console.error(`  [API Request Failed]: ${res.status()} ${res.url()}`);
    }
  });

  try {
    const baseUrl = 'http://localhost:3000';
    console.log('[Step 1] Navigating to login page...');
    await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });
    await page.evaluate(() => { localStorage.clear(); sessionStorage.clear(); });
    await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });

    console.log('[Step 2] Authenticating as Admin (admin@sentinel.io)...');
    const emailInput = await page.waitForSelector('input[type="email"]', { timeout: 15000 });
    await emailInput.click({ clickCount: 3 });
    await emailInput.type('admin@sentinel.io');
    const passInput = await page.waitForSelector('input[type="password"]');
    await passInput.click({ clickCount: 3 });
    await passInput.type(ADMIN_PASSWORD);

    await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      const authBtn = buttons.find((b) => b.innerText.includes('AUTHENTICATE'));
      if (authBtn) authBtn.click();
    });

    await page.waitForFunction(() => window.location.pathname === '/dashboard', { timeout: 10000 });
    console.log('  -> Logged in successfully to /dashboard');

    // Clear initial unauthenticated noise (such as initial 401 refresh on /login)
    consoleErrors.length = 0;
    pageErrors.length = 0;
    failedRequests.length = 0;

    // Wait 2 seconds for alerts to load via hook
    await new Promise((r) => setTimeout(r, 2000));

    console.log('[Step 3] Clicking Alert Bell (🔔) to open Alerts dropdown...');
    await page.evaluate(() => {
      const buttons = Array.from(document.querySelectorAll('button'));
      const bell = buttons.find(b => b.innerText.includes('🔔'));
      if (!bell) throw new Error('Alert bell button (🔔) not found in DOM');
      bell.click();
    });

    // Wait for dropdown
    await new Promise((r) => setTimeout(r, 1000));

    const alertItems = await page.evaluate(() => {
      // Find all alert items in dropdown
      const items = Array.from(document.querySelectorAll('div')).filter(d => 
        d.innerText && (d.innerText.includes('198.51.100.77') || d.innerText.includes('IP Address Blocked') || d.innerText.includes('SQL Injection'))
      );
      return items.map(el => el.innerText.trim());
    });

    console.log('\n[Step 4] Alerts found rendered in UI dropdown:');
    alertItems.forEach((text, i) => {
      console.log(`  --- Alert Item ${i + 1} ---`);
      console.log(text);
    });

    console.log('\n[Step 5] Clicking rendered alert items to trigger markRead...');
    await page.evaluate(() => {
      const clickableAlerts = Array.from(document.querySelectorAll('div')).filter(d =>
        d.style.cursor === 'pointer' && d.innerText && d.innerText.includes('198.51.100.77')
      );
      for (const el of clickableAlerts) {
        el.click();
      }
    });

    await new Promise((r) => setTimeout(r, 1500));

    console.log('\n[Step 6] Verification Results:');
    console.log(`  -> Console Errors: ${consoleErrors.length}`);
    console.log(`  -> Page / Uncaught Errors: ${pageErrors.length}`);
    console.log(`  -> Failed Network API calls: ${failedRequests.length}`);

    if (consoleErrors.length === 0 && pageErrors.length === 0 && failedRequests.length === 0) {
      console.log('\n=== ALERTS OPENED IN UI SUCCESSFULLY: ZERO ERRORS ENCOUNTERED ===');
    } else {
      console.error('\n=== ALERTS OPENED WITH ERRORS ===');
    }
  } finally {
    await browser.close().catch(() => {});
  }
}

main().catch(console.error);
