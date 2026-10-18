import { spawn } from 'child_process';
import http from 'http';
import path from 'path';
import fs from 'fs';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const backendDir = 'c:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete\\backend';
const frontendDir = 'c:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete\\frontend';
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

function waitPort(url, timeoutMs = 30000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const check = () => {
      http.get(url, (res) => {
        resolve();
      }).on('error', () => {
        if (Date.now() - start > timeoutMs) {
          reject(new Error(`Timeout waiting for ${url}`));
        } else {
          setTimeout(check, 500);
        }
      });
    };
    check();
  });
}

async function isPortOpen(url) {
  return new Promise((resolve) => {
    http.get(url, () => resolve(true)).on('error', () => resolve(false));
  });
}

async function main() {
  console.log('=== Starting Live Real-Browser RBAC Verification ===\n');

  // Check browser executable
  let executablePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  if (!fs.existsSync(executablePath)) {
    executablePath = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  }
  console.log(`[Browser] Using system executable: ${executablePath}`);

  // Backend is running on port 5000
  console.log('[Setup] Verifying backend health on port 5000...');
  await waitPort('http://localhost:5000/api/auth/csrf', 15000);
  console.log('  -> Backend is healthy on port 5000');

  const baseUrl = 'http://localhost:3000';
  let frontendProc = null;

  const port3000Active = await isPortOpen('http://localhost:3000');
  if (!port3000Active) {
    console.log('[Setup] Starting local Vite dev server on port 3000...');
    frontendProc = spawn('cmd.exe', ['/c', 'npx', 'vite', '--port', '3000'], {
      cwd: frontendDir,
      env: { ...process.env },
      stdio: 'pipe'
    });
    frontendProc.stdout.on('data', d => process.stdout.write(`[vite] ${d}`));
    frontendProc.stderr.on('data', d => process.stderr.write(`[vite err] ${d}`));
    await waitPort('http://localhost:3000', 30000);
  }
  console.log(`  -> Frontend Vite server is ready on ${baseUrl}`);

  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath,
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    console.log('  -> Real system browser launched successfully!\n');

    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    page.on('console', msg => console.log(`[Browser Console ${msg.type()}]`, msg.text()));
    page.on('pageerror', err => console.log(`[Browser PageError]`, err.message));

    // Helper: Login
    async function loginAs(email, password, expectedRole) {
      console.log(`\n--------------------------------------------------`);
      console.log(`[Test] Logging in as ${email} (Role: ${expectedRole})...`);
      await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });
      await page.evaluate(() => {
        localStorage.clear();
        sessionStorage.clear();
      });
      await page.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' });
      const emailInput = await page.waitForSelector('input[type="email"]', { timeout: 15000 });
      await emailInput.click({ clickCount: 3 });
      await emailInput.type(email);

      // Enter password
      const passInput = await page.waitForSelector('input[type="password"]');
      await passInput.click({ clickCount: 3 });
      await passInput.type(password);

      // Click the AUTHENTICATE button specifically (not Auto-fill)
      await page.evaluate(() => {
        const buttons = Array.from(document.querySelectorAll('button'));
        const authBtn = buttons.find(b => b.innerText.includes('AUTHENTICATE'));
        if (authBtn) authBtn.click();
      });

      // Wait for navigation to /dashboard
      await page.waitForFunction(() => window.location.pathname === '/dashboard', { timeout: 10000 });
      console.log(`  -> Successfully logged in and reached /dashboard`);

      // Verify role in live DOM
      await page.waitForSelector('aside', { timeout: 10000 });
      const sidebarText = await page.evaluate(() => document.querySelector('aside').innerText);
      const expectedBadge = {
        admin: 'ADMIN // CONTROL',
        analyst: 'ANALYST // DEFEND',
        viewer: 'VIEWER // OBSERVE',
      }[expectedRole];
      console.log(`  -> Verified live role badge in DOM: ${sidebarText.includes(expectedBadge)} (${expectedBadge})`);
      if (!sidebarText.includes(expectedBadge)) {
        throw new Error(`Role mismatch! DOM missing ${expectedBadge}`);
      }
    }

    // Helper: Check Sidebar
    async function checkSidebar() {
      console.log(`[Check] Inspecting Sidebar in live DOM...`);
      await page.waitForSelector('aside', { timeout: 10000 });
      await page.waitForFunction(() => {
        const aside = document.querySelector('aside');
        return aside && aside.querySelectorAll('a').length > 0;
      }, { timeout: 10000 });

      const sidebarInfo = await page.evaluate(() => {
        const aside = document.querySelector('aside');
        if (!aside) return { links: [], text: '' };
        const links = Array.from(aside.querySelectorAll('a')).map(a => ({
          text: a.innerText.trim(),
          href: a.getAttribute('href')
        }));
        return { links, text: aside.innerText };
      });
      console.log(`  -> Sidebar links found (${sidebarInfo.links.length}):`, sidebarInfo.links.map(l => l.text));
      return sidebarInfo;
    }

    // Helper: Attempt Direct Navigation
    async function attemptNavigation(targetPath) {
      console.log(`[Check] Navigating directly to ${baseUrl}${targetPath}...`);
      await page.goto(`${baseUrl}${targetPath}`, { waitUntil: 'domcontentloaded' });

      // Wait for redirect to /dashboard
      await page.waitForFunction(() => window.location.pathname === '/dashboard', { timeout: 10000 });
      const currentPath = await page.evaluate(() => window.location.pathname);

      // Wait for toast to appear in DOM
      let toastTexts = [];
      try {
        await page.waitForFunction(() => {
          const text = document.body.innerText || '';
          return text.includes('Access denied') || text.includes('Insufficient permissions');
        }, { timeout: 5000 });

        toastTexts = await page.evaluate(() => {
          const elements = Array.from(document.querySelectorAll('div, [role="status"], span'));
          return elements
            .filter(d => d.innerText && (d.innerText.includes('Access denied') || d.innerText.includes('Insufficient permissions')))
            .map(t => t.innerText.trim());
        });
      } catch (err) {
        console.log('  [Toast wait warning]:', err.message);
      }

      return { currentPath, toastTexts };
    }

    // ==========================================
    // TEST 1: ANALYST (arjun@sentinel.io)
    // ==========================================
    await loginAs('arjun@sentinel.io', ANALYST_PASSWORD, 'analyst');

    // 1.1 Sidebar check
    const analystNav = await checkSidebar();
    const hasAnalystUsers = analystNav.links.some(l => l.href.includes('/dashboard/users'));
    const hasAnalystSettings = analystNav.links.some(l => l.href.includes('/settings'));
    const hasAnalystMgmtHeader = analystNav.text.includes('MANAGEMENT');

    console.log(`  -> Sidebar contains 'Users' link: ${hasAnalystUsers} (Expected: false)`);
    console.log(`  -> Sidebar contains 'Settings' link: ${hasAnalystSettings} (Expected: false)`);
    console.log(`  -> Sidebar contains 'MANAGEMENT' section: ${hasAnalystMgmtHeader} (Expected: false)`);
    if (hasAnalystUsers || hasAnalystSettings || hasAnalystMgmtHeader) {
      throw new Error('FAILED: Analyst sidebar leaked admin navigation links/headers!');
    }
    console.log('  [PASS] Analyst sidebar correctly hides admin links and empty sections.');

    // 1.2 Direct navigation to /dashboard/users
    const analystUsersResult = await attemptNavigation('/dashboard/users');
    console.log(`  -> Destination pathname: ${analystUsersResult.currentPath} (Expected: /dashboard)`);
    console.log(`  -> Toast notification in DOM: ${JSON.stringify(analystUsersResult.toastTexts)}`);
    if (analystUsersResult.currentPath !== '/dashboard') {
      throw new Error(`FAILED: Analyst was NOT redirected from /dashboard/users! Current path: ${analystUsersResult.currentPath}`);
    }
    if (analystUsersResult.toastTexts.length === 0) {
      throw new Error('FAILED: Denial toast was not rendered in DOM!');
    }
    console.log('  [PASS] Direct navigation to /dashboard/users was redirected to /dashboard with denial toast.');

    // 1.3 Direct navigation to /settings
    const analystSettingsResult = await attemptNavigation('/settings');
    console.log(`  -> Destination pathname: ${analystSettingsResult.currentPath} (Expected: /dashboard)`);
    console.log(`  -> Toast notification in DOM: ${JSON.stringify(analystSettingsResult.toastTexts)}`);
    if (analystSettingsResult.currentPath !== '/dashboard') {
      throw new Error(`FAILED: Analyst was NOT redirected from /settings! Current path: ${analystSettingsResult.currentPath}`);
    }
    if (analystSettingsResult.toastTexts.length === 0) {
      throw new Error('FAILED: Denial toast was not rendered in DOM!');
    }
    console.log('  [PASS] Direct navigation to /settings was redirected to /dashboard with denial toast.');

    // ==========================================
    // TEST 2: VIEWER (sara@sentinel.io)
    // ==========================================
    await loginAs('sara@sentinel.io', VIEWER_PASSWORD, 'viewer');

    // 2.1 Sidebar check
    const viewerNav = await checkSidebar();
    const hasViewerUsers = viewerNav.links.some(l => l.href.includes('/dashboard/users'));
    const hasViewerSettings = viewerNav.links.some(l => l.href.includes('/settings'));
    const hasViewerMgmtHeader = viewerNav.text.includes('MANAGEMENT');

    console.log(`  -> Sidebar contains 'Users' link: ${hasViewerUsers} (Expected: false)`);
    console.log(`  -> Sidebar contains 'Settings' link: ${hasViewerSettings} (Expected: false)`);
    console.log(`  -> Sidebar contains 'MANAGEMENT' section: ${hasViewerMgmtHeader} (Expected: false)`);
    if (hasViewerUsers || hasViewerSettings || hasViewerMgmtHeader) {
      throw new Error('FAILED: Viewer sidebar leaked admin navigation links/headers!');
    }
    console.log('  [PASS] Viewer sidebar correctly hides admin links and empty sections.');

    // 2.2 Direct navigation to /dashboard/users
    const viewerUsersResult = await attemptNavigation('/dashboard/users');
    console.log(`  -> Destination pathname: ${viewerUsersResult.currentPath} (Expected: /dashboard)`);
    console.log(`  -> Toast notification in DOM: ${JSON.stringify(viewerUsersResult.toastTexts)}`);
    if (viewerUsersResult.currentPath !== '/dashboard') {
      throw new Error(`FAILED: Viewer was NOT redirected from /dashboard/users! Current path: ${viewerUsersResult.currentPath}`);
    }
    if (viewerUsersResult.toastTexts.length === 0) {
      throw new Error('FAILED: Denial toast was not rendered for Viewer on /dashboard/users!');
    }
    console.log('  [PASS] Direct navigation to /dashboard/users was redirected to /dashboard with denial toast.');

    // 2.3 Direct navigation to /settings
    const viewerSettingsResult = await attemptNavigation('/settings');
    console.log(`  -> Destination pathname: ${viewerSettingsResult.currentPath} (Expected: /dashboard)`);
    console.log(`  -> Toast notification in DOM: ${JSON.stringify(viewerSettingsResult.toastTexts)}`);
    if (viewerSettingsResult.currentPath !== '/dashboard') {
      throw new Error(`FAILED: Viewer was NOT redirected from /settings! Current path: ${viewerSettingsResult.currentPath}`);
    }
    if (viewerSettingsResult.toastTexts.length === 0) {
      throw new Error('FAILED: Denial toast was not rendered for Viewer on /settings!');
    }
    console.log('  [PASS] Direct navigation to /settings was redirected to /dashboard with denial toast.');

    // ==========================================
    // TEST 3: ADMIN (admin@sentinel.io)
    // ==========================================
    await loginAs('admin@sentinel.io', ADMIN_PASSWORD, 'admin');

    // 3.1 Sidebar check
    const adminNav = await checkSidebar();
    const hasAdminUsers = adminNav.links.some(l => l.href.includes('/dashboard/users'));
    const hasAdminSettings = adminNav.links.some(l => l.href.includes('/settings'));
    const hasAdminMgmtHeader = adminNav.text.includes('MANAGEMENT');

    console.log(`  -> Sidebar contains 'Users' link: ${hasAdminUsers} (Expected: true)`);
    console.log(`  -> Sidebar contains 'Settings' link: ${hasAdminSettings} (Expected: true)`);
    console.log(`  -> Sidebar contains 'MANAGEMENT' section: ${hasAdminMgmtHeader} (Expected: true)`);
    if (!hasAdminUsers || !hasAdminSettings || !hasAdminMgmtHeader) {
      throw new Error('FAILED: Admin sidebar missing admin navigation links or header!');
    }
    console.log('  [PASS] Admin sidebar displays all management links and sections.');

    // 3.2 Direct navigation to /dashboard/users
    console.log('[Check] Admin navigating to /dashboard/users...');
    await page.goto(`${baseUrl}/dashboard/users`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => {
      const text = document.body.innerText || '';
      return text.includes('User') && text.includes('Management');
    }, { timeout: 15000 });

    const adminUsersPath = await page.evaluate(() => window.location.pathname);
    console.log(`  -> Destination pathname: ${adminUsersPath} (Expected: /dashboard/users)`);
    if (adminUsersPath !== '/dashboard/users') {
      throw new Error(`FAILED: Admin was redirected away from /dashboard/users!`);
    }
    console.log('  [PASS] Admin successfully accessed /dashboard/users without redirection.');

    // 3.3 Direct navigation to /settings
    console.log('[Check] Admin navigating to /settings...');
    await page.goto(`${baseUrl}/settings`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => {
      const text = document.body.innerText || '';
      return text.includes('Settings') || text.includes('Autonomous Auto-Blocking') || text.includes('BLOCKED IP') || text.includes('AUDIT LOG');
    }, { timeout: 15000 });

    const adminSettingsPath = await page.evaluate(() => window.location.pathname);
    console.log(`  -> Destination pathname: ${adminSettingsPath} (Expected: /settings)`);
    if (adminSettingsPath !== '/settings') {
      throw new Error(`FAILED: Admin was redirected away from /settings!`);
    }
    console.log('  [PASS] Admin successfully accessed /settings without redirection.');

    console.log('\n================================================================');
    console.log('=== ALL REAL-BROWSER END-TO-END RBAC TESTS PASSED WITH 100% SUCCESS ===');
    console.log('================================================================\n');

  } finally {
    if (browser) await browser.close().catch(() => {});
    if (frontendProc && frontendProc.pid) {
      spawn('taskkill', ['/pid', frontendProc.pid.toString(), '/T', '/F']);
    }
  }
}

main().catch(err => {
  console.error('\n[FATAL ERROR in Verification]', err);
  process.exit(1);
});
