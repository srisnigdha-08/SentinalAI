import fs from 'fs';
import { createRequire } from 'module';
import { test, expect, SEEDED_USERS } from './fixtures/auth.fixture.js';
import { validateTestDatabaseName } from './dbGuard.js';

// Browser verification of the four dashboard workflows: Export Report, Adaptive Deception Refresh, Campaigns
// Refresh Feed and Edit User. Every record a test creates lives in the isolated test database (the guard below
// refuses any database whose name lacks "test") and is removed again by the test that created it.
const require = createRequire(import.meta.url);
const mongoose = require('../../backend/node_modules/mongoose');
const models = {
  User: require('../../backend/models/User'),
  ThreatLog: require('../../backend/models/ThreatLog'),
  Campaign: require('../../backend/models/Campaign'),
  HoneypotSession: require('../../backend/models/HoneypotSession'),
  DeceptionDecision: require('../../backend/models/DeceptionDecision'),
  SystemSetting: require('../../backend/models/SystemSetting'),
};

async function withTestDb(fn) {
  const uri = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinelai_test';
  validateTestDatabaseName(uri);
  const conn = await mongoose.createConnection(uri, { serverSelectionTimeoutMS: 5000 }).asPromise();
  try {
    const m = Object.fromEntries(Object.entries(models).map(([name, model]) => [name, conn.model(name, model.schema)]));
    return await fn(m);
  } finally {
    await conn.close();
  }
}

async function loginApi(request, email, password) {
  const csrf = await (await request.get('/api/auth/csrf', { headers: { Origin: 'http://127.0.0.1:3000' } })).json();
  const res = await request.post('/api/auth/login', {
    data: { email, password },
    headers: { 'X-CSRF-Token': csrf.data.csrfToken, Origin: 'http://127.0.0.1:3000' },
  });
  expect(res.ok()).toBe(true);
  return (await res.json()).data.token;
}

const kpiValue = (page, label) => page.getByText(label, { exact: true }).locator('xpath=following-sibling::div[1]');

test.describe('Dashboard: Export Report', () => {
  test('admin downloads a valid PDF and CSV built from database figures; repeated clicks export once', async ({ page, loginAs }, testInfo) => {
    const { total } = await withTestDb(async (m) => ({ total: await m.ThreatLog.countDocuments() }));
    await loginAs('admin');
    await expect(page.getByText(/ADMIN/).first()).toBeVisible();

    const exportRequests = [];
    page.on('request', (r) => { if (r.url().includes('/api/reports/security-summary')) exportRequests.push(r.url()); });
    const button = page.getByRole('button', { name: 'Export Report' });
    await expect(button).toBeEnabled();

    // Two synchronous clicks: the in-flight guard must allow only one export
    const downloadPromise = page.waitForEvent('download');
    await button.evaluate((b) => { b.click(); b.click(); });
    await expect(page.getByRole('button', { name: 'Exporting...' })).toBeVisible().catch(() => {}); // may be very brief
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/^sentinelai-security-report-7d-[\d_-]+\.pdf$/);
    const pdfPath = testInfo.outputPath('report.pdf');
    await download.saveAs(pdfPath);
    const pdf = fs.readFileSync(pdfPath).toString('latin1');
    expect(pdf.startsWith('%PDF-1.4')).toBe(true);
    expect(pdf.trimEnd().endsWith('%%EOF')).toBe(true);
    expect(pdf).toContain(`(all time: ${total}\\)`.replace('(', '\\('));
    expect(pdf).toContain('Reporting period: last 7 calendar day');
    expect(pdf).toContain('SSH-COWRIE-01');
    expect(pdf).not.toMatch(/password|token|api[_ ]?key|secret/i);
    await expect(page.getByText(/Report downloaded: sentinelai-security-report-7d/)).toBeVisible();
    await expect(button).toBeEnabled();
    expect(exportRequests).toHaveLength(1);

    // CSV for today
    await page.getByLabel('Report format').selectOption('csv');
    await page.getByLabel('Report period').selectOption('1');
    const csvDownload = page.waitForEvent('download');
    await button.click();
    const csvFile = await csvDownload;
    expect(csvFile.suggestedFilename()).toMatch(/-1d-[\d_-]+\.csv$/);
    const csvPath = testInfo.outputPath('report.csv');
    await csvFile.saveAs(csvPath);
    const csv = fs.readFileSync(csvPath, 'utf8');
    expect(csv).toContain('section,metric,value');
    expect(csv).toContain('report,period_days,1');
    expect(csv).toMatch(/detections,all_time,\d+/);
    expect(csv).toContain(`detections,all_time,${total}`);
  });

  test('server failure and network outage show an error and re-enable the button', async ({ page, loginAs }) => {
    await loginAs('admin');
    await page.route('**/api/reports/security-summary**', (route) =>
      route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ success: false, error: 'Report store offline' }) }));
    const button = page.getByRole('button', { name: 'Export Report' });
    await button.click();
    await expect(page.getByText('Export failed: Report store offline')).toBeVisible();
    await expect(button).toBeEnabled();

    await page.unroute('**/api/reports/security-summary**');
    await page.route('**/api/reports/security-summary**', (route) => route.abort('connectionfailed'));
    await button.click();
    await expect(page.getByText(/Export failed: The server could not be reached/)).toBeVisible();
    await expect(button).toBeEnabled();
  });

  test('viewer has no export control and the API refuses viewers and anonymous callers', async ({ page, loginAs, playwright }) => {
    await loginAs('viewer');
    await expect(page.getByText('READ ONLY', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Export Report' })).toHaveCount(0);
    const ctx = await playwright.request.newContext({ baseURL: 'http://127.0.0.1:3000' });
    try {
      expect((await ctx.get('/api/reports/security-summary')).status()).toBe(401);
      const token = await loginApi(ctx, SEEDED_USERS.viewer.email, SEEDED_USERS.viewer.password);
      expect((await ctx.get('/api/reports/security-summary', { headers: { Authorization: `Bearer ${token}` } })).status()).toBe(403);
    } finally {
      await ctx.dispose();
    }
  });
});

test.describe('Honeypot Analytics: Adaptive Deception Refresh', () => {
  const PENDING_ID = 'e2e-pending-decision-0001';
  const SCORED_SESSION = 'e2e-real-scored-session';

  test.beforeEach(async () => {
    await withTestDb(async (m) => {
      await m.DeceptionDecision.deleteMany({});
      await m.HoneypotSession.deleteMany({ sessionId: SCORED_SESSION });
      await m.SystemSetting.deleteMany({ key: 'deceptionActiveProfile' });
      // The served persona is the built-in default (centos_7); a decision is already pending for it
      await m.DeceptionDecision.create([
        { decisionId: 'e2e-applied-decision-0000', state: 'debian_11', action: 'centos_7', status: 'APPLIED', appliedProfile: 'centos_7', closedAt: new Date(Date.now() - 60000) },
        { decisionId: PENDING_ID, state: 'centos_7', action: 'ubuntu_22', explored: false, policy: 'q_learning', pendingLock: 'PENDING' },
      ]);
    });
  });
  test.afterEach(async () => {
    await withTestDb(async (m) => {
      await m.DeceptionDecision.deleteMany({});
      await m.HoneypotSession.deleteMany({ sessionId: SCORED_SESSION });
    });
  });

  test('refresh reads current state, reports no change, then shows new backend state, without rotating', async ({ page, loginAs }) => {
    await loginAs('admin');
    await page.goto('/dashboard/honeypot');
    const panel = page.getByTestId('adaptive-deception');
    await expect(page.getByTestId('serving-persona')).toHaveText('centos_7');
    await expect(panel).toContainText('built-in default; nothing recorded yet; not a live SSH probe');
    await expect(page.getByTestId('recommendation')).toContainText('Switch centos_7 → ubuntu_22');
    await expect(page.getByTestId('decision-status')).toContainText('…ion-0001 (already pending)');
    await expect(page.getByTestId('last-closed-decision')).toContainText('APPLIED by the rotator (debian_11 → centos_7)');
    await expect(page.getByTestId('deception-last-refreshed')).toContainText('Last refreshed');
    const firstStamp = await page.getByTestId('deception-last-refreshed').textContent();

    // Unchanged state: a real request, the same pending decision, "up to date"
    await page.waitForTimeout(1100); // let the clock move so the timestamp visibly changes
    const [statusRes, recRes] = await Promise.all([
      page.waitForResponse((r) => r.url().includes('/api/honeypot/deception/status')),
      page.waitForResponse((r) => r.url().includes('/api/honeypot/deception/recommendation')),
      page.getByRole('button', { name: 'REFRESH', exact: true }).click(),
    ]);
    expect(statusRes.status()).toBe(200);
    expect(recRes.status()).toBe(200);
    expect((await recRes.json()).data.decisionId).toBe(PENDING_ID);
    await expect(page.getByTestId('deception-refresh-note')).toHaveText('Up to date: no change since the last refresh.');
    await expect(page.getByTestId('deception-last-refreshed')).not.toHaveText(firstStamp);

    // New backend state: a real session is scored; the next refresh must show it
    const before = await page.getByTestId('learning-counts').textContent();
    await withTestDb((m) => m.HoneypotSession.create({
      sessionId: SCORED_SESSION, sourceIP: '203.0.113.77', status: 'analysed', deceptionScoredAt: new Date(),
      recommendedProfile: 'ubuntu_22', shadowPolicy: { version: 'persona-ducb-v2', mode: 'shadow', recommendation: 'debian_11', learned: true },
    }));
    await page.getByRole('button', { name: 'REFRESH', exact: true }).click();
    await expect(page.getByTestId('deception-refresh-note')).toHaveText('Updated: the backend state changed since the last refresh.');
    await expect(page.getByTestId('learning-counts')).not.toHaveText(before);
    await expect(page.getByTestId('shadow-summary')).toContainText('never applied');
    await expect(page.getByTestId('shadow-summary')).toContainText('debian_11');

    // Rapid clicks: one request set while one is in flight
    let statusCalls = 0;
    page.on('request', (r) => { if (r.url().includes('/api/honeypot/deception/status')) statusCalls += 1; });
    await page.getByRole('button', { name: 'REFRESH', exact: true }).evaluate((b) => { b.click(); b.click(); b.click(); });
    await expect(page.getByRole('button', { name: 'REFRESH', exact: true })).toBeEnabled();
    expect(statusCalls).toBe(1);

    // Nothing was rotated, drawn or duplicated
    await withTestDb(async (m) => {
      expect(await m.DeceptionDecision.countDocuments({ status: 'PENDING' })).toBe(1);
      expect((await m.DeceptionDecision.findOne({ status: 'PENDING' })).decisionId).toBe(PENDING_ID);
      expect(await m.DeceptionDecision.countDocuments()).toBe(2);
      expect(await m.SystemSetting.countDocuments({ key: 'deceptionActiveProfile' })).toBe(0);
    });
    await expect(page.getByTestId('serving-persona')).toHaveText('centos_7');
  });

  test('a failed status request shows a useful error and keeps the rest of the panel', async ({ page, loginAs }) => {
    await loginAs('analyst');
    await page.goto('/dashboard/honeypot');
    await expect(page.getByTestId('serving-persona')).toHaveText('centos_7');
    await page.route('**/api/honeypot/deception/status', (route) =>
      route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ success: false, error: 'Decision store offline' }) }));
    await page.getByRole('button', { name: 'REFRESH', exact: true }).click();
    await expect(page.getByTestId('status-error')).toHaveText('Decision history unavailable: Decision store offline.');
    await expect(page.getByTestId('deception-refresh-note')).toContainText('Partially refreshed');
    await expect(page.getByTestId('recommendation')).toContainText('ubuntu_22');
  });

  test('viewer sees the recorded persona but no decision controls', async ({ page, loginAs }) => {
    await loginAs('viewer');
    await page.goto('/dashboard/honeypot');
    await expect(page.getByTestId('serving-persona')).toHaveText('centos_7');
    await expect(page.getByRole('button', { name: 'REFRESH', exact: true })).toHaveCount(0);
  });
});

test.describe('Campaigns: Refresh Feed', () => {
  const NEW_ID = 'CAMP-E2E-REFRESH';
  test.afterEach(async () => {
    await withTestDb((m) => m.Campaign.deleteMany({ campaignId: NEW_ID }));
  });

  test('refresh reads totals, reports up to date, then shows a new campaign; ANALYZE keeps working', async ({ page, loginAs }) => {
    await withTestDb((m) => m.Campaign.deleteMany({ campaignId: NEW_ID }));
    const stored = await withTestDb((m) => m.Campaign.countDocuments());
    await loginAs('analyst');
    await page.goto('/dashboard/campaigns');
    await expect(kpiValue(page, 'Detected Campaigns')).toHaveText(String(stored));
    await expect(page.getByTestId('campaigns-last-updated')).toContainText('Last updated');

    const [listRes, sumRes] = await Promise.all([
      page.waitForResponse((r) => /\/api\/campaigns(\?|$)/.test(r.url())),
      page.waitForResponse((r) => r.url().includes('/api/campaigns/summary')),
      page.getByRole('button', { name: 'REFRESH FEED' }).click(),
    ]);
    expect(listRes.status()).toBe(200);
    expect(sumRes.status()).toBe(200);
    await expect(page.getByTestId('campaigns-refresh-note')).toHaveText('Campaign feed is up to date.');

    // New authoritative data appears on the next refresh
    await withTestDb((m) => m.Campaign.create({
      campaignId: NEW_ID, sourceIPs: ['198.51.100.201', '198.51.100.202'], threatLevel: 'HIGH', maxDeceptionScore: 99, lastSeen: new Date(),
    }));
    await page.getByRole('button', { name: 'REFRESH FEED' }).click();
    await expect(page.getByTestId('campaigns-refresh-note')).toHaveText('Campaign feed updated with the latest stored campaigns.');
    await expect(kpiValue(page, 'Detected Campaigns')).toHaveText(String(stored + 1));
    await expect(kpiValue(page, 'Max Deception')).toHaveText('99');
    const row = page.locator('tbody tr').filter({ hasText: NEW_ID });
    await expect(row).toHaveCount(1);

    // ANALYZE opens the detail panel, and a refresh keeps it on the same campaign
    await row.getByRole('button', { name: 'ANALYZE' }).click();
    await expect(page.getByText(`Campaign Details: ${NEW_ID}`)).toBeVisible();
    await page.getByRole('button', { name: 'REFRESH FEED' }).click();
    await expect(page.getByTestId('campaigns-refresh-note')).toHaveText('Campaign feed is up to date.');
    await expect(page.getByText(`Campaign Details: ${NEW_ID}`)).toBeVisible();
    await expect(page.locator('tbody tr').filter({ hasText: NEW_ID })).toHaveCount(1);

    // Refreshing never created or merged campaigns
    expect(await withTestDb((m) => m.Campaign.countDocuments())).toBe(stored + 1);
  });

  test('API outage shows the alert and Retry recovers', async ({ page, loginAs }) => {
    await loginAs('analyst');
    await page.goto('/dashboard/campaigns');
    await expect(page.getByTestId('campaigns-last-updated')).toContainText('Last updated');
    await page.route('**/api/campaigns/summary', (route) => route.abort('connectionfailed'));
    await page.getByRole('button', { name: 'REFRESH FEED' }).click();
    const alert = page.locator('[role="alert"]').filter({ hasText: /Campaign telemetry is unavailable \(the server could not be reached\)/ });
    await expect(alert).toBeVisible();
    await page.unroute('**/api/campaigns/summary');
    await alert.getByRole('button', { name: /Retry/i }).click();
    await expect(alert).not.toBeVisible();
  });
});

test.describe('User Management: Edit User', () => {
  let email;
  test.beforeEach(async ({ browserName }) => {
    email = `e2e.edit.${browserName}.${Date.now()}@sentinel.test`;
    await withTestDb((m) => m.User.create({ name: 'Edit Target', email, password: 'EditTarget123!', role: 'viewer', department: 'SOC' }));
  });
  test.afterEach(async () => {
    await withTestDb((m) => m.User.deleteMany({ email }));
  });

  const rowFor = (page, text) => page.locator('.sentinel-table-scroll table tbody tr').filter({ hasText: text });
  const statValue = (page, label) => page.getByTestId('user-stats').getByText(label, { exact: true }).locator('xpath=following-sibling::div[1]');

  test('admin edits name, department and role; changes persist, totals update, sessions are revoked', async ({ page, loginAs }) => {
    await loginAs('admin');
    await page.goto('/dashboard/users');
    const analystsBefore = Number(await statValue(page, 'ANALYST').textContent());

    await rowFor(page, email).getByRole('button', { name: 'Edit Edit Target' }).click();
    const dialog = page.getByRole('dialog', { name: 'Edit User' });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText(email);
    await expect(dialog.getByLabel('Display name')).toHaveValue('Edit Target');
    await expect(dialog.getByLabel('Role')).toHaveValue('viewer');

    // Client-side validation: nothing is sent
    let puts = 0;
    page.on('request', (r) => { if (r.method() === 'PUT' && r.url().includes('/api/users/')) puts += 1; });
    await dialog.getByLabel('Display name').fill('a');
    await dialog.getByRole('button', { name: 'Save changes' }).click();
    await expect(dialog.getByText('Name must be 2-50 characters.')).toBeVisible();
    expect(puts).toBe(0);

    await dialog.getByLabel('Display name').fill('Edited Operator');
    await dialog.getByLabel('Department').fill('Threat Intel');
    await dialog.getByLabel('Role').selectOption('analyst');
    await expect(dialog.getByText(/signs this user out of every session/)).toBeVisible();
    const [res] = await Promise.all([
      page.waitForResponse((r) => r.request().method() === 'PUT' && r.url().includes('/api/users/')),
      dialog.getByRole('button', { name: 'Save changes' }).click(),
    ]);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.data.changed.sort()).toEqual(['department', 'name', 'role']);
    expect(JSON.stringify(body)).not.toMatch(/"password"/);
    await expect(dialog).toHaveCount(0);
    await expect(page.getByText(/Edited Operator updated\. Their sessions were signed out\./)).toBeVisible();
    await expect(rowFor(page, email)).toContainText('Edited Operator');
    await expect(rowFor(page, email)).toContainText('analyst');
    await expect(statValue(page, 'ANALYST')).toHaveText(String(analystsBefore + 1));

    const saved = await withTestDb((m) => m.User.findOne({ email }).lean());
    expect(saved).toMatchObject({ name: 'Edited Operator', department: 'Threat Intel', role: 'analyst', authVersion: 1, tokenVersion: 1 });

    await page.reload();
    await expect(rowFor(page, email)).toContainText('Edited Operator');
    await expect(rowFor(page, email)).toContainText('analyst');
  });

  test('cancel sends nothing; own role is locked; a concurrent change produces a conflict', async ({ page, loginAs }) => {
    await loginAs('admin');
    await page.goto('/dashboard/users');
    let puts = 0;
    page.on('request', (r) => { if (r.method() === 'PUT' && r.url().includes('/api/users/')) puts += 1; });

    await rowFor(page, email).getByRole('button', { name: 'Edit Edit Target' }).click();
    let dialog = page.getByRole('dialog', { name: 'Edit User' });
    await dialog.getByLabel('Display name').fill('Never Saved');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toHaveCount(0);
    expect(puts).toBe(0);
    expect((await withTestDb((m) => m.User.findOne({ email }).lean())).name).toBe('Edit Target');

    // The signed-in administrator cannot change its own role or status
    await rowFor(page, SEEDED_USERS.admin.email).getByRole('button', { name: `Edit ${SEEDED_USERS.admin.name}` }).click();
    dialog = page.getByRole('dialog', { name: 'Edit User' });
    await expect(dialog.getByLabel('Role')).toBeDisabled();
    await expect(dialog.getByLabel('Status')).toBeDisabled();
    await expect(dialog.getByText(/cannot change your own role or status/)).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);

    // Someone else changes the record after the form opened: the stale save is refused
    await rowFor(page, email).getByRole('button', { name: 'Edit Edit Target' }).click();
    dialog = page.getByRole('dialog', { name: 'Edit User' });
    await withTestDb((m) => m.User.updateOne({ email }, { $set: { department: 'Changed Elsewhere', updatedAt: new Date(Date.now() + 5000) } }));
    await dialog.getByLabel('Display name').fill('Stale Edit');
    const [res] = await Promise.all([
      page.waitForResponse((r) => r.request().method() === 'PUT' && r.url().includes('/api/users/')),
      dialog.getByRole('button', { name: 'Save changes' }).click(),
    ]);
    expect(res.status()).toBe(409);
    await expect(page.getByText(/changed by someone else/)).toBeVisible();
    await expect(dialog).toHaveCount(0);
    const saved = await withTestDb((m) => m.User.findOne({ email }).lean());
    expect(saved).toMatchObject({ name: 'Edit Target', department: 'Changed Elsewhere' });
  });

  test('server rules hold for the API: unsupported fields, analysts, viewers and the last active admin', async ({ playwright }) => {
    const target = await withTestDb((m) => m.User.findOne({ email }).lean());
    const admin = await withTestDb((m) => m.User.findOne({ email: SEEDED_USERS.admin.email }).lean());
    const call = async (who, id, data) => {
      const ctx = await playwright.request.newContext({ baseURL: 'http://127.0.0.1:3000' });
      try {
        const csrf = (await (await ctx.get('/api/auth/csrf', { headers: { Origin: 'http://127.0.0.1:3000' } })).json()).data.csrfToken;
        const login = await ctx.post('/api/auth/login', {
          data: { email: SEEDED_USERS[who].email, password: SEEDED_USERS[who].password },
          headers: { 'X-CSRF-Token': csrf, Origin: 'http://127.0.0.1:3000' },
        });
        const token = (await login.json()).data.token;
        const res = await ctx.put(`/api/users/${id}`, {
          data,
          headers: { Authorization: `Bearer ${token}`, 'X-CSRF-Token': csrf, Origin: 'http://127.0.0.1:3000' },
        });
        return { status: res.status(), body: await res.json() };
      } finally {
        await ctx.dispose();
      }
    };
    expect((await call('analyst', target._id, { role: 'admin' })).status).toBe(403);
    expect((await call('viewer', target._id, { role: 'admin' })).status).toBe(403);
    expect((await call('admin', target._id, { email: SEEDED_USERS.admin.email })).status).toBe(422);
    expect((await call('admin', target._id, { password: 'Changed123456!' })).status).toBe(422);
    const self = await call('admin', admin._id, { role: 'viewer' });
    expect(self.status).toBe(400);
    expect(self.body.error).toMatch(/cannot demote their own account/);
    const after = await withTestDb((m) => m.User.findOne({ email }).lean());
    expect(after).toMatchObject({ role: 'viewer', email, authVersion: 0 });
    expect((await withTestDb((m) => m.User.findOne({ email: SEEDED_USERS.admin.email }).lean())).role).toBe('admin');
  });

  test('Remove still works for non-admin operators', async ({ page, loginAs }) => {
    await loginAs('admin');
    await page.goto('/dashboard/users');
    page.once('dialog', (d) => d.accept());
    await rowFor(page, email).getByRole('button', { name: 'Remove' }).click();
    await expect(page.getByText('Edit Target removed')).toBeVisible();
    await expect(rowFor(page, email)).toHaveCount(0);
    expect(await withTestDb((m) => m.User.countDocuments({ email }))).toBe(0);
    await expect(rowFor(page, SEEDED_USERS.admin.email).getByRole('button', { name: 'Remove' })).toHaveCount(0);
  });
});
