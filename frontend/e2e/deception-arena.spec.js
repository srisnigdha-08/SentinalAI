import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { test, expect } from './fixtures/auth.fixture.js';
import { validateTestDatabaseName } from './dbGuard.js';

// Deception Arena on the real route and test backend. Experiments are seeded into the isolated test database from
// fixtures/deceptionArenaRuns.json, which the real runner (ai-engine/demo/deception_arena.py) produced. The spec
// also seeds one Cowrie session for the observational panel, and removes exactly what it created.
const require = createRequire(import.meta.url);
const mongoose = require('../../backend/node_modules/mongoose');
const { v4: uuidv4 } = require('../../backend/node_modules/uuid');
const DeceptionExperiment = require('../../backend/models/DeceptionExperiment');
const HoneypotSession = require('../../backend/models/HoneypotSession');
const RUNS = JSON.parse(readFileSync(new URL('./fixtures/deceptionArenaRuns.json', import.meta.url), 'utf8'));

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinelai_test';
const seeded = { experiments: [] };

const seedRun = async (name, run, at) => {
  const events = [{ type: 'EXPERIMENT_CREATED', at, detail: run.config.scenario }, { type: 'RUN_STARTED', at, detail: 'runner deception_arena/1' }];
  for (const t of run.trials) {
    if (t.decision) events.push({ type: 'PERSONA_RECOMMENDED', at: t.startedAt, detail: `${t.decision.state} -> ${t.decision.recommendedPersona}` });
    events.push({ type: 'TRIAL_COMPLETED', at: t.endedAt, detail: `${t.strategy} #${t.index + 1}` });
  }
  events.push({ type: 'RESULTS_AGGREGATED', at, detail: `${run.trials.length} trials recorded` });
  const doc = await DeceptionExperiment.create({
    experimentId: uuidv4(), name, description: 'e2e seed from the real runner', ...run.config, adaptiveEnabled: true, status: 'COMPLETED',
    createdBy: { email: 'analyst@sentinel.test', role: 'analyst' }, startedAt: at, completedAt: at, heartbeatAt: at,
    provenance: run.provenance, trials: run.trials, events,
  });
  seeded.experiments.push(doc._id);
  return doc.experimentId;
};

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  validateTestDatabaseName(MONGO_URI);
  if (mongoose.connection.readyState === 0) await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
  seeded.sim = await seedRun('Arena e2e: simulated attacker', RUNS.simulated, new Date());
  seeded.scripted = await seedRun('Arena e2e: scripted recon', RUNS.scripted, new Date(Date.now() - 60000));
  const s = await HoneypotSession.create({ sessionId: 'arena-e2e-301', sourceIP: '198.51.100.81', servedProfile: 'ubuntu_22', status: 'closed', startTime: new Date(), durationSeconds: 42, commandCount: 2, commands: [{ command: 'id' }, { command: 'uname -a' }] });
  seeded.session = s._id;
});

test.afterAll(async () => {
  await DeceptionExperiment.deleteMany({ $or: [{ _id: { $in: seeded.experiments } }, { name: /^Arena e2e/ }] });
  await HoneypotSession.deleteOne({ _id: seeded.session });
  await mongoose.disconnect();
});

const watchWrites = (page) => {
  const writes = [];
  page.on('request', (r) => { if (r.url().includes('/api/') && !['GET', 'OPTIONS'].includes(r.method()) && !/\/api\/auth\//.test(r.url())) writes.push(`${r.method()} ${r.url()}`); });
  return writes;
};

test('analyst inspects a completed simulated experiment side by side', async ({ page, loginAs }) => {
  const writes = watchWrites(page);
  await loginAs('analyst');
  await page.locator('.sentinel-sidebar').getByRole('link', { name: /Deception Arena/i }).click();
  await expect(page).toHaveURL(/\/dashboard\/deception-arena$/);
  await expect(page.getByRole('heading', { name: /Deception Arena/i })).toBeVisible();
  await expect(page.getByTestId('arena-live-mode')).toContainText('Adaptive engagement benefit not yet established');

  await page.getByTestId('arena-item').filter({ hasText: 'Arena e2e: simulated attacker' }).click();
  const d = page.getByTestId('arena-details');
  await expect(d.getByTestId('arena-name')).toHaveText('Arena e2e: simulated attacker');
  await expect(d.getByTestId('arena-static')).toContainText('Fixed persona: centos_7');
  await expect(d.getByTestId('arena-static')).toContainText('Trials recorded12');
  await expect(d.getByTestId('arena-adaptive')).toContainText('Personas served:');
  await expect(d.getByTestId('arena-adaptive')).toContainText('Recommendations applied');
  await expect(d.getByTestId('arena-paired')).toContainText('12 pairs');
  await expect(d.getByTestId('arena-headline')).not.toBeEmpty();
  await expect(d.getByTestId('arena-findings').locator('[data-code="SIM_ASSUMPTIONS"]')).toContainText('real attackers');
  await expect(d.getByTestId('arena-findings').locator('[data-code="REWARD_NOT_OUTCOME"]')).toBeVisible();
  await expect(d.getByTestId('arena-live-caveat')).toContainText('not yet established');
  // Charts are drawn from the recorded trials: one bar per trial per strategy
  await expect(d.getByTestId('arena-chart-commands').locator('.recharts-bar-rectangle')).toHaveCount(24);
  // Decision explainer: one row per adaptive trial, recommendation and application kept apart
  await expect(d.getByTestId('arena-decisions').locator('tbody tr')).toHaveCount(12);
  await expect(d.getByTestId('arena-decisions')).toContainText('RECOMMENDED');
  await expect(d.getByTestId('arena-timeline')).toContainText('PERSONA RECOMMENDED');
  await expect(d.getByTestId('arena-config')).toContainText('Unchanged before vs after the run');

  const download = page.waitForEvent('download');
  await d.getByRole('button', { name: 'Export CSV' }).click();
  expect((await download).suggestedFilename()).toMatch(/^deception-arena-.+\.csv$/);

  // Supporting recorded sessions open in the Attack Time Machine (observational, labelled as such)
  await expect(page.getByTestId('arena-observational')).toContainText('ubuntu_22');
  await page.getByRole('link', { name: 'Replay session arena-e2e-301 in the Attack Time Machine' }).click();
  await expect(page).toHaveURL(new RegExp(`/dashboard/attack-time-machine\\?session=${seeded.session}`));
  await expect(page.getByTestId('atm-session-id')).toHaveText('arena-e2e-301');

  expect(writes).toEqual([]);
});

test('scripted experiment: small-sample warning and no engagement claim', async ({ page, loginAs }) => {
  await loginAs('analyst');
  await page.goto(`/dashboard/deception-arena?experiment=${seeded.scripted}`);
  const d = page.getByTestId('arena-details');
  await expect(d.getByTestId('arena-headline')).toHaveText('The scripted scenario does not measure adaptive attacker engagement.');
  await expect(d.getByTestId('arena-small-sample')).toContainText('3 paired trials');
  await expect(d.getByTestId('arena-findings').locator('[data-code="MECHANICS"]')).toContainText('identical sessions');
  await page.screenshot({ path: 'test-results/deception-arena.png', fullPage: true });
});

test('filters and empty state', async ({ page, loginAs }) => {
  await loginAs('analyst');
  await page.goto('/dashboard/deception-arena');
  await page.getByTestId('arena-filter-status').selectOption('FAILED');
  await expect(page.getByTestId('arena-empty')).toContainText('No experiment matches these filters.');
  await page.route(/\/api\/deception-arena\/experiments(\?|$)/, (r) => r.fulfill({ status: 200, json: { success: true, data: [], pagination: { total: 0, page: 1, limit: 50, pages: 0 } } }));
  await page.goto('/dashboard/deception-arena');
  await expect(page.getByTestId('arena-empty')).toContainText('No experiment has been created yet.');
});

test('analyst creates a bounded experiment and cancels it before any runner claims it', async ({ page, loginAs }) => {
  await loginAs('analyst');
  await page.goto('/dashboard/deception-arena');
  await page.getByTestId('arena-new').click();
  await page.getByTestId('arena-form-name').fill('Arena e2e: created in browser');
  await page.getByTestId('arena-form-scenario').selectOption('scripted_dropper');
  await page.getByTestId('arena-form-submit').click();
  const d = page.getByTestId('arena-details');
  await expect(d.getByTestId('arena-name')).toHaveText('Arena e2e: created in browser');
  await expect(d).toContainText('WAITING FOR RUNNER');
  await expect(d.getByTestId('arena-runner-hint')).toContainText('demo/deception_arena.py');
  await expect(d.getByTestId('arena-no-trials')).toBeVisible();
  await d.getByTestId('arena-cancel').click();
  await expect(d).toContainText('CANCELLED');
  await expect(d.getByTestId('arena-headline')).toContainText('has not completed');
});

test('viewer can read results but cannot create or cancel; unauthenticated access is refused', async ({ page, loginAs, request }) => {
  await loginAs('viewer');
  await page.goto(`/dashboard/deception-arena?experiment=${seeded.sim}`);
  await expect(page.getByTestId('arena-details')).toBeVisible();
  await expect(page.getByTestId('arena-new')).toHaveCount(0);
  await expect(page.getByTestId('arena-cancel')).toHaveCount(0);
  expect((await request.get('http://127.0.0.1:5000/api/deception-arena/experiments')).status()).toBe(401);
  expect((await request.post('http://127.0.0.1:5000/api/deception-arena/experiments', { data: { name: 'x' } })).status()).toBe(401);
  expect((await request.post(`http://127.0.0.1:5000/api/deception-arena/runner/${seeded.sim}/claim`)).status()).toBe(401);
});

test('narrow screen: list and details fit without page-level horizontal scroll', async ({ page, loginAs }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await loginAs('analyst');
  await page.goto(`/dashboard/deception-arena?experiment=${seeded.sim}`);
  await expect(page.getByTestId('arena-details')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
});
