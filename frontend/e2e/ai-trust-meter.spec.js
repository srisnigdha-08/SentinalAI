import { createRequire } from 'module';
import { test, expect } from './fixtures/auth.fixture.js';
import { validateTestDatabaseName } from './dbGuard.js';

// AI Trust Meter on the real route, test backend and isolated test database. The spec seeds its own predictions
// (documentation-range IPs 198.51.100.7x) and removes exactly those afterwards. The SHAP endpoint needs the AI
// engine to re-score the stored vector, which the browser suite does not run, so only that response is mocked
// (as in explanation.spec.js); everything else is real.
const require = createRequire(import.meta.url);
const mongoose = require('../../backend/node_modules/mongoose');
const AIPrediction = require('../../backend/models/AIPrediction');
const ThreatLog = require('../../backend/models/ThreatLog');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinelai_test';
const seeded = {};
const now = () => new Date();
const pred = (over) => ({
  inputSource: 'network_traffic', predictedClass: 'DDoS', classProbabilities: { DDoS: 0.97, BENIGN: 0.02, PortScan: 0.01 },
  threatScore: 0.94, modelVersion: 'xgb_cicids_v1', modelType: 'ensemble', isAnomaly: true, anomalyScore: 0.4,
  incompleteInput: false, needsReview: false, verified: false, createdAt: now(), updatedAt: now(), ...over,
});

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  validateTestDatabaseName(MONGO_URI);
  if (mongoose.connection.readyState === 0) await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
  const col = AIPrediction.collection;
  seeded.incomplete = (await col.insertOne(pred({
    sourceIP: '198.51.100.71', incompleteInput: true, featureVector: Array(53).fill(1), featureSchemaVersion: 'v2.1_53feat',
    defaultedFeatures: ['flow_duration', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags'],
  }))).insertedId;
  seeded.historical = (await col.insertOne(pred({
    sourceIP: '198.51.100.72', predictedClass: 'PortScan', classProbabilities: { PortScan: 0.88, BENIGN: 0.12 }, threatScore: 0.91,
    isAnomaly: false, anomalyScore: 0, createdAt: new Date(Date.now() - 60000),
  }))).insertedId;
  seeded.complete = (await col.insertOne(pred({ sourceIP: '198.51.100.73', defaultedFeatures: [], createdAt: new Date(Date.now() - 120000) }))).insertedId;
  const threat = await ThreatLog.create({
    sourceIP: '198.51.100.71', severity: 'CRITICAL', attackType: 'DDoS', aiScore: 0.94, status: 'MONITORING',
    predictionId: seeded.incomplete, notes: 'ai-trust-meter e2e',
  });
  seeded.threat = threat._id;
  await col.updateOne({ _id: seeded.incomplete }, { $set: { generatedThreat: threat._id } });
});

test.afterAll(async () => {
  await AIPrediction.collection.deleteMany({ _id: { $in: [seeded.incomplete, seeded.historical, seeded.complete].filter(Boolean) } });
  await ThreatLog.deleteOne({ _id: seeded.threat });
  await mongoose.disconnect();
});

const search = async (page) => {
  await page.getByTestId('trust-search').fill('198.51.100.7');
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.getByTestId('trust-row')).toHaveCount(3);
};

test('analyst inspects an incomplete prediction end to end', async ({ page, loginAs }) => {
  const writes = [];
  page.on('request', (r) => { if (r.url().includes('/api/') && !['GET', 'OPTIONS'].includes(r.method()) && !/\/api\/auth\//.test(r.url())) writes.push(`${r.method()} ${r.url()}`); });
  await page.route('**/api/threats/*/explanation', (route) => route.fulfill({ status: 200, json: { success: true, data: {
    threatId: String(seeded.threat), predictionId: String(seeded.incomplete), predictedAt: new Date().toISOString(), modelVersion: 'xgb_cicids_v1',
    featureSchemaVersion: 'v2.1_53feat', predictedClass: 'DDoS', explainedClass: 'DDoS', threatScore: 0.94, confidence: 0.97, baseValue: -0.2, reproduced: true,
    contributions: [{ feature: 'init_win_bytes_forward', contribution: 2.1, value: 8192 }],
  } } }));
  await loginAs('analyst');

  await page.locator('.sentinel-sidebar').getByRole('link', { name: /AI Trust Meter/i }).click();
  await expect(page).toHaveURL(/\/dashboard\/ai-trust-meter$/);
  await expect(page.getByRole('heading', { name: /AI Trust Meter/i })).toBeVisible();
  await expect(page.getByTestId('trust-limitations')).toContainText('15.2% attack recall');

  await search(page);
  await page.getByTestId('trust-state').selectOption('INCOMPLETE');
  await expect(page.getByTestId('trust-row')).toHaveCount(1);
  await expect(page.getByTestId('trust-row')).toContainText('4 input features were missing');
  await page.getByRole('button', { name: /Open trust assessment for DDoS prediction from 198\.51\.100\.71/ }).click();

  const details = page.getByTestId('trust-details');
  await expect(details.getByTestId('trust-class')).toHaveText('DDoS');
  await expect(details.locator('[data-trust-state="INCOMPLETE"]')).toBeVisible();
  await expect(details.getByTestId('trust-confidence')).toContainText('97.0%');
  await expect(details.getByTestId('trust-confidence')).toContainText('not a measured probability that this prediction is correct');
  await expect(details.getByTestId('trust-threat-score')).toContainText('94.0%');
  await expect(details.getByTestId('trust-input')).toContainText('4 of 50 caller features missing');
  await expect(details.getByTestId('trust-defaulted')).toContainText('flow_duration, bwd_psh_flags');
  await expect(details.locator('[data-code="DEFAULTED_FEATURES"]')).toHaveAttribute('open', '');
  await details.locator('[data-code="FABRICATED_DEFAULTS"] summary').click();
  await expect(details.locator('[data-code="FABRICATED_DEFAULTS"]')).toContainText('SOURCE FIELD');
  await expect(details.getByTestId('trust-anomaly')).toContainText('Flagged as unusual');

  await details.getByTestId('trust-open-shap').click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);

  await page.getByTestId('trust-back').click();
  await expect(page.getByTestId('trust-search')).toHaveValue('198.51.100.7');
  await expect(page.getByTestId('trust-row')).toHaveCount(1);

  // An older record without completeness metadata: insufficient evidence, never "complete"
  await page.getByTestId('trust-state').selectOption('');
  await page.getByRole('button', { name: /PortScan prediction from 198\.51\.100\.72/ }).click();
  await expect(details.locator('[data-trust-state="INSUFFICIENT"]')).toBeVisible();
  await expect(details.getByTestId('trust-input')).toContainText('Completeness not recorded');
  await expect(details.locator('[data-code="COMPLETENESS_UNVERIFIED"]')).toContainText('does not prove that all features were supplied');
  await expect(details).toContainText('No threat record was raised from this prediction');

  expect(writes).toEqual([]);
  await page.screenshot({ path: 'test-results/ai-trust-meter.png', fullPage: true });
});

test('entry points from Threat Logs and AI Analytics', async ({ page, loginAs }) => {
  await loginAs('analyst');
  await page.goto('/dashboard/threats');
  await page.getByRole('link', { name: 'View AI Trust Assessment' }).first().waitFor();
  const row = page.locator('tr', { hasText: '198.51.100.71' });
  await row.getByRole('link', { name: 'View AI Trust Assessment' }).click();
  await expect(page).toHaveURL(new RegExp(`prediction=${seeded.incomplete}`));
  await expect(page.getByTestId('trust-class')).toHaveText('DDoS');

  await page.goto('/dashboard/ai');
  await page.getByTestId('ai-trust-entry').click();
  await expect(page).toHaveURL(/\/dashboard\/ai-trust-meter$/);
});

test('viewer sees redacted IPs and no SHAP access', async ({ page, loginAs }) => {
  await loginAs('viewer');
  await page.goto(`/dashboard/ai-trust-meter?prediction=${seeded.incomplete}`);
  await expect(page.getByTestId('trust-details')).toContainText('198.51.100.xxx');
  await expect(page.getByTestId('trust-details')).not.toContainText('198.51.100.71');
  await expect(page.getByTestId('trust-shap-unavailable')).toContainText('analyst and admin roles');
});

test('empty and error states', async ({ page, loginAs }) => {
  await loginAs('analyst');
  await page.goto('/dashboard/ai-trust-meter?q=no-such-prediction-xyz');
  await expect(page.getByTestId('trust-empty')).toContainText('No stored ML prediction matches these filters.');
  await page.route(/\/api\/ai\/trust\/predictions(\?|$)/, (route) => route.fulfill({ status: 500, json: { success: false } }));
  await page.goto('/dashboard/ai-trust-meter');
  await expect(page.getByRole('alert')).toContainText('Predictions could not be loaded.');
});

test('unauthenticated access is redirected and the API refuses', async ({ page, request }) => {
  await page.goto('/dashboard/ai-trust-meter');
  await expect(page).toHaveURL(/\/login/);
  expect((await request.get('http://127.0.0.1:5000/api/ai/trust/predictions')).status()).toBe(401);
  expect((await request.get(`http://127.0.0.1:5000/api/ai/trust/predictions/${seeded.incomplete}`)).status()).toBe(401);
});

test('narrow screen: list and details fit without page-level horizontal scroll', async ({ page, loginAs }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await loginAs('analyst');
  for (const url of ['/dashboard/ai-trust-meter?q=198.51.100.7', `/dashboard/ai-trust-meter?prediction=${seeded.incomplete}`]) {
    await page.goto(url);
    await expect(page.getByTestId(url.includes('prediction=') ? 'trust-details' : 'trust-table')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
  }
});
