import { defineConfig, devices } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig({
  testDir: './e2e',
  globalSetup: './e2e/global-setup.js',
  fullyParallel: false, // Stateful suites share database and session lifecycle
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1, // Single worker avoids database race conditions
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],
  timeout: 60000,
  expect: {
    timeout: 10000,
  },
  use: {
    baseURL: 'http://127.0.0.1:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 15000,
    navigationTimeout: 20000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    {
      name: 'Mobile (Pixel 5)',
      use: { ...devices['Pixel 5'] },
      testMatch: /responsive\.spec\.js/,
    },
    {
      name: 'Tablet (iPad)',
      use: { ...devices['iPad (gen 7)'] },
      testMatch: /responsive\.spec\.js/,
    },
  ],
  webServer: [
    {
      command: 'node ../scripts/start-test-backend.cjs',
      url: 'http://127.0.0.1:5000/',
      // Never attach to an already-running backend: it may be the demo backend on sentinel-db, and the
      // test-DB guard lives in start-test-backend.cjs. If port 5000 is busy, stop that server first.
      reuseExistingServer: false,
      timeout: 30000,
    },
    {
      command: 'npm run dev -- --host 127.0.0.1',
      url: 'http://127.0.0.1:3000/',
      reuseExistingServer: !process.env.CI,
      timeout: 30000,
    },
  ],
});
