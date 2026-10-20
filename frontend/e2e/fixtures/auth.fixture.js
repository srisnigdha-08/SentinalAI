import { test as base, expect } from '@playwright/test';
import { LoginPage } from './pom/LoginPage.js';
import { DashboardPage } from './pom/DashboardPage.js';
import { ThreatLogsPage } from './pom/ThreatLogsPage.js';
import { SettingsPage } from './pom/SettingsPage.js';
import { UserManagementPage } from './pom/UserManagementPage.js';
import { ChangePasswordPage } from './pom/ChangePasswordPage.js';
import { ModalComponent } from './pom/ModalComponent.js';
import { SEEDED_USERS } from '../global-setup.js';

export { SEEDED_USERS };

export const test = base.extend({
  // Page Object Models
  loginPage: async ({ page }, use) => {
    await use(new LoginPage(page));
  },
  dashboardPage: async ({ page }, use) => {
    await use(new DashboardPage(page));
  },
  threatLogsPage: async ({ page }, use) => {
    await use(new ThreatLogsPage(page));
  },
  settingsPage: async ({ page }, use) => {
    await use(new SettingsPage(page));
  },
  userManagementPage: async ({ page }, use) => {
    await use(new UserManagementPage(page));
  },
  changePasswordPage: async ({ page }, use) => {
    await use(new ChangePasswordPage(page));
  },
  modal: async ({ page }, use) => {
    await use(new ModalComponent(page));
  },

  // Auth Helpers
  loginAs: async ({ page }, use) => {
    const fn = async (role = 'admin') => {
      const user = SEEDED_USERS[role];
      if (!user) throw new Error(`Unknown seeded user role: ${role}`);
      const loginPage = new LoginPage(page);
      await loginPage.goto();
      await loginPage.login(user.email, user.password);
      if (user.mustChangePassword) {
        await page.waitForURL('**/change-password');
      } else {
        await page.waitForURL('**/dashboard');
      }
    };
    await use(fn);
  },

  // Role-authenticated Pages
  adminPage: async ({ page }, use) => {
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.admin.email, SEEDED_USERS.admin.password);
    await page.waitForURL('**/dashboard');
    await use(page);
  },

  analystPage: async ({ page }, use) => {
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.analyst.email, SEEDED_USERS.analyst.password);
    await page.waitForURL('**/dashboard');
    await use(page);
  },

  viewerPage: async ({ page }, use) => {
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.viewer.email, SEEDED_USERS.viewer.password);
    await page.waitForURL('**/dashboard');
    await use(page);
  },

  mustChangePage: async ({ page }, use) => {
    const loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginPage.login(SEEDED_USERS.mustChange.email, SEEDED_USERS.mustChange.password);
    await page.waitForURL('**/change-password');
    await use(page);
  },
});

export { expect };
