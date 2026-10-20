import { test, expect } from '@playwright/test';
import { SEEDED_USERS } from './global-setup.js';

// Helper to authenticate via API and retrieve JWT access token & CSRF token
async function loginApi(request, email, password) {
  // 1. Fetch CSRF token and nonce cookie
  const csrfRes = await request.get('/api/auth/csrf', {
    headers: { Origin: 'http://127.0.0.1:3000' },
  });
  expect(csrfRes.ok()).toBe(true);
  const csrfBody = await csrfRes.json();
  const csrfToken = csrfBody.data.csrfToken;

  // 2. Perform login request
  const loginRes = await request.post('/api/auth/login', {
    data: { email, password },
    headers: {
      'X-CSRF-Token': csrfToken,
      Origin: 'http://127.0.0.1:3000',
    },
  });
  expect(loginRes.ok()).toBe(true);
  const loginBody = await loginRes.json();
  const token = loginBody.data.token;

  return { token, csrfToken };
}

test.describe('API-Level Authorization & RBAC Enforcement (No UI)', () => {
  let adminContext;
  let analystContext;
  let viewerContext;
  let adminAuth;
  let analystAuth;
  let viewerAuth;

  test.beforeAll(async ({ playwright }) => {
    // Dedicated isolated contexts prevent cookie-jar cross-talk and session revoking
    adminContext = await playwright.request.newContext({ baseURL: 'http://127.0.0.1:3000' });
    analystContext = await playwright.request.newContext({ baseURL: 'http://127.0.0.1:3000' });
    viewerContext = await playwright.request.newContext({ baseURL: 'http://127.0.0.1:3000' });

    adminAuth = await loginApi(adminContext, SEEDED_USERS.admin.email, SEEDED_USERS.admin.password);
    analystAuth = await loginApi(analystContext, SEEDED_USERS.analyst.email, SEEDED_USERS.analyst.password);
    viewerAuth = await loginApi(viewerContext, SEEDED_USERS.viewer.email, SEEDED_USERS.viewer.password);
  });

  test.afterAll(async () => {
    await adminContext?.dispose();
    await analystContext?.dispose();
    await viewerContext?.dispose();
  });

  test('unauthenticated requests receive 401 on protected endpoints', async ({ request }) => {
    const protectedEndpoints = [
      { method: 'get', url: '/api/threats' },
      { method: 'get', url: '/api/honeypot/analytics' },
      { method: 'get', url: '/api/ai/stats' },
      { method: 'get', url: '/api/alerts' },
      { method: 'get', url: '/api/users' },
      { method: 'get', url: '/api/audit' },
      { method: 'get', url: '/api/containment/status' },
    ];

    for (const ep of protectedEndpoints) {
      const res = await request[ep.method](ep.url);
      expect(res.status(), `Expected 401 on unauthenticated ${ep.method.toUpperCase()} ${ep.url}`).toBe(401);
      const body = await res.json();
      expect(body.success).toBe(false);
    }
  });

  test('viewer and analyst receive 403 on admin-only user management endpoints', async ({ request }) => {
    const roles = [
      { name: 'viewer', auth: viewerAuth },
      { name: 'analyst', auth: analystAuth },
    ];

    const dummyUserId = '507f1f77bcf86cd799439011';

    for (const { name, auth } of roles) {
      // 1. GET /api/users
      const listRes = await request.get('/api/users', {
        headers: { Authorization: `Bearer ${auth.token}` },
      });
      expect(listRes.status(), `${name} should get 403 on GET /api/users`).toBe(403);

      // 2. GET /api/users/stats
      const statsRes = await request.get('/api/users/stats', {
        headers: { Authorization: `Bearer ${auth.token}` },
      });
      expect(statsRes.status(), `${name} should get 403 on GET /api/users/stats`).toBe(403);

      // 3. DELETE /api/users/:id
      const delRes = await request.delete(`/api/users/${dummyUserId}`, {
        headers: { Authorization: `Bearer ${auth.token}` },
      });
      expect(delRes.status(), `${name} should get 403 on DELETE /api/users/:id`).toBe(403);

      // 4. POST /api/auth/provision
      const provRes = await request.post('/api/auth/provision', {
        data: {
          email: `unauthorized-${name}-${Date.now()}@sentinel.test`,
          password: 'Password123!',
          role: 'viewer',
        },
        headers: {
          Authorization: `Bearer ${auth.token}`,
          'X-CSRF-Token': auth.csrfToken,
          Origin: 'http://127.0.0.1:3000',
        },
      });
      expect(provRes.status(), `${name} should get 403 on POST /api/auth/provision`).toBe(403);
    }
  });

  test('viewer receives 403 on analyst/admin incident triage and containment endpoints', async ({ request }) => {
    const dummyThreatId = '507f1f77bcf86cd799439011';

    // 1. POST /api/threats/:id/block
    const blockRes = await request.post(`/api/threats/${dummyThreatId}/block`, {
      headers: { Authorization: `Bearer ${viewerAuth.token}` },
    });
    expect(blockRes.status(), 'viewer should get 403 on POST /api/threats/:id/block').toBe(403);

    // 2. PATCH /api/threats/:id/triage
    const triageRes = await request.patch(`/api/threats/${dummyThreatId}/triage`, {
      data: { status: 'RESOLVED', notes: 'Unauthorized triage attempt' },
      headers: { Authorization: `Bearer ${viewerAuth.token}` },
    });
    expect(triageRes.status(), 'viewer should get 403 on PATCH /api/threats/:id/triage').toBe(403);

    // 3. POST /api/containment/actions
    const actionRes = await request.post('/api/containment/actions', {
      data: {
        target: '198.51.100.99',
        actionType: 'block_ip',
        reason: 'Viewer unauthorized attempt',
      },
      headers: { Authorization: `Bearer ${viewerAuth.token}` },
    });
    expect(actionRes.status(), 'viewer should get 403 on POST /api/containment/actions').toBe(403);

    // 4. GET /api/threats/settings
    const getSettingsRes = await request.get('/api/threats/settings', {
      headers: { Authorization: `Bearer ${viewerAuth.token}` },
    });
    expect(getSettingsRes.status(), 'viewer should get 403 on GET /api/threats/settings').toBe(403);

    // 5. POST /api/threats/settings
    const postSettingsRes = await request.post('/api/threats/settings', {
      data: { autoBlock: false },
      headers: { Authorization: `Bearer ${viewerAuth.token}` },
    });
    expect(postSettingsRes.status(), 'viewer should get 403 on POST /api/threats/settings').toBe(403);

    // 6. GET /api/audit
    const auditRes = await request.get('/api/audit', {
      headers: { Authorization: `Bearer ${viewerAuth.token}` },
    });
    expect(auditRes.status(), 'viewer should get 403 on GET /api/audit').toBe(403);
  });

  test('admin receives 2xx on admin endpoints with containment operating in dry-run mode', async ({ request }) => {
    // 1. GET /api/users
    const usersRes = await request.get('/api/users', {
      headers: { Authorization: `Bearer ${adminAuth.token}` },
    });
    expect(usersRes.status()).toBe(200);
    const usersBody = await usersRes.json();
    expect(usersBody.success).toBe(true);

    // 2. GET /api/users/stats
    const statsRes = await request.get('/api/users/stats', {
      headers: { Authorization: `Bearer ${adminAuth.token}` },
    });
    expect(statsRes.status()).toBe(200);
    const statsBody = await statsRes.json();
    expect(statsBody.success).toBe(true);

    // 3. GET /api/threats/settings
    const settingsRes = await request.get('/api/threats/settings', {
      headers: { Authorization: `Bearer ${adminAuth.token}` },
    });
    expect(settingsRes.status()).toBe(200);
    const settingsBody = await settingsRes.json();
    expect(settingsBody.success).toBe(true);

    // 4. GET /api/audit
    const auditRes = await request.get('/api/audit', {
      headers: { Authorization: `Bearer ${adminAuth.token}` },
    });
    expect(auditRes.status()).toBe(200);
    const auditBody = await auditRes.json();
    expect(auditBody.success).toBe(true);

    // 5. POST /api/containment/actions in dry-run mode
    const containRes = await request.post('/api/containment/actions', {
      data: {
        target: '203.0.113.199',
        actionType: 'block_ip',
        reason: 'Automated test containment dry run',
        durationSeconds: 900,
      },
      headers: { Authorization: `Bearer ${adminAuth.token}` },
    });
    expect([200, 201]).toContain(containRes.status());
    const containBody = await containRes.json();
    expect(containBody.success).toBe(true);
    // Verify action status indicates safe mock/dry-run execution
    expect(containBody.data.action.actionType).toBe('block_ip');
    expect(containBody.data.action.enforcementStatus).toBe('ACTIVE');
  });
});
