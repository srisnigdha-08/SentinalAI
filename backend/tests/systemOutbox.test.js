'use strict'

const request = require('supertest')
const express = require('express')
const systemOutboxRoutes = require('../routes/systemOutbox')
const { defaultSecurityEventBus, InMemoryOutboxStore } = require('../utils/securityEventBus')
const { defaultSecurityAuditLogger } = require('../utils/securityAuditLogger')
const authSessionService = require('../services/authSessionService')

describe('Stage 3 & 4 — System Outbox Administration & Authorization Boundary Tests', () => {
  let app
  let memoryStore
  let mockUser = null
  let authorizeSpy
  let recordActivitySpy

  beforeAll(() => {
    authorizeSpy = jest.spyOn(authSessionService, 'authorize').mockImplementation(async () => {
      if (!mockUser) {
        const err = new Error('Invalid token')
        err.statusCode = 401
        err.name = 'AuthError'
        throw err
      }
      return {
        user: mockUser,
        session: { _id: 'mock-session-id' },
      }
    })
    recordActivitySpy = jest.spyOn(authSessionService, 'recordActivity').mockImplementation(() => {})
  })

  afterAll(() => {
    authorizeSpy.mockRestore()
    recordActivitySpy.mockRestore()
  })

  beforeEach(() => {
    memoryStore = new InMemoryOutboxStore()
    defaultSecurityEventBus.outboxStore = memoryStore

    app = express()
    app.use(express.json())
    app.use('/api/system/outbox', systemOutboxRoutes)
  })

  afterEach(() => {
    mockUser = null
  })

  test('1. Unauthenticated request to outbox endpoints is denied with 401', async () => {
    mockUser = null
    const res = await request(app).get('/api/system/outbox/status')
    expect(res.status).toBe(401)
    expect(res.body.success).toBe(false)
  })

  test('2. Viewer role is denied access with 403 (RBAC Enforcement)', async () => {
    mockUser = { _id: 'viewer-1', role: 'viewer', status: 'active' }

    const resStatus = await request(app)
      .get('/api/system/outbox/status')
      .set('Authorization', 'Bearer mock-viewer-token')
    expect(resStatus.status).toBe(403)

    const resFailed = await request(app)
      .get('/api/system/outbox/failed')
      .set('Authorization', 'Bearer mock-viewer-token')
    expect(resFailed.status).toBe(403)

    const resRedrive = await request(app)
      .post('/api/system/outbox/redrive')
      .set('Authorization', 'Bearer mock-viewer-token')
    expect(resRedrive.status).toBe(403)
  })

  test('3. Analyst role can view status but cannot redrive or inspect raw failed events', async () => {
    mockUser = { _id: 'analyst-1', role: 'analyst', status: 'active' }

    const resStatus = await request(app)
      .get('/api/system/outbox/status')
      .set('Authorization', 'Bearer mock-analyst-token')
    expect(resStatus.status).toBe(200)
    expect(resStatus.body.success).toBe(true)
    expect(resStatus.body.data.supported).toBe(true)

    const resFailed = await request(app)
      .get('/api/system/outbox/failed')
      .set('Authorization', 'Bearer mock-analyst-token')
    expect(resFailed.status).toBe(403)

    const resRedrive = await request(app)
      .post('/api/system/outbox/redrive')
      .set('Authorization', 'Bearer mock-analyst-token')
    expect(resRedrive.status).toBe(403)
  })

  test('4. Admin role can inspect failed events and execute manual redrive with audit trail', async () => {
    mockUser = { _id: 'admin-1', role: 'admin', username: 'secadmin', status: 'active' }

    // Inject a failed event in memoryStore
    memoryStore.records.set('failed-evt-1', {
      envelope: { eventId: 'failed-evt-1', eventType: 'ALERT_CREATED', payload: { error: 'test' } },
      status: 'FAILED',
      attempts: 3,
      createdAt: new Date().toISOString(),
      lastError: 'Simulated subscriber crash',
    })

    // Admin inspects failed events
    const resFailed = await request(app)
      .get('/api/system/outbox/failed')
      .set('Authorization', 'Bearer mock-admin-token')
    expect(resFailed.status).toBe(200)
    expect(resFailed.body.data.failed.length).toBe(1)
    expect(resFailed.body.data.failed[0].attempts).toBe(3)

    // Admin executes manual redrive
    const logSpy = jest.spyOn(defaultSecurityAuditLogger, 'logEvent')
    const resRedrive = await request(app)
      .post('/api/system/outbox/redrive')
      .set('Authorization', 'Bearer mock-admin-token')
    expect(resRedrive.status).toBe(200)
    expect(resRedrive.body.data.redriven).toBe(1)

    // Verify structured audit event was logged
    expect(logSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: 'OUTBOX_REDRIVE',
        action: 'MANUAL_REDRIVE',
        status: 'EXECUTED',
        actor: expect.objectContaining({
          role: 'admin',
        }),
        details: expect.objectContaining({
          redrivenCount: 1,
        }),
      })
    )

    logSpy.mockRestore()

    // Verify status is back to PENDING
    const rec = memoryStore.records.get('failed-evt-1')
    expect(rec.status).toBe('PENDING')
    expect(rec.attempts).toBe(0)
  })
})
