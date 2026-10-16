'use strict'

// Set environment for test mode before requiring server
process.env.JWT_SECRET = 'test-jwt-secret'
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret'
process.env.NODE_ENV = 'test'
process.env.HONEYPOT_API_KEY = 'test-internal-api-key-12345'
process.env.SENTINEL_KEY = 'test-sentinel-key-12345'
process.env.PORT = '0'

// Mock database and socketManager before importing server
jest.mock('../config/db', () => jest.fn())
jest.mock('../websocket/socketManager', () => ({
  init: jest.fn(),
  startDemoFeed: jest.fn(),
  stopDemoFeed: jest.fn(),
  getStats: jest.fn().mockReturnValue({}),
}))
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}))

const request = require('supertest')
const SwaggerParser = require('@apidevtools/swagger-parser')
const { app } = require('../server')
const { swaggerSpec } = require('../config/swagger')

describe('OpenAPI 3.0 Documentation & Swagger UI', () => {
  test('generates a structurally valid OpenAPI 3.0 specification according to SwaggerParser', async () => {
    // Clone spec so parser mutation (if any) doesn't affect subsequent assertions
    const specCopy = JSON.parse(JSON.stringify(swaggerSpec))
    const api = await SwaggerParser.validate(specCopy)
    expect(api).toBeDefined()
    expect(api.openapi).toMatch(/^3\.0\./)
    expect(api.info.title).toBe('SentinelAI Backend API')
  })

  test('contains documented paths for ALL major route groups', () => {
    const paths = Object.keys(swaggerSpec.paths)

    // 1. Auth routes
    expect(paths).toContain('/auth/register')
    expect(paths).toContain('/auth/login')
    expect(paths).toContain('/auth/refresh-token')
    expect(paths).toContain('/auth/me')
    expect(paths).toContain('/auth/update-password')

    // 2. Threats routes
    expect(paths).toContain('/threats')
    expect(paths).toContain('/threats/{id}')
    expect(paths).toContain('/threats/analytics/summary')
    expect(paths).toContain('/threats/vector-trend')
    expect(paths).toContain('/threats/recent')
    expect(paths).toContain('/threats/{id}/block')

    // 3. Settings & Blocklist routes
    expect(paths).toContain('/threats/settings')
    expect(paths).toContain('/threats/blocked-ips')
    expect(paths).toContain('/threats/block-ip')
    expect(paths).toContain('/threats/unblock-ip')

    // 4. Honeypot routes
    expect(paths).toContain('/honeypot/analytics')
    expect(paths).toContain('/honeypot/nodes')
    expect(paths).toContain('/honeypot/sessions')
    expect(paths).toContain('/honeypot/sessions/{id}')
    expect(paths).toContain('/honeypot/sessions/{id}/commands')
    expect(paths).toContain('/honeypot/sessions/{id}/close')

    // 5. Honeypot Ingest routes
    expect(paths).toContain('/honeypot/ingest/check-block')
    expect(paths).toContain('/honeypot/ingest')
    expect(paths).toContain('/honeypot/ingest/match-session')
    expect(paths).toContain('/honeypot/ingest/command')
    expect(paths).toContain('/honeypot/ingest/download')
    expect(paths).toContain('/honeypot/ingest/close')

    // 6. Campaigns routes
    expect(paths).toContain('/campaigns')
    expect(paths).toContain('/campaigns/{id}')

    // 7. AI Engine routes
    expect(paths).toContain('/ai/engine/health')
    expect(paths).toContain('/ai/engine/model-info')
    expect(paths).toContain('/ai/engine/stats')
    expect(paths).toContain('/ai/analyze')
    expect(paths).not.toContain('/ai/simulate')
    expect(paths).toContain('/ai/predictions')
    expect(paths).toContain('/ai/predictions/{id}/verify')
    expect(paths).toContain('/ai/stats')

    // 8. Alerts routes
    expect(paths).toContain('/alerts')
    expect(paths).toContain('/alerts/unread-count')
    expect(paths).toContain('/alerts/mark-all-read')
    expect(paths).toContain('/alerts/{id}/read')
    expect(paths).toContain('/alerts/{id}')

    // 9. Users routes
    expect(paths).toContain('/users')
    expect(paths).toContain('/users/stats')
    expect(paths).toContain('/users/{id}')
  })

  test('GET /api/docs.json serves raw OpenAPI specification', async () => {
    const res = await request(app).get('/api/docs.json')
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/json/)
    expect(res.body.openapi).toMatch(/^3\.0\./)
    expect(res.body.info.title).toBe('SentinelAI Backend API')
    expect(res.body.paths['/auth/login']).toBeDefined()
  })

  test('GET /api/docs/ serves interactive Swagger UI HTML interface', async () => {
    const res = await request(app).get('/api/docs/')
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/html/)
    expect(res.text).toContain('swagger-ui')
  })
})
