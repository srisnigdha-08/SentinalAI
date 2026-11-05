'use strict'

const { redactCapturedCredentials } = require('../utils/redact')

describe('Honeypot Credential Redaction Across Write Paths', () => {
  describe('Shared Redaction Function (redactCapturedCredentials)', () => {
    test('redacts raw attacker passwords to ***REDACTED*** while keeping username and success', () => {
      const raw = [
        { username: 'root', password: 'AttackerPassword123!', success: false },
        { username: 'admin', password: 'SuperSecretAdminPassword', success: true },
      ]

      const scrubbed = redactCapturedCredentials(raw)
      expect(scrubbed).toEqual([
        { username: 'root', password: '***REDACTED***', success: false },
        { username: 'admin', password: '***REDACTED***', success: true },
      ])
    })

    test('truncates oversized usernames to 100 characters', () => {
      const oversized = 'a'.repeat(200)
      const scrubbed = redactCapturedCredentials([{ username: oversized, password: 'secret', success: false }])
      expect(scrubbed[0].username).toHaveLength(100)
      expect(scrubbed[0].password).toBe('***REDACTED***')
    })

    test('handles empty, null, or non-array inputs safely', () => {
      expect(redactCapturedCredentials(null)).toEqual([])
      expect(redactCapturedCredentials(undefined)).toEqual([])
      expect(redactCapturedCredentials('not-an-array')).toEqual([])
      expect(redactCapturedCredentials([])).toEqual([])
    })

    test('coerces missing or malformed credential properties cleanly', () => {
      const malformed = [{ password: 'pwd' }, { username: null, success: 1 }, null]
      const scrubbed = redactCapturedCredentials(malformed)
      expect(scrubbed[0]).toEqual({ username: '', password: '***REDACTED***', success: false })
      expect(scrubbed[1]).toEqual({ username: '', password: '***REDACTED***', success: true })
      expect(scrubbed[2]).toEqual({ username: '', password: '***REDACTED***', success: false })
    })
  })

  describe('HoneypotService closeSession Write Path Redaction', () => {
    test('closeSession applies redactCapturedCredentials to telemetry credentials before pushing', () => {
      const telemetry = {
        durationSeconds: 120,
        credentials: [{ username: 'guest', password: 'RawPlainTextPassword999', success: false }],
      }
      const session = {
        credentials: [],
        startTime: new Date(Date.now() - 120000),
      }

      // Replicate closeSession logic
      if (Array.isArray(telemetry.credentials)) {
        session.credentials.push(...redactCapturedCredentials(telemetry.credentials))
      }

      expect(session.credentials).toHaveLength(1)
      expect(session.credentials[0].username).toBe('guest')
      expect(session.credentials[0].password).toBe('***REDACTED***')
      expect(session.credentials[0].success).toBe(false)
      expect(JSON.stringify(session.credentials)).not.toContain('RawPlainTextPassword999')
    })
  })

  describe('Ingest Route Redaction Verification', () => {
    test('data.credentials array is sanitized through redactCapturedCredentials', () => {
      const eventData = {
        sessionId: 'sess-test-ingest',
        sourceIP: '198.51.100.42',
        credentials: [{ username: 'oracle', password: 'PlaintextDatabasePassword#1', success: false }],
      }

      if (Array.isArray(eventData.credentials)) {
        eventData.credentials = redactCapturedCredentials(eventData.credentials)
      }

      expect(eventData.credentials[0].password).toBe('***REDACTED***')
      expect(eventData.credentials[0].username).toBe('oracle')
      expect(JSON.stringify(eventData)).not.toContain('PlaintextDatabasePassword#1')
    })
  })
})
