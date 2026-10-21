'use strict'

const { SecurityAuditLogger, sanitizeLogString, sanitizeAuditPayload } = require('../utils/securityAuditLogger')
const { SecurityEventBus } = require('../utils/securityEventBus')

describe('Phase 7 — Security Monitoring, Event Reliability & Observability Tests', () => {
  describe('SecurityAuditLogger Tests', () => {
    let auditLogger

    beforeEach(() => {
      auditLogger = new SecurityAuditLogger()
    })

    test('sanitizes CRLF characters to prevent Log Injection / Forging', () => {
      const maliciousPayload = 'admin\r\n[CRITICAL] System Compromised\nUser logged in'
      const cleaned = sanitizeLogString(maliciousPayload)
      expect(cleaned).not.toContain('\r')
      expect(cleaned).not.toContain('\n')
      expect(cleaned).toBe('admin  [CRITICAL] System Compromised User logged in')
    })

    test('recursively redacts credentials and sensitive tokens', () => {
      const input = {
        username: 'analyst_1',
        password: 'SuperSecretPassword123!',
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        nested: {
          apiKey: 'AIzaSyD-1234567890',
          refreshToken: 'refresh-token-uuid',
          safeField: 'normal-value',
        },
      }

      const sanitized = sanitizeAuditPayload(input)
      expect(sanitized.username).toBe('analyst_1')
      expect(sanitized.password).toBe('***REDACTED***')
      expect(sanitized.token).toBe('***REDACTED***')
      expect(sanitized.nested.apiKey).toBe('***REDACTED***')
      expect(sanitized.nested.refreshToken).toBe('***REDACTED***')
      expect(sanitized.nested.safeField).toBe('normal-value')
    })

    test('tracks security audit event metrics accurately', () => {
      auditLogger.logEvent({ eventType: 'AUTH_FAILURE', action: 'INVALID_PASSWORD' })
      auditLogger.logEvent({ eventType: 'AUTH_FAILURE', action: 'USER_NOT_FOUND' })
      auditLogger.logEvent({ eventType: 'SESSION_EXPIRED', action: 'INACTIVITY_TIMEOUT' })
      auditLogger.logEvent({ eventType: 'REFRESH_REPLAY', action: 'STALE_GENERATION' })
      auditLogger.logEvent({ eventType: 'CONTAINMENT_REQUEST', action: 'BLOCK_IP' })
      auditLogger.logEvent({ eventType: 'CONTAINMENT_FAILURE', action: 'ADAPTER_ERROR' })

      const metrics = auditLogger.getMetrics()
      expect(metrics.authFailures).toBe(2)
      expect(metrics.sessionExpirations).toBe(1)
      expect(metrics.refreshReplays).toBe(1)
      expect(metrics.containmentRequests).toBe(1)
      expect(metrics.containmentFailures).toBe(1)
      expect(metrics.totalEvents).toBe(6)
    })
  })

  describe('SecurityEventBus Reliability & Durable Outbox', () => {
    let bus

    beforeEach(() => {
      bus = new SecurityEventBus({ maxHistory: 10, dedupSize: 50 })
    })

    test('tracks bus metrics across publications and duplicate skips', () => {
      const event1 = { eventType: 'THREAT_DETECTED', payload: { sourceIP: '192.0.2.10', threatScore: 0.95 } }
      const res1 = bus.publish(event1)
      expect(res1.status).toBe('published')

      // Publish duplicate with identical eventId
      const res2 = bus.publish({ ...event1, eventId: res1.eventId, version: '1.0' })
      expect(res2.status).toBe('duplicate_skipped')

      const metrics = bus.getMetrics()
      expect(metrics.published).toBe(1)
      expect(metrics.duplicates).toBe(1)
      expect(metrics.outboxDepth).toBe(1)
    })

    test('publishDurable guarantees persistence callback succeeds before publishing', async () => {
      const persistedDocs = []
      const fakePersistFn = async (envelope) => {
        persistedDocs.push(envelope)
      }

      let subscriberCalled = false
      bus.subscribe('IP_BLOCKED', () => {
        subscriberCalled = true
      })

      const res = await bus.publishDurable(
        { eventType: 'IP_BLOCKED', payload: { targetIP: '192.0.2.55', reason: 'DDoS mitigation' } },
        fakePersistFn
      )

      expect(res.status).toBe('published')
      expect(persistedDocs.length).toBe(1)
      expect(persistedDocs[0].eventId).toBe(res.eventId)
      expect(subscriberCalled).toBe(true)

      const metrics = bus.getMetrics()
      expect(metrics.durablePersisted).toBe(1)
      expect(metrics.published).toBe(1)
      expect(metrics.dropped).toBe(0)
    })

    test('publishDurable drops event and does NOT publish if persistence fails', async () => {
      const failingPersistFn = async () => {
        throw new Error('Database connection lost')
      }

      let subscriberCalled = false
      bus.subscribe('IP_BLOCKED', () => {
        subscriberCalled = true
      })

      await expect(
        bus.publishDurable({ eventType: 'IP_BLOCKED', payload: { targetIP: '192.0.2.55' } }, failingPersistFn)
      ).rejects.toThrow('Database connection lost')

      // Event was NOT emitted to subscribers and was NOT added to history
      expect(subscriberCalled).toBe(false)
      expect(bus.history.length).toBe(0)

      const metrics = bus.getMetrics()
      expect(metrics.durablePersisted).toBe(0)
      expect(metrics.published).toBe(0)
      expect(metrics.dropped).toBe(1)
    })

    test('recovers pending outbox events across simulated process restart', async () => {
      const { InMemoryOutboxStore } = require('../utils/securityEventBus')
      // Shared persistent store simulating external/disk storage
      const persistentStore = new InMemoryOutboxStore()

      // Process Instance 1: crashes or subscriber fails before delivery
      const bus1 = new SecurityEventBus({ outboxStore: persistentStore })
      bus1.subscribe('THREAT_DETECTED', () => {
        throw new Error('Subscriber crashed unexpectedly')
      })

      // Attempt durable publish in Process 1
      await bus1.publishDurable(
        { eventType: 'THREAT_DETECTED', payload: { sourceIP: '198.51.100.22', severity: 'HIGH' } },
        async () => {} // Business persistence succeeds
      )

      // Event remains in PENDING state in persistent store
      const pendingBefore = await persistentStore.getPendingEvents()
      expect(pendingBefore.length).toBe(1)
      expect(pendingBefore[0].payload.sourceIP).toBe('198.51.100.22')

      // Process Instance 2: New process starts up, connects to persistent store
      const bus2 = new SecurityEventBus({ outboxStore: persistentStore })
      const receivedInProcess2 = []
      bus2.subscribe('THREAT_DETECTED', (env) => {
        receivedInProcess2.push(env)
      })

      // Startup recovery: replay pending outbox
      const replayResult = await bus2.replayPendingOutbox()
      expect(replayResult.replayed).toBe(1)
      expect(replayResult.failed).toBe(0)
      expect(receivedInProcess2.length).toBe(1)
      expect(receivedInProcess2[0].payload.sourceIP).toBe('198.51.100.22')

      // Outbox queue is now fully cleared (no pending events)
      const pendingAfter = await persistentStore.getPendingEvents()
      expect(pendingAfter.length).toBe(0)
    })

    test('FileOutboxStore persists pending events to disk file', async () => {
      const { FileOutboxStore } = require('../utils/securityEventBus')
      const fs = require('fs')
      const path = require('path')
      const tmpFile = path.join(__dirname, '..', 'logs', `test_outbox_${Date.now()}.json`)

      try {
        const fileStore = new FileOutboxStore(tmpFile)
        const fakeEnvelope = {
          eventId: 'test-evt-001',
          eventType: 'ALERT_CREATED',
          payload: { alert: 'test' },
          version: '1.0',
        }

        await fileStore.persistEnvelope(fakeEnvelope)
        const pending = await fileStore.getPendingEvents()
        expect(pending.length).toBe(1)
        expect(pending[0].eventId).toBe('test-evt-001')

        await fileStore.markDelivered('test-evt-001')
        const remaining = await fileStore.getPendingEvents()
        expect(remaining.length).toBe(0)
      } finally {
        if (fs.existsSync(tmpFile)) {
          fs.unlinkSync(tmpFile)
        }
      }
    })
  })
})
