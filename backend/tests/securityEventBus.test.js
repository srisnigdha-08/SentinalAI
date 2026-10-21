'use strict'

const { SecurityEventBus, sanitizePayload } = require('../utils/securityEventBus')

describe('Phase 6D — Security Event Distribution & Reliability Tests', () => {
  let bus

  beforeEach(() => {
    bus = new SecurityEventBus({ maxHistory: 10, dedupSize: 50 })
  })

  describe('Sanitization & Security Properties', () => {
    test('sanitizes sensitive keys and redacts credentials in payloads', () => {
      const raw = {
        sourceIP: '192.168.1.100',
        password: 'RawSuperSecretPassword',
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        nested: {
          refreshToken: 'refresh-token-12345',
          safeValue: 42,
        },
      }

      const clean = sanitizePayload(raw)
      expect(clean.sourceIP).toBe('192.168.1.100')
      expect(clean.password).toBe('***REDACTED***')
      expect(clean.token).toBe('***REDACTED***')
      expect(clean.nested.refreshToken).toBe('***REDACTED***')
      expect(clean.nested.safeValue).toBe(42)
    })

    test('protects against prototype pollution in event payload', () => {
      const malicious = JSON.parse('{"__proto__": {"polluted": true}, "normal": "valid"}')
      const clean = sanitizePayload(malicious)
      expect(clean.__proto__.polluted).toBeUndefined()
      expect(clean.normal).toBe('valid')
    })
  })

  describe('Envelope Creation & Validation', () => {
    test('creates standard envelope with UUID, timestamp, and version 1.0', () => {
      const envelope = bus.createEnvelope({
        eventType: 'THREAT_DETECTED',
        payload: { sourceIP: '10.0.0.1', severity: 'HIGH', attackType: 'Port Scan' },
        source: 'threat-engine',
        correlationId: 'threat-123',
      })

      expect(envelope.eventId).toMatch(/^[0-9a-f-]{36}$/)
      expect(envelope.eventType).toBe('THREAT_DETECTED')
      expect(envelope.source).toBe('threat-engine')
      expect(envelope.version).toBe('1.0')
      expect(envelope.correlationId).toBe('threat-123')
      expect(envelope.timestamp).toBeDefined()
      expect(envelope.payload.sourceIP).toBe('10.0.0.1')
    })

    test('rejects unsupported eventType', () => {
      expect(() => {
        bus.createEnvelope({
          eventType: 'UNAUTHORIZED_CUSTOM_EVENT',
          payload: { foo: 'bar' },
        })
      }).toThrow(/Invalid or unsupported eventType/)
    })

    test('rejects payload exceeding 32 KB limit', () => {
      const hugeData = 'x'.repeat(35000)
      expect(() => {
        bus.createEnvelope({
          eventType: 'THREAT_DETECTED',
          payload: { data: hugeData },
        })
      }).toThrow(/exceeds maximum permitted size/)
    })
  })

  describe('Deduplication & History Ring Buffer', () => {
    test('detects and suppresses duplicate events with identical eventId', () => {
      const envelope = bus.createEnvelope({
        eventType: 'THREAT_DETECTED',
        payload: { sourceIP: '192.168.1.50' },
      })

      const res1 = bus.publish(envelope)
      expect(res1.status).toBe('published')
      expect(res1.success).toBe(true)

      const res2 = bus.publish(envelope)
      expect(res2.status).toBe('duplicate_skipped')
      expect(res2.success).toBe(false)
    })

    test('history ring buffer maintains bounded size and supports filtering', () => {
      for (let i = 1; i <= 15; i++) {
        bus.publish({
          eventType: i % 2 === 0 ? 'ALERT_CREATED' : 'THREAT_DETECTED',
          payload: { count: i },
        })
      }

      // History was configured with maxHistory: 10
      const history = bus.getHistory({ limit: 50 })
      expect(history.length).toBe(10)
      expect(history[history.length - 1].payload.count).toBe(15)

      // Filter by eventType
      const alerts = bus.getHistory({ eventType: 'ALERT_CREATED' })
      expect(alerts.every((e) => e.eventType === 'ALERT_CREATED')).toBe(true)
    })
  })

  describe('In-Process Subscription & WebSocket Broadcasting', () => {
    test('delivers events to in-process subscribers', () => {
      const received = []
      const unsubscribe = bus.subscribe('THREAT_DETECTED', (e) => received.push(e))

      bus.publish({
        eventType: 'THREAT_DETECTED',
        payload: { threat: 'SQL Injection' },
      })

      expect(received.length).toBe(1)
      expect(received[0].payload.threat).toBe('SQL Injection')

      // Unsubscribe
      unsubscribe()
      bus.publish({
        eventType: 'THREAT_DETECTED',
        payload: { threat: 'Second Threat' },
      })
      expect(received.length).toBe(1)
    })

    test('broadcasts to WebSockets with standard envelope and backward-compatible channels', () => {
      const mockIO = {
        to: jest.fn().mockReturnThis(),
        emit: jest.fn(),
      }

      bus.publish(
        {
          eventType: 'THREAT_DETECTED',
          payload: { severity: 'CRITICAL', sourceIP: '1.2.3.4' },
        },
        mockIO
      )

      // Emits on standard 'security_event' channel
      expect(mockIO.to).toHaveBeenCalledWith('all')
      expect(mockIO.emit).toHaveBeenCalledWith('security_event', expect.objectContaining({ version: '1.0' }))

      // Emits on backward-compatible 'new_threat' channel
      expect(mockIO.to).toHaveBeenCalledWith(['threat_subscribers', 'all'])
      expect(mockIO.emit).toHaveBeenCalledWith('new_threat', expect.objectContaining({ sourceIP: '1.2.3.4' }))

      // Emits CRITICAL alert to admin
      expect(mockIO.to).toHaveBeenCalledWith('admin')
      expect(mockIO.emit).toHaveBeenCalledWith('critical_alert', expect.objectContaining({ urgency: 'IMMEDIATE' }))
    })
  })
})
