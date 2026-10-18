'use strict'
/**
 * tests/websocket.test.js
 *
 * Verifies that:
 * 1. Unauthenticated Socket.IO connections are rejected outright during handshake.
 * 2. Connections with invalid/expired tokens are rejected.
 * 3. Connections with inactive user accounts are rejected.
 * 4. Authenticated connections with valid JWT succeed.
 * 5. Role-based rooms strictly bind to the server-verified JWT role,
 *    preventing client-side privilege spoofing in join_room.
 */

process.env.JWT_SECRET = 'test-jwt-secret'
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret'
process.env.JWT_EXPIRES_IN = '1d'
process.env.NODE_ENV = 'test'
process.env.PORT = '0'

jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../config/db', () => jest.fn())
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}))

const http = require('http')
const { Server } = require('socket.io')
const ioClient = require('../../frontend/node_modules/socket.io-client')
const { accessToken } = require('./helpers/accessFixture')
const User = require('../models/User')
const socketManager = require('../websocket/socketManager')

describe('WebSocket Authentication & Role-Based Access Control', () => {
  let server
  let io
  let port
  let testClient

  const mockUsers = {
    admin: {
      _id: '111111111111111111111111',
      name: 'Admin User',
      email: 'admin@sentinel.io',
      role: 'admin',
      status: 'active',
    },
    analyst: {
      _id: '222222222222222222222222',
      name: 'Analyst User',
      email: 'analyst@sentinel.io',
      role: 'analyst',
      status: 'active',
    },
    viewer: {
      _id: '333333333333333333333333',
      name: 'Viewer User',
      email: 'viewer@sentinel.io',
      role: 'viewer',
      status: 'active',
    },
    inactive: {
      _id: '444444444444444444444444',
      name: 'Inactive User',
      email: 'inactive@sentinel.io',
      role: 'analyst',
      status: 'inactive',
    },
  }

  const generateToken = (id, role, expiresIn = 900) => accessToken({ _id: id, role }, expiresIn)

  beforeAll((done) => {
    server = http.createServer()
    io = new Server(server, {
      pingTimeout: 5000,
      pingInterval: 2500,
    })

    require('../websocket/auth').install(io)

    socketManager.init(io)

    server.listen(0, () => {
      port = server.address().port
      done()
    })
  })

  afterAll((done) => {
    socketManager.stopHealthBroadcast()
    io.close(() => {
      server.close(() => {
        done()
      })
    })
  })

  afterEach((done) => {
    jest.clearAllMocks()
    User.findById.mockImplementation((id) => ({
      select: async () => Object.values(mockUsers).find((user) => user._id === id),
    }))
    if (testClient) {
      try {
        testClient.disconnect()
        testClient.close()
      } catch {}
      testClient = null
    }
    done()
  })

  // 1. Rejects unauthenticated connection (no token)
  test('rejects unauthenticated connection attempt without token', (done) => {
    testClient = ioClient(`http://localhost:${port}`, {
      transports: ['websocket'],
      reconnection: false,
    })

    testClient.on('connect_error', (err) => {
      expect(err.message).toMatch(/authentication rejected/i)
      done()
    })

    testClient.on('connect', () => {
      done(new Error('Unauthenticated connection should not have succeeded'))
    })
  })

  // 2. Rejects connection with invalid JWT
  test('rejects connection attempt with an invalid token', (done) => {
    testClient = ioClient(`http://localhost:${port}`, {
      auth: { token: 'invalid.token.string' },
      transports: ['websocket'],
      reconnection: false,
    })

    testClient.on('connect_error', (err) => {
      expect(err.message).toMatch(/authentication rejected/i)
      done()
    })

    testClient.on('connect', () => {
      done(new Error('Connection with invalid token should not have succeeded'))
    })
  })

  // 3. Rejects connection with expired JWT
  test('rejects connection attempt with an expired token', (done) => {
    const expiredToken = generateToken('111111111111111111111111', 'admin', -10)
    testClient = ioClient(`http://localhost:${port}`, {
      auth: { token: expiredToken },
      transports: ['websocket'],
      reconnection: false,
    })

    testClient.on('connect_error', (err) => {
      expect(err.message).toMatch(/authentication rejected/i)
      done()
    })

    testClient.on('connect', () => {
      done(new Error('Connection with expired token should not have succeeded'))
    })
  })

  // 4. Rejects connection when account is inactive
  test('rejects connection attempt when user status is inactive', (done) => {
    User.findById.mockReturnValue({
      select: jest.fn().mockResolvedValue(mockUsers.inactive),
    })

    const token = generateToken('444444444444444444444444', 'analyst')
    testClient = ioClient(`http://localhost:${port}`, {
      auth: { token },
      transports: ['websocket'],
      reconnection: false,
    })

    testClient.on('connect_error', (err) => {
      expect(err.message).toMatch(/authentication rejected/i)
      done()
    })

    testClient.on('connect', () => {
      done(new Error('Inactive user connection should not have succeeded'))
    })
  })

  // 5. Connects successfully with valid JWT
  test('connects successfully when valid JWT token is provided in auth', (done) => {
    User.findById.mockReturnValue({
      select: jest.fn().mockResolvedValue(mockUsers.viewer),
    })

    const token = generateToken('333333333333333333333333', 'viewer')
    testClient = ioClient(`http://localhost:${port}`, {
      auth: { token },
      transports: ['websocket'],
      reconnection: false,
    })

    testClient.on('connect', () => {
      expect(testClient.connected).toBe(true)
      done()
    })

    testClient.on('connect_error', (err) => {
      done(err)
    })
  })

  // 6. Privilege spoofing prevention: join_room strictly enforces verified role from JWT
  test('binds join_room strictly to server-verified role from token, ignoring spoofed client role', (done) => {
    User.findById.mockReturnValue({
      select: jest.fn().mockResolvedValue(mockUsers.viewer),
    })

    const token = generateToken('333333333333333333333333', 'viewer')
    testClient = ioClient(`http://localhost:${port}`, {
      auth: { token },
      transports: ['websocket'],
      reconnection: false,
    })

    testClient.on('connect', () => {
      // Client maliciously claims to be an admin in join_room payload
      testClient.emit('join_room', { role: 'admin', userId: '333333333333333333333333' })
    })

    testClient.on('connected', (data) => {
      // The server MUST override the claimed 'admin' role with verified 'viewer' role
      expect(data.room).toBe('viewer')

      // Verify that stats internally record the verified role, not the spoofed role
      const stats = socketManager.getStats()
      const clientEntry = stats.clients.find((c) => c.socketId === testClient.id)
      expect(clientEntry).toBeDefined()
      expect(clientEntry.role).toBe('viewer')
      done()
    })
  })

  // 7. Real-time event reception: Admin-only alerts are not received by a viewer socket
  test('viewer socket does not receive alerts targeted strictly to analyst/admin', (done) => {
    User.findById.mockReturnValue({
      select: jest.fn().mockResolvedValue(mockUsers.viewer),
    })

    const token = generateToken('333333333333333333333333', 'viewer')
    testClient = ioClient(`http://localhost:${port}`, {
      auth: { token },
      transports: ['websocket'],
      reconnection: false,
    })

    let receivedAlert = false

    testClient.on('connect', () => {
      testClient.emit('join_room', { role: 'viewer', userId: '333333333333333333333333' })
    })

    testClient.on('connected', () => {
      // Register listener for new_alert
      testClient.on('new_alert', () => {
        receivedAlert = true
      })

      // Emit an alert targeted strictly to 'admin' and 'analyst'
      socketManager.emitNewAlert({
        _id: 'alert-analyst-only',
        title: 'Analyst Alert',
        message: 'Internal SOC alert',
        severity: 'HIGH',
        type: 'THREAT_DETECTED',
        targetRoles: ['analyst'],
      })

      // Allow 300ms to confirm no event was received
      setTimeout(() => {
        expect(receivedAlert).toBe(false)
        done()
      }, 300)
    })
  })
  test('overlapping rooms receive each genuine event once', (done) => {
    testClient = ioClient(`http://localhost:${port}`, {
      auth: { token: generateToken('111111111111111111111111', 'admin') },
      transports: ['websocket'],
      reconnection: false,
    })
    let threats = 0
    let alerts = 0
    testClient.on('connect', () => testClient.emit('join_room', { role: 'admin' }))
    testClient.on('new_threat', () => threats++)
    testClient.on('new_alert', () => alerts++)
    testClient.on('connected', () => {
      socketManager.emitNewThreat({
        _id: 'test-once',
        severity: 'HIGH',
        sourceIP: '192.0.2.1',
        attackType: 'Port Scan',
      })
      socketManager.emitNewAlert({ _id: 'test-alert-once', severity: 'CRITICAL', targetRoles: ['admin'] })
      setTimeout(() => {
        try {
          expect(threats).toBe(1)
          expect(alerts).toBe(1)
          done()
        } catch (error) {
          done(error)
        }
      }, 200)
    })
  })

  test('viewer joining threat_subscribers and all still receives only redacted data', (done) => {
    testClient = ioClient(`http://localhost:${port}`, {
      auth: { token: generateToken('333333333333333333333333', 'viewer') },
      transports: ['websocket'],
      reconnection: false,
    })

    testClient.on('connect', () => {
      testClient.emit('join_room', { role: 'viewer', userId: '333333333333333333333333' })
      testClient.emit('subscribe_threats')
    })

    testClient.on('new_threat', (threat) => {
      try {
        expect(threat.sourceIP).toBe('198.51.100.xxx')
        expect(threat.payload).toBe('[REDACTED_PAYLOAD]')
        done()
      } catch (err) {
        done(err)
      }
    })

    testClient.on('connected', () => {
      socketManager.emitNewThreat({
        _id: 'viewer-redaction-ws-test',
        severity: 'CRITICAL',
        sourceIP: '198.51.100.42',
        attackType: 'SQL_INJECTION',
        payload: 'UNION SELECT password FROM admins',
      })
    })
  })

  test('deactivated or demoted user live socket is forcibly disconnected', (done) => {
    testClient = ioClient(`http://localhost:${port}`, {
      auth: { token: generateToken('222222222222222222222222', 'analyst') },
      transports: ['websocket'],
      reconnection: false,
    })

    testClient.on('connect', () => {
      testClient.emit('join_room', { role: 'analyst', userId: '222222222222222222222222' })
    })

    testClient.on('disconnect', (reason) => {
      try {
        expect(['io server disconnect', 'transport close']).toContain(reason)
        done()
      } catch (err) {
        done(err)
      }
    })

    testClient.on('connected', () => {
      // Trigger live socket disconnect for user
      socketManager.disconnectUser('222222222222222222222222')
    })
  })

  test('securityEventBus emits redacted payload to viewer in all or threat_subscribers room', (done) => {
    testClient = ioClient(`http://localhost:${port}`, {
      auth: { token: generateToken('333333333333333333333333', 'viewer') },
      transports: ['websocket'],
      reconnection: false,
    })

    testClient.on('connect', () => {
      testClient.emit('join_room', { role: 'viewer', userId: '333333333333333333333333' })
    })

    testClient.on('new_threat', (threat) => {
      try {
        expect(threat.sourceIP).toBe('198.51.100.xxx')
        expect(threat.payload).toBe('[REDACTED_PAYLOAD]')
        done()
      } catch (err) {
        done(err)
      }
    })

    testClient.on('connected', () => {
      const { SecurityEventBus } = require('../utils/securityEventBus')
      const bus = new SecurityEventBus({ io })
      bus._broadcastToWebSockets(
        {
          eventType: 'THREAT_DETECTED',
          eventId: 'evt-test-1',
          timestamp: new Date().toISOString(),
          payload: {
            _id: 'bus-threat-1',
            severity: 'CRITICAL',
            sourceIP: '198.51.100.88',
            attackType: 'SQL Injection',
            payload: 'DROP TABLE users;',
          },
        },
        io
      )
    })
  })
})

