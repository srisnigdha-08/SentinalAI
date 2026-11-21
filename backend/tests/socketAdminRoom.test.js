'use strict'

// Socket.IO admin-room authorization. The real socketManager connection handler runs against in-memory sockets
// that keep real room membership, and a fake `io` that delivers an emit only to sockets in the target rooms (one
// copy per socket, as Socket.IO does). Identity comes from socket.role / socket.user, which websocket/auth.js
// sets from the verified session; nothing the client sends in join_room may widen it.

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../models/ThreatLog', () => ({}))
jest.mock('../utils/securityEventBus', () => ({ defaultSecurityEventBus: { recordDelivered: jest.fn() } }))

const logger = require('../utils/logger')
const socketManager = require('../websocket/socketManager')

let sockets
let onConnection

const makeIo = () => ({
  engine: { clientsCount: 0 }, // init() starts the health interval, which reads this
  on: (event, fn) => {
    if (event === 'connection') onConnection = fn
  },
  to: (rooms) => ({
    emit: (event, payload) => {
      const targets = [].concat(rooms)
      for (const s of sockets) if (targets.some((r) => s.rooms.has(r))) s.received.push({ event, payload })
    },
  }),
})

/** A connected socket whose role was set by the auth middleware (server-verified), then join_room as the client sends it. */
const connect = (role, joinPayload = { role, userId: `${role}-1` }) => {
  const handlers = {}
  const socket = {
    id: `sock-${sockets.length + 1}-${role}`,
    role,
    user: { _id: `${role}-1`, role, email: `${role}@example.test` },
    rooms: new Set(),
    received: [],
    join: (room) => socket.rooms.add(room),
    on: (event, fn) => {
      handlers[event] = fn
    },
    emit: () => {},
  }
  sockets.push(socket)
  onConnection(socket)
  handlers.join_room(joinPayload)
  return socket
}

const events = (socket, name) => socket.received.filter((r) => r.event === name)

const CRITICAL = {
  _id: 't-critical',
  severity: 'CRITICAL',
  sourceIP: '203.0.113.77',
  attackType: 'DDoS',
  aiScore: 0.97,
  status: 'MONITORING',
}

describe('Socket.IO admin room authorization', () => {
  beforeEach(() => {
    sockets = []
    onConnection = null
    logger.warn.mockClear()
    socketManager.init(makeIo())
  })
  afterEach(() => socketManager.stopHealthBroadcast())

  test('an authenticated admin requesting the admin room is in it', () => {
    const admin = connect('admin', { role: 'admin', room: 'admin' })
    expect(admin.rooms.has('admin')).toBe(true)
    expect(logger.warn).not.toHaveBeenCalled()
  })

  test('an authenticated analyst requesting the admin room is refused (and the refusal is logged)', () => {
    const analyst = connect('analyst', { role: 'analyst', room: 'admin' })
    expect(analyst.rooms.has('admin')).toBe(false)
    expect(analyst.rooms.has('analyst')).toBe(true)
    expect(logger.warn).toHaveBeenCalledWith(expect.stringMatching(/requested room 'admin'; refused/))
  })

  test('an authenticated viewer requesting the admin room is refused', () => {
    const viewer = connect('viewer', { role: 'viewer', room: 'admin' })
    expect(viewer.rooms.has('admin')).toBe(false)
    expect(viewer.rooms.has('threat_subscribers_privileged')).toBe(false)
  })

  test('an analyst claiming the admin role in the payload is still an analyst', () => {
    const analyst = connect('analyst', { role: 'admin', userId: 'admin-1', room: 'admin' })
    expect(analyst.rooms.has('admin')).toBe(false)
    expect([...analyst.rooms]).not.toContain('threat_subscribers_admin')
  })

  test('only the admin receives admin-only critical_alert; analyst and viewer requesting the room do not', () => {
    const admin = connect('admin')
    const analyst = connect('analyst', { role: 'admin', room: 'admin' })
    const viewer = connect('viewer', { role: 'admin', room: 'admin' })
    socketManager.emitNewThreat(CRITICAL)

    expect(events(admin, 'critical_alert')).toHaveLength(1)
    expect(events(analyst, 'critical_alert')).toHaveLength(0)
    expect(events(viewer, 'critical_alert')).toHaveLength(0)
  })

  test('admin-only alerts reach only admins', () => {
    const admin = connect('admin')
    const analyst = connect('analyst', { role: 'analyst', room: 'admin' })
    socketManager.emitNewAlert({
      _id: 'a1',
      title: 'Admin only',
      message: 'x',
      severity: 'HIGH',
      type: 'SYSTEM',
      targetRoles: ['admin'],
    })

    expect(events(admin, 'new_alert')).toHaveLength(1)
    expect(events(analyst, 'new_alert')).toHaveLength(0)
  })

  test('analysts keep their normal threat, alert and feed events', () => {
    const analyst = connect('analyst')
    socketManager.emitNewThreat(CRITICAL)
    socketManager.emitNewAlert({ _id: 'a2', title: 'Shared', message: 'm', severity: 'HIGH', type: 'THREAT' })

    const [threat] = events(analyst, 'new_threat')
    expect(threat.payload.sourceIP).toBe('203.0.113.77') // privileged copy, unredacted
    expect(events(analyst, 'new_threat')).toHaveLength(1)
    expect(events(analyst, 'live_feed_event')).toHaveLength(1)
    expect(events(analyst, 'new_alert')).toHaveLength(1)
  })

  test('viewers still receive exactly one redacted threat copy and no privileged events', () => {
    const viewer = connect('viewer')
    socketManager.emitNewThreat(CRITICAL)

    const copies = events(viewer, 'new_threat')
    expect(copies).toHaveLength(1)
    expect(copies[0].payload.sourceIP).not.toBe('203.0.113.77')
    expect(events(viewer, 'critical_alert')).toHaveLength(0)
  })

  test('a reconnecting analyst that asks for the admin room again is still refused', () => {
    const first = connect('analyst', { role: 'admin', room: 'admin' })
    sockets.splice(sockets.indexOf(first), 1) // disconnected
    const second = connect('analyst', { role: 'admin', room: 'admin' })
    socketManager.emitNewThreat(CRITICAL)

    expect(second.rooms.has('admin')).toBe(false)
    expect(events(second, 'critical_alert')).toHaveLength(0)
  })

  test('the room request is optional: the current frontend payload ({ role, userId }) joins the role rooms quietly', () => {
    const admin = connect('admin', { role: 'admin', userId: 'admin-1' })
    expect([...admin.rooms].sort()).toEqual([
      'admin',
      'all',
      'threat_subscribers',
      'threat_subscribers_admin',
      'threat_subscribers_privileged',
    ])
    expect(logger.warn).not.toHaveBeenCalled()
  })
})
