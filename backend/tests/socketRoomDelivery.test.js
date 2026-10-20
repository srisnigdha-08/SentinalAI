'use strict'

// Every authenticated socket joins 'all' and 'threat_subscribers' (socketManager join_room), so a
// redacted copy sent to those rooms would reach admins/analysts a second time.

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../models/ThreatLog', () => ({}))

const socketManager = require('../websocket/socketManager')

const PRIVILEGED_ROOMS = ['admin', 'analyst', 'all', 'threat_subscribers', 'threat_subscribers_privileged']

const captureEmits = (fn) => {
  const emits = []
  const io = {
    engine: { clientsCount: 0 }, // init() starts the health interval, which reads this
    on: jest.fn(),
    to: jest.fn((rooms) => ({
      emit: (event, payload) => emits.push({ rooms: [].concat(rooms), event, payload }),
    })),
  }
  socketManager.init(io)
  fn()
  return emits
}

const roomsFor = (emits, event) => emits.filter((e) => e.event === event).map((e) => e.rooms)

describe('socket room delivery: one copy per role', () => {
  afterAll(() => socketManager.stopHealthBroadcast())

  test('honeypot_command: raw to admin/analyst, redacted only to viewer', () => {
    const emits = captureEmits(() =>
      socketManager.emitHoneypotEvent('honeypot_command', { sessionId: 's1', sourceIP: '203.0.113.5', command: 'uname -a' })
    )
    const deliveries = roomsFor(emits, 'honeypot_command')
    expect(deliveries).toEqual([['admin', 'analyst'], ['viewer']])

    const feed = roomsFor(emits, 'live_feed_event')
    expect(feed).toEqual([['admin', 'analyst'], ['viewer']])
  })

  test('ai_prediction redacted copy does not target rooms privileged sockets are in', () => {
    const emits = captureEmits(() =>
      socketManager.emitAIPrediction({ _id: 'p1', sourceIP: '203.0.113.5', predictedClass: 'DDoS', threatScore: 0.8 })
    )
    const [raw, redacted] = roomsFor(emits, 'ai_prediction')
    expect(raw).toEqual(['admin', 'analyst'])
    for (const room of redacted) expect(PRIVILEGED_ROOMS).not.toContain(room)
  })
})
