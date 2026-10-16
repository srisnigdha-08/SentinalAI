jest.mock('../models/ThreatLog', () => ({ countDocuments: jest.fn() }))
jest.mock('../services/threatService', () => ({ getAttackVectorTrend: jest.fn() }))
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
const Threat = require('../models/ThreatLog')
const service = require('../services/threatService')
const manager = require('../websocket/socketManager')
const time = require('../utils/reportingTime')
const beforeMidnight = new Date('2026-12-31T18:29:59.999Z')
const afterMidnight = new Date('2026-12-31T18:30:00Z')
beforeEach(() => {
  jest.useFakeTimers()
  jest.setSystemTime(beforeMidnight)
  jest.clearAllMocks()
})
afterEach(() => {
  manager.stopHealthBroadcast()
  jest.useRealTimers()
})
test('attack-vector response metadata matches query when aggregation crosses IST midnight', async () => {
  service.getAttackVectorTrend.mockImplementation(async () => {
    jest.setSystemTime(afterMidnight)
    return []
  })
  const res = { status: jest.fn().mockReturnThis(), json: jest.fn() }
  const next = jest.fn()
  await require('../controllers/threatController').getVectorTrend({ query: {} }, res, next)
  expect(next).not.toHaveBeenCalled()
  expect(service.getAttackVectorTrend).toHaveBeenCalledWith(7, beforeMidnight)
  expect(res.json.mock.calls[0][0].data.reporting).toEqual(time.metadata(7, beforeMidnight))
})
test('WebSocket snapshot uses the same IST range for counters and metadata across midnight', async () => {
  let connect
  const io = {
    on: (_event, listener) => {
      connect = listener
    },
    engine: { clientsCount: 0 },
  }
  manager.init(io)
  const handlers = {}
  const socket = {
    id: 'reporting-test',
    user: { role: 'viewer' },
    on: (event, handler) => {
      handlers[event] = handler
    },
    emit: jest.fn(),
  }
  connect(socket)
  Threat.countDocuments.mockImplementation(async () => {
    jest.setSystemTime(afterMidnight)
    return 0
  })
  await handlers.request_stats()
  expect(Threat.countDocuments).toHaveBeenNthCalledWith(1, { createdAt: time.filter(1, beforeMidnight) })
  expect(Threat.countDocuments).toHaveBeenNthCalledWith(2, {
    severity: 'CRITICAL',
    createdAt: time.filter(1, beforeMidnight),
  })
  expect(socket.emit).toHaveBeenCalledWith(
    'stats_snapshot',
    expect.objectContaining({ totalToday: 0, reporting: time.metadata(1, beforeMidnight) })
  )
})
test('WebSocket health broadcast metadata matches its counted IST day', async () => {
  const emit = jest.fn()
  const io = { engine: { clientsCount: 1 }, to: () => ({ emit }) }
  Threat.countDocuments.mockImplementation(async () => {
    jest.setSystemTime(afterMidnight)
    return 0
  })
  manager.startHealthBroadcast(io)
  jest.setSystemTime(new Date(beforeMidnight.getTime() - 15000))
  await jest.advanceTimersByTimeAsync(15000)
  expect(Threat.countDocuments).toHaveBeenCalledWith({ createdAt: time.filter(1, beforeMidnight) })
  expect(emit).toHaveBeenCalledWith(
    'system_health',
    expect.objectContaining({ threatsToday: 0, reporting: time.metadata(1, beforeMidnight) })
  )
})
