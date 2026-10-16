jest.mock('../services/honeypotService', () => ({ findSessionById: jest.fn(), findSessions: jest.fn() }))
jest.mock('../services/alertService', () => ({}))
jest.mock('../websocket/socketManager', () => ({}))
jest.mock('../utils/logger', () => ({}))
const service = require('../services/honeypotService')
const controller = require('../controllers/honeypotController')
const credentials = Object.freeze([
  Object.freeze({ username: 'offline-captured-user', password: 'offline-captured-password', success: false }),
])
const session = Object.freeze({ sessionId: 'offline-privacy', credentials })
const response = () => ({ status: jest.fn().mockReturnThis(), json: jest.fn() })
beforeEach(() => {
  service.findSessionById.mockResolvedValue(session)
  service.findSessions.mockResolvedValue({ data: [session], total: 1, page: 1, limit: 20 })
})
test.each(['viewer', undefined])(
  'detail response excludes captured login fields for role %s without altering storage',
  async (role) => {
    const res = response()
    const next = jest.fn()
    await controller.getSession({ params: { id: 'offline' }, user: { role } }, res, next)
    expect(next).not.toHaveBeenCalled()
    const data = res.json.mock.calls[0][0].data.session
    expect(data.credentials).toEqual([{ success: false }])
    expect(JSON.stringify(data).includes(credentials[0].password)).toBe(false)
    expect(session.credentials).toBe(credentials)
  }
)
test.each(['admin', 'analyst'])('existing authorized forensic detail remains available for role %s', async (role) => {
  const res = response()
  await controller.getSession({ params: { id: 'offline' }, user: { role } }, res, jest.fn())
  expect(res.json.mock.calls[0][0].data.session.credentials[0].password === credentials[0].password).toBe(true)
})
test('viewer list retains attempt counts/success metadata but never the captured username/password', async () => {
  const res = response()
  await controller.getSessions({ query: {}, user: { role: 'viewer' } }, res, jest.fn())
  const body = res.json.mock.calls[0][0]
  expect(body.pagination.total).toBe(1)
  expect(body.data[0].credentials).toHaveLength(1)
  expect(Object.keys(body.data[0].credentials[0])).toEqual(['success'])
})
