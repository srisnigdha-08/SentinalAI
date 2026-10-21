process.env.SENTINEL_KEY = 'offline-internal-ai-contract-key'
const mockGet = jest.fn()
const mockPost = jest.fn()
jest.mock('axios', () => ({ create: () => ({ get: mockGet, post: mockPost }) }))
jest.mock('../utils/logger', () => ({ info: jest.fn(), error: jest.fn(), warn: jest.fn() }))
const ai = require('../services/aiEngineService')
beforeEach(() => {
  jest.resetAllMocks()
})
test('readiness requires loaded models and successful internal-key authentication', async () => {
  mockGet.mockResolvedValueOnce({ data: { status: 'ok' } }).mockResolvedValueOnce({ data: { featureCount: 53 } })
  expect(await ai.getHealth()).toEqual({ status: 'ok', authenticated: true })
  expect(mockGet).toHaveBeenNthCalledWith(2, '/model/info', { timeout: 1500 })
})
test('public ready endpoint alone cannot conceal an invalid internal credential', async () => {
  mockGet
    .mockResolvedValueOnce({ data: { status: 'ok' } })
    .mockRejectedValueOnce({ response: { status: 403 }, message: 'offline-private-credential' })
  const health = await ai.getHealth()
  expect(health.status).toBe('unreachable')
  expect(health.error.includes('offline-private-credential')).toBe(false)
})
test('models unavailable cannot claim authenticated readiness', async () => {
  mockGet.mockResolvedValueOnce({ data: { status: 'unavailable' } })
  expect((await ai.getHealth()).status).toBe('unreachable')
  expect(mockGet).toHaveBeenCalledTimes(1)
})
test('invalid model input returns sanitized 422 rather than masquerading as service outage', async () => {
  mockPost.mockRejectedValue({ response: { status: 422, data: { detail: 'offline-private-input' } } })
  await expect(ai.predictRecord({ flow_duration: 'invalid' })).rejects.toMatchObject({
    statusCode: 422,
    message: 'Invalid AI feature input',
  })
})
test('actual dependency loss still returns the existing unavailable result and omits unsafe error text', async () => {
  mockPost.mockRejectedValue(new Error('offline-private-untrusted-error'))
  expect(await ai.predictRecord({})).toBeNull()
  expect(require('../utils/logger').warn).toHaveBeenCalledWith('[AI] predict failed (Error)')
})

test('model reload sends the separate admin key only when configured (M9)', async () => {
  mockPost.mockResolvedValue({ data: { success: true } })
  process.env.AI_ENGINE_ADMIN_KEY = 'admin-key-test'
  try {
    await ai.reloadModel()
  } finally {
    delete process.env.AI_ENGINE_ADMIN_KEY
  }
  await ai.reloadModel()
  expect(mockPost.mock.calls[0][2].headers).toEqual({ 'X-Admin-Key': 'admin-key-test' })
  expect(mockPost.mock.calls[1][2].headers).toEqual({})
})
