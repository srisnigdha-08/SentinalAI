jest.mock('../models/HoneypotSession', () => ({ findOne: jest.fn(), findById: jest.fn(), create: jest.fn() }))
jest.mock('../models/ThreatLog', () => ({ create: jest.fn() }))
jest.mock('../models/Alert', () => ({ create: jest.fn() }))
jest.mock('../utils/logger', () => ({ info: jest.fn(), error: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ emitHoneypotEvent: jest.fn(), emitNewThreat: jest.fn() }))
jest.mock('../services/honeypotService', () => ({
  closeSession: jest.fn(),
  recordSessionActivity: jest.fn(),
  sensitiveFilesIn: (text) => ['/etc/passwd', '/etc/shadow', '/.ssh/', '/root/'].filter((f) => text.includes(f)),
}))
const sessions = require('../models/HoneypotSession')
const closure = require('../services/honeypotService')
const logger = require('../utils/logger')
const collector = require('../../honeypot/collectors/session_collector')
let session
beforeEach(() => {
  jest.clearAllMocks()
  session = {
    _id: 'offline-document',
    sessionId: 'offline',
    sourceIP: '192.0.2.10',
    iocExtracted: { urls: [], hashes: [] },
    malwareDownloaded: [],
    deceptionScore: 0,
    durationSeconds: 60,
    save: jest.fn().mockResolvedValue(true),
  }
  sessions.findOne.mockResolvedValue(session)
  sessions.findById.mockResolvedValue(session)
  closure.closeSession.mockResolvedValue(session)
  closure.recordSessionActivity.mockResolvedValue(session)
})
test('a completed closure is not processed or broadcast twice', async () => {
  session.closureAnalysisState = 'complete'
  expect(await collector.onSessionClosed({ sessionId: 'offline', sourceIP: '192.0.2.10' })).toBe(session)
  expect(closure.closeSession).not.toHaveBeenCalled()
  expect(require('../websocket/socketManager').emitHoneypotEvent).not.toHaveBeenCalled()
})

test('session-open signal is explicitly heuristic while preserving HIGH/0.75/MONITORING semantics', async () => {
  sessions.findOne.mockResolvedValue(null)
  sessions.create.mockResolvedValue(session)
  const threats = require('../models/ThreatLog')
  threats.create.mockResolvedValue({ _id: 'offline-heuristic-threat' })
  await collector.onSessionOpened({ sessionId: 'heuristic-offline', sourceIP: '192.0.2.10' })
  expect(threats.create).toHaveBeenCalledWith(
    expect.objectContaining({
      severity: 'HIGH',
      aiScore: 0.75,
      status: 'MONITORING',
      attackType: 'SSH Brute Force',
      notes: '[SESSION_OPEN_HEURISTIC] Fixed SSH session-open signal; no RF/IF inference has run for this signal.',
    })
  )
  expect(session.linkedThreatLog).toBe('offline-heuristic-threat')
  expect(require('../services/honeypotService').closeSession).not.toHaveBeenCalled()
})
test('credential persistence and closure are delegated to the database claim owner', async () => {
  const credentials = [{ username: 'offline-captured-user', password: 'offline-captured-password', success: false }]
  await collector.onSessionClosed({ sessionId: 'offline', sourceIP: '192.0.2.10', durationSeconds: 0, credentials })
  expect(closure.closeSession).toHaveBeenCalledWith(session._id, {
    telemetry: { durationSeconds: 0, credentials, hassh: undefined },
  })
  expect(session.save).not.toHaveBeenCalled()
})
test('download returns its persisted session and a missing session returns null', async () => {
  expect(
    await collector.onFileDownload({
      sessionId: 'offline',
      sourceIP: '192.0.2.10',
      url: 'https://example.invalid/file',
    })
  ).toBe(session)
  // One atomic update instead of read-modify-save (M2)
  expect(closure.recordSessionActivity).toHaveBeenCalledWith(
    { sessionId: 'offline' },
    { urls: ['https://example.invalid/file'], hashes: [], malware: ['https://example.invalid/file'], downloads: 1 }
  )
  expect(session.save).not.toHaveBeenCalled()
  closure.recordSessionActivity.mockResolvedValue(null)
  expect(await collector.onFileDownload({ sessionId: 'missing', sourceIP: '192.0.2.10' })).toBeNull()
})
test('command activity is recorded atomically, opening the session first when it is unknown', async () => {
  closure.recordSessionActivity.mockResolvedValueOnce(null).mockResolvedValueOnce(session)
  sessions.findOne.mockResolvedValue(session) // onSessionOpened finds the session created by the opener
  const s = await collector.onCommandReceived({
    sessionId: 'offline',
    sourceIP: '192.0.2.10',
    command: 'cat /etc/passwd',
    intent: 'CREDENTIAL_HARVEST',
  })
  expect(s).toBe(session)
  expect(closure.recordSessionActivity).toHaveBeenCalledTimes(2)
  const [, activity] = closure.recordSessionActivity.mock.calls[1]
  expect(activity.files).toEqual(['/etc/passwd'])
  expect(activity.commands[0]).toMatchObject({ command: 'cat /etc/passwd', intent: 'CREDENTIAL_HARVEST' })
})
test('download failure propagates and logs only error type, without captured payload', async () => {
  closure.recordSessionActivity.mockRejectedValue(new TypeError('offline-private-captured-value'))
  await expect(
    collector.onFileDownload({ sessionId: 'offline', sourceIP: '192.0.2.10', url: 'https://example.invalid/file' })
  ).rejects.toBeInstanceOf(TypeError)
  expect(logger.error).toHaveBeenCalledWith('[Collector] onFileDownload: TypeError')
})
