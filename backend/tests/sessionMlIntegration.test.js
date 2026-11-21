'use strict'
/**
 * Honeypot-session ML, backend side (docs/SESSION_ML.md, "How it is verified"): the engine's shadow "sessionML" block
 * is validated and stored beside, never instead of, the rule-based classification; it never changes threats,
 * alerts or containment; engine / model failures are stored honestly; duplicate and concurrent closures produce one
 * record; the Capability Status never claims more than the engine reports. In-memory MongoDB; the AI engine is a
 * mock; no containment adapter runs (executeAutoBlock is a recorder).
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

const mockPredict = jest.fn()
const mockSessionMlStatus = jest.fn()
jest.mock('../services/aiEngineService', () => ({
  predictHoneypotSession: (...a) => mockPredict(...a),
  getDeceptionScore: jest.fn().mockResolvedValue(null),
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
  getAlertThreshold: jest.fn().mockResolvedValue(0.9),
  getDeceptionStats: jest.fn().mockResolvedValue(null),
  getSessionMlStatus: (...a) => mockSessionMlStatus(...a),
}))
jest.mock('../services/aiService', () => ({ storePrediction: jest.fn().mockResolvedValue({}) }))
jest.mock('../services/campaignService', () => ({ clusterSession: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({
  emitHoneypotEvent: jest.fn(),
  emitNewThreat: jest.fn(),
  emitThreatUpdated: jest.fn(),
  emitNewAlert: jest.fn(),
  emitIPBlocked: jest.fn(),
}))
const mockAutoBlock = jest.fn().mockResolvedValue({ success: true })
jest.mock('../services/containmentService', () => ({ executeAutoBlock: (...a) => mockAutoBlock(...a) }))
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const fs = require('fs')
const path = require('path')
const HoneypotSession = require('../models/HoneypotSession')
const ThreatLog = require('../models/ThreatLog')
const SystemSetting = require('../models/SystemSetting')
const honeypotService = require('../services/honeypotService')
const collector = require('../../honeypot/collectors/session_collector')
const { sanitizeSessionMl, engineUnavailable, STATUSES } = require('../utils/sessionMl')
const { redactHoneypotSession } = require('../utils/redact')

const ML_OK = (sessionId, extra = {}) => ({
  status: 'OK',
  sessionId,
  shadowOnly: true,
  mode: 'shadow',
  prediction: 'dropper',
  score: 0.97,
  scores: { dropper: 0.97, recon: 0.03 },
  calibrated: false,
  modelName: 'session_classifier',
  modelVersion: 'shadow-0.1',
  featureSchemaVersion: 'session_v2',
  reasonCodes: ['DOWNLOAD_ATTEMPT', 'EXECUTION_MARKER'],
  evidenceSource: 'operator',
  inferredAt: '2026-11-13T10:00:00Z',
  ...extra,
})
const RULES = (predictedClass = 'SSH Brute Force', threatScore = 0.7) => ({
  predictedClass,
  threatScore,
  classificationMethod: 'honeypot_rules',
})

describe('sanitizeSessionMl', () => {
  test('a valid shadow prediction keeps exactly the whitelisted fields', () => {
    const r = sanitizeSessionMl(
      { ...ML_OK('s1'), commands: ['wget x'], sourceIP: '203.0.113.9', credentials: [{ password: 'p' }] },
      's1'
    )
    expect(r).toMatchObject({
      status: 'OK',
      prediction: 'dropper',
      score: 0.97,
      shadowOnly: true,
      mode: 'shadow',
      modelVersion: 'shadow-0.1',
      featureSchemaVersion: 'session_v2',
      evidenceSource: 'operator',
      sessionId: 's1',
      calibrated: false,
    })
    expect(r.inferredAt).toEqual(new Date('2026-11-13T10:00:00Z'))
    const text = JSON.stringify(r)
    for (const leak of ['wget', '203.0.113.9', 'password', 'scores']) expect(text).not.toContain(leak)
  })

  test.each(STATUSES.filter((s) => !['OK', 'ENGINE_UNAVAILABLE', 'NOT_REPORTED', 'INVALID_RESULT'].includes(s)))(
    'status %s never carries a prediction or score',
    (status) => {
      const r = sanitizeSessionMl({ ...ML_OK('s1'), status }, 's1')
      expect(r.status).toBe(status)
      expect(r.prediction).toBeNull()
      expect(r.score).toBeNull()
    }
  )

  test.each([
    ['another session', { sessionId: 'other' }],
    ['not shadow-only', { shadowOnly: false }],
    ['missing shadowOnly', { shadowOnly: undefined }],
    ['score above 1', { score: 1.5 }],
    ['NaN score', { score: NaN }],
    ['string score', { score: '0.9' }],
    ['no prediction', { prediction: null }],
    ['prediction with markup', { prediction: '<script>' }],
    ['no model version', { modelVersion: null }],
    ['unknown status', { status: 'ACTIVE' }],
    ['backend-only status', { status: 'ENGINE_UNAVAILABLE' }],
  ])('%s -> INVALID_RESULT with no prediction', (_name, change) => {
    const r = sanitizeSessionMl(ML_OK('s1', change), 's1')
    expect(r.status).toBe('INVALID_RESULT')
    expect(r.prediction).toBeNull()
    expect(r.score).toBeNull()
  })

  test('absent, malformed and unavailable blocks are explicit states', () => {
    expect(sanitizeSessionMl(undefined, 's').status).toBe('NOT_REPORTED')
    expect(sanitizeSessionMl([1], 's').status).toBe('INVALID_RESULT')
    expect(sanitizeSessionMl('OK', 's').status).toBe('INVALID_RESULT')
    expect(engineUnavailable('s')).toMatchObject({ status: 'ENGINE_UNAVAILABLE', prediction: null, shadowOnly: true })
  })

  test('reason codes are filtered, de-duplicated and bounded; sources are normalised', () => {
    const r = sanitizeSessionMl(
      ML_OK('s', {
        reasonCodes: ['A_B', 'A_B', 'lower', '<x>', 5, ...Array.from({ length: 60 }, (_, i) => `C${i}`)],
        evidenceSource: 'real',
      }),
      's'
    )
    expect(r.reasonCodes[0]).toBe('A_B')
    expect(r.reasonCodes).not.toContain('lower')
    expect(r.reasonCodes.length).toBe(40)
    expect(r.evidenceSource).toBe('unknown')
  })
})

describe('closure integration (in-memory MongoDB)', () => {
  let mongoServer
  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create()
    await mongoose.connect(mongoServer.getUri())
  }, 60000)
  afterAll(async () => {
    await mongoose.disconnect()
    if (mongoServer) await mongoServer.stop()
  })
  beforeEach(async () => {
    jest.clearAllMocks()
    for (const c of ['honeypotsessions', 'threatlogs', 'alerts', 'systemsettings', 'blockedips'])
      await mongoose.connection.db.collection(c).deleteMany({})
  })

  const open = (sessionId, sourceIP = '198.51.100.70') => collector.onSessionOpened({ sessionId, sourceIP })
  const close = async (sessionId, ip) => {
    const s = await open(sessionId, ip)
    await honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 5 } })
    return HoneypotSession.findById(s._id).lean()
  }

  test('the shadow block is stored beside the unchanged rule-based classification', async () => {
    mockPredict.mockImplementation(async (p) => ({ success: true, result: RULES(), sessionML: ML_OK(p.sessionId) }))
    const s = await close('ml-1')
    expect(s.aiClassification).toBe('SSH Brute Force')
    expect(s.aiClassificationMethod).toBe('honeypot_rules')
    expect(s.aiThreatScore).toBe(0.7)
    expect(s.sessionMl).toMatchObject({ status: 'OK', prediction: 'dropper', shadowOnly: true, sessionId: 'ml-1' })
    expect(JSON.stringify(s.sessionMl)).not.toMatch(/198\.51\.100\.70/)
  })

  test('an ML prediction never changes threats, alerts or containment', async () => {
    await SystemSetting.create({ key: 'autoBlockEnabled', value: true })
    const run = async (id, ip, ml) => {
      mockPredict.mockImplementation(async (p) => ({ success: true, result: RULES('BENIGN', 0.1), sessionML: ml(p) }))
      const s = await close(id, ip)
      const threat = await ThreatLog.findOne({ sourceIP: ip }).lean()
      const alerts = await mongoose.connection.db.collection('alerts').countDocuments({})
      return { s, threat, alerts }
    }
    const without = await run('ml-a', '203.0.113.71', () => undefined)
    const blocksWithout = mockAutoBlock.mock.calls.length
    // The most alarming shadow output possible, for an otherwise benign session
    const withMl = await run('ml-b', '203.0.113.72', (p) =>
      ML_OK(p.sessionId, { prediction: 'malicious', score: 1, reasonCodes: ['DOWNLOAD_ATTEMPT'] })
    )
    expect(mockAutoBlock.mock.calls.length).toBe(blocksWithout) // no containment request from ML
    expect(mockAutoBlock).not.toHaveBeenCalled()
    expect(withMl.s.aiClassification).toBe(without.s.aiClassification)
    expect(withMl.s.aiThreatScore).toBe(without.s.aiThreatScore)
    expect(withMl.threat.status).toBe(without.threat.status)
    expect(withMl.threat.attackType).toBe(without.threat.attackType)
    expect(withMl.s.sessionMl.prediction).toBe('malicious')
    expect(await mongoose.connection.db.collection('blockedips').countDocuments({})).toBe(0)
  })

  test('rule-based containment still works exactly as before (ML present or not)', async () => {
    await SystemSetting.create({ key: 'autoBlockEnabled', value: true })
    mockPredict.mockImplementation(async (p) => ({
      success: true,
      result: RULES('RCE Attempt', 0.99),
      sessionML: ML_OK(p.sessionId, { prediction: 'benign-looking', score: 0.99 }),
    }))
    await close('ml-c', '203.0.113.73')
    expect(mockAutoBlock).toHaveBeenCalledTimes(1) // the rules decide, as before
  })

  test('engine unavailable: rule analysis pending, ML stored as ENGINE_UNAVAILABLE with no prediction', async () => {
    mockPredict.mockResolvedValue(null)
    const s = await close('ml-d')
    expect(s.aiAnalysisPending).toBe(true)
    expect(s.sessionMl).toMatchObject({ status: 'ENGINE_UNAVAILABLE', prediction: null, score: null })
  })

  test('model unavailable and older engines without the block are stored honestly', async () => {
    mockPredict.mockImplementation(async (p) => ({
      success: true,
      result: RULES(),
      sessionML: {
        status: 'MODEL_UNAVAILABLE',
        sessionId: p.sessionId,
        shadowOnly: true,
        reasonCodes: ['NO_COMMANDS'],
      },
    }))
    expect((await close('ml-e')).sessionMl).toMatchObject({ status: 'MODEL_UNAVAILABLE', prediction: null })
    mockPredict.mockResolvedValue({ success: true, result: RULES() })
    expect((await close('ml-f')).sessionMl).toMatchObject({ status: 'NOT_REPORTED', prediction: null })
  })

  test('a result for another session is refused', async () => {
    mockPredict.mockResolvedValue({ success: true, result: RULES(), sessionML: ML_OK('someone-else') })
    expect((await close('ml-g')).sessionMl).toMatchObject({ status: 'INVALID_RESULT', prediction: null })
  })

  test('duplicate and concurrent closures analyse once and keep one record', async () => {
    mockPredict.mockImplementation(async (p) => ({ success: true, result: RULES(), sessionML: ML_OK(p.sessionId) }))
    const s = await open('ml-h')
    const results = await Promise.allSettled([
      honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 5 } }),
      honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 5 } }),
      honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 5 } }),
    ])
    expect(mockPredict).toHaveBeenCalledTimes(1)
    expect(results.filter((r) => r.status === 'fulfilled').length).toBeGreaterThanOrEqual(1)
    const again = await honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 5 } })
    expect(again.closureAnalysisState).toBe('complete') // a completed closure is returned, not re-analysed
    expect(mockPredict).toHaveBeenCalledTimes(1)
    expect(await HoneypotSession.countDocuments({ sessionId: 'ml-h' })).toBe(1)
  })

  test('historical sessions without the field are untouched and read as absent', async () => {
    await mongoose.connection.db
      .collection('honeypotsessions')
      .insertOne({ sessionId: 'legacy-1', sourceIP: '198.51.100.99', status: 'closed', aiClassification: 'BENIGN' })
    const legacy = await HoneypotSession.findOne({ sessionId: 'legacy-1' }).lean()
    expect(legacy.sessionMl).toBeUndefined()
    expect(legacy.aiClassification).toBe('BENIGN')
  })
})

describe('viewer redaction', () => {
  test('viewers keep the ML block (it holds no IP, command or credential) while commands and IPs are redacted', () => {
    const session = {
      sessionId: 's',
      sourceIP: '203.0.113.50',
      commands: [{ command: 'wget http://203.0.113.50/x' }],
      sessionMl: sanitizeSessionMl(ML_OK('s'), 's'),
    }
    const v = redactHoneypotSession(session, 'viewer')
    expect(v.sourceIP).not.toBe('203.0.113.50')
    expect(v.commands[0].command).toBe('[REDACTED_COMMAND]')
    expect(v.sessionMl.prediction).toBe('dropper')
    expect(JSON.stringify(v.sessionMl)).not.toContain('203.0.113.50')
  })
})

describe('Capability Status for honeypot-session ML', () => {
  const { getCapabilities, LABELS } = require('../services/capabilityService')
  const byId = async () => Object.fromEntries((await getCapabilities()).items.map((i) => [i.id, i]))
  const ROOT = path.join(__dirname, '..', '..')

  test('no model: pipeline verified, model blocked (insufficient labelled data), effectiveness experimental', async () => {
    mockSessionMlStatus.mockResolvedValue({
      mode: 'shadow',
      featureSchemaVersion: 'session_v2',
      modelStatus: 'MODEL_UNAVAILABLE',
      reason: 'no session-classifier manifest in session_ml/',
      shadowOnly: true,
    })
    const c = await byId()
    expect(c.session_ml_pipeline.label).toBe('implemented_and_verified')
    expect(c.session_ml.label).toBe('blocked')
    expect(c.session_ml.summary).toMatch(/^SHADOW ONLY — INSUFFICIENT LABELLED DATA/)
    expect(c.session_ml_effectiveness.label).toBe('experimental')
    for (const id of ['session_ml_pipeline', 'session_ml', 'session_ml_effectiveness'])
      expect(Object.keys(LABELS)).toContain(c[id].label)
    for (const f of [...c.session_ml_pipeline.facts.evidence, c.session_ml.facts.audit])
      expect(fs.existsSync(path.join(ROOT, f))).toBe(true)
    const audit = JSON.parse(fs.readFileSync(path.join(ROOT, c.session_ml.facts.audit), 'utf8'))
    expect(audit.totals.independentLabels).toBe(0)
    expect(c.session_ml.summary).toContain(`${audit.totals.sessions} honeypot sessions`)
  })

  test('even a loaded model is only shadow, never verified; effectiveness stays experimental', async () => {
    mockSessionMlStatus.mockResolvedValue({
      mode: 'shadow',
      featureSchemaVersion: 'session_v2',
      modelStatus: 'OK',
      modelVersion: 'shadow-0.1',
      shadowOnly: true,
    })
    const c = await byId()
    expect(c.session_ml.label).toBe('shadow_only')
    expect(c.session_ml_effectiveness.label).toBe('experimental')
  })

  test('an unreachable engine or an invalid artifact never reads as a working model', async () => {
    for (const status of [
      null,
      { modelStatus: 'INVALID_ARTIFACT', mode: 'shadow', featureSchemaVersion: 'session_v2' },
    ]) {
      mockSessionMlStatus.mockResolvedValue(status)
      const c = await byId()
      expect(c.session_ml.label).toBe('blocked')
      expect(c.session_ml_pipeline.label).toBe('implemented_and_verified')
    }
    mockSessionMlStatus.mockRejectedValue(new Error('ECONNREFUSED'))
    expect((await byId()).session_ml.label).toBe('blocked')
  })
})
