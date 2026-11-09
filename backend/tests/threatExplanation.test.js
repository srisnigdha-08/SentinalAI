'use strict'

/**
 * XAI-001: on-demand per-threat SHAP explanation (services/threatExplanationService.js, GET /threats/:id/explanation).
 *
 * The explanation must come from the vector stored with the threat's own prediction, be refused rather than
 * fabricated when that is impossible (no vector, other schema, other model, not reproduced), map engine outages to
 * 503, never echo the stored vector, and be available to analysts and admins only.
 */
process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-test-jwt-secret-explanation'
process.env.JWT_REFRESH_SECRET = 'unit-test-refresh-secret-explanation'
process.env.HONEYPOT_API_KEY = 'unit-test-honeypot-key-explanation'
process.env.SENTINEL_KEY = 'unit-test-sentinel-key-explanation'

jest.mock('../config/db', () => jest.fn())
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({
  init: jest.fn(),
  emitNewThreat: jest.fn(),
  emitThreatUpdated: jest.fn(),
  emitNewAlert: jest.fn(),
  emitAIPrediction: jest.fn(),
  emitIPBlocked: jest.fn(),
  emitIPUnblocked: jest.fn(),
  getStats: jest.fn().mockReturnValue({}),
}))

const ThreatLog = require('../models/ThreatLog')
const AIPrediction = require('../models/AIPrediction')
const aiEngineService = require('../services/aiEngineService')
const { explainThreat, ExplanationError } = require('../services/threatExplanationService')

const THREAT_ID = '64b7f0a1c2d3e4f5a6b7c8d9'
const PRED_ID = '64b7f0a1c2d3e4f5a6b7c8da'
const VECTOR = Array.from({ length: 53 }, (_, i) => i + 0.5)

const chain = (value) => ({ select: jest.fn().mockReturnValue({ lean: jest.fn().mockResolvedValue(value) }) })

const storedPrediction = (over = {}) => ({
  _id: PRED_ID,
  inputSource: 'network_traffic',
  predictedClass: 'DDoS',
  threatScore: 0.9731,
  modelVersion: 'xgb_cicids_v1',
  featureVector: VECTOR,
  featureSchemaVersion: 'v2.1_53feat',
  createdAt: new Date('2026-11-03T10:00:00Z'),
  ...over,
})

const engineResult = (over = {}) => ({
  predictedClass: 'DDoS',
  explainedClass: 'DDoS',
  threatScore: 0.9731,
  confidence: 0.9731,
  classProbabilities: { DDoS: 0.9731, BENIGN: 0.0269 },
  isAnomaly: false,
  modelVersion: 'xgb_cicids_v1',
  featureSchemaVersion: 'v2.1_53feat',
  baseValue: -0.2,
  units: 'classifier margin (log-odds) for explainedClass',
  explainerAvailable: true,
  contributions: [
    { feature: 'init_win_bytes_forward', contribution: 2.1, value: 8192 },
    { feature: 'flow_duration', contribution: -0.4, value: 1200 },
  ],
  ...over,
})

let explainSpy
beforeEach(() => {
  jest.restoreAllMocks()
  ThreatLog.findById = jest.fn().mockReturnValue(chain({ _id: THREAT_ID, predictionId: PRED_ID }))
  AIPrediction.findById = jest.fn().mockReturnValue(chain(storedPrediction()))
  explainSpy = jest.spyOn(aiEngineService, 'explainVector').mockResolvedValue(engineResult())
})

const reasonOf = async (p) => {
  try {
    await p
  } catch (e) {
    expect(e).toBeInstanceOf(ExplanationError)
    return [e.reason, e.statusCode]
  }
  throw new Error('expected a refusal')
}

describe('threatExplanationService.explainThreat', () => {
  test('explains the reproduced prediction from the stored vector, with the stored score and model version', async () => {
    const out = await explainThreat(THREAT_ID)
    expect(explainSpy).toHaveBeenCalledWith(VECTOR, 'v2.1_53feat')
    expect(AIPrediction.findById).toHaveBeenCalledWith(PRED_ID)
    expect(out).toMatchObject({
      threatId: THREAT_ID,
      predictionId: PRED_ID,
      predictedClass: 'DDoS',
      threatScore: 0.9731,
      modelVersion: 'xgb_cicids_v1',
      reproduced: true,
    })
    expect(out.contributions).toHaveLength(2)
    expect(out).not.toHaveProperty('featureVector') // the stored vector is never returned
  })

  test('reads the hidden vector fields explicitly', async () => {
    await explainThreat(THREAT_ID)
    const sel = AIPrediction.findById.mock.results[0].value.select.mock.calls[0][0]
    expect(sel).toMatch(/\+featureVector/)
    expect(sel).toMatch(/\+featureSchemaVersion/)
  })

  test.each([
    ['THREAT_NOT_FOUND', 404, () => (ThreatLog.findById = jest.fn().mockReturnValue(chain(null)))],
    ['NO_LINKED_PREDICTION', 409, () => (ThreatLog.findById = jest.fn().mockReturnValue(chain({ _id: THREAT_ID })))],
    ['PREDICTION_MISSING', 409, () => (AIPrediction.findById = jest.fn().mockReturnValue(chain(null)))],
    [
      'NOT_A_FLOW',
      409,
      () =>
        (AIPrediction.findById = jest.fn().mockReturnValue(chain(storedPrediction({ inputSource: 'honeypot_log' })))),
    ],
    [
      'NO_STORED_VECTOR',
      409,
      () => (AIPrediction.findById = jest.fn().mockReturnValue(chain(storedPrediction({ featureVector: [] })))),
    ],
    [
      'NO_STORED_VECTOR',
      409,
      () =>
        (AIPrediction.findById = jest
          .fn()
          .mockReturnValue(chain(storedPrediction({ featureVector: VECTOR.slice(0, 52) })))),
    ],
    [
      'NO_STORED_VECTOR',
      409,
      () =>
        (AIPrediction.findById = jest
          .fn()
          .mockReturnValue(chain(storedPrediction({ featureSchemaVersion: undefined })))),
    ],
  ])('refuses with %s (%i) and never calls the engine', async (reason, status, arrange) => {
    arrange()
    expect(await reasonOf(explainThreat(THREAT_ID))).toEqual([reason, status])
    expect(explainSpy).not.toHaveBeenCalled()
  })

  test('refuses an explanation from a different model version', async () => {
    explainSpy.mockResolvedValue(engineResult({ modelVersion: 'xgb_cicids_v2' }))
    expect(await reasonOf(explainThreat(THREAT_ID))).toEqual(['MODEL_VERSION_MISMATCH', 409])
  })

  test.each([
    ['another class', { predictedClass: 'BENIGN' }],
    ['another score', { threatScore: 0.95 }],
  ])('refuses when re-scoring gives %s (NOT_REPRODUCED)', async (_label, over) => {
    explainSpy.mockResolvedValue(engineResult(over))
    expect(await reasonOf(explainThreat(THREAT_ID))).toEqual(['NOT_REPRODUCED', 409])
  })

  test('accepts the engine’s 4-decimal rounding of the same score', async () => {
    explainSpy.mockResolvedValue(engineResult({ threatScore: 0.97305 }))
    AIPrediction.findById = jest.fn().mockReturnValue(chain(storedPrediction({ threatScore: 0.9731 })))
    await expect(explainThreat(THREAT_ID)).resolves.toMatchObject({ reproduced: true })
  })

  test.each([
    [
      'engine down (no response)',
      Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' }),
      'ENGINE_UNAVAILABLE',
      503,
    ],
    ['circuit open', Object.assign(new Error('open'), { code: 'CIRCUIT_OPEN' }), 'ENGINE_UNAVAILABLE', 503],
    ['engine 5xx', Object.assign(new Error('x'), { response: { status: 500 } }), 'ENGINE_UNAVAILABLE', 503],
    ['schema conflict', Object.assign(new Error('x'), { response: { status: 409 } }), 'SCHEMA_MISMATCH', 409],
    ['vector rejected', Object.assign(new Error('x'), { response: { status: 422 } }), 'NO_STORED_VECTOR', 409],
  ])('maps %s', async (_label, err, reason, status) => {
    explainSpy.mockRejectedValue(err)
    expect(await reasonOf(explainThreat(THREAT_ID))).toEqual([reason, status])
  })

  test('reports a missing SHAP explainer distinctly', async () => {
    explainSpy.mockResolvedValue(engineResult({ explainerAvailable: false, contributions: [] }))
    expect(await reasonOf(explainThreat(THREAT_ID))).toEqual(['EXPLAINER_UNAVAILABLE', 503])
  })
})

describe('GET /threats/:id/explanation (router, role check)', () => {
  const express = require('express')
  const request = require('supertest')
  let app
  let svc

  beforeAll(() => {
    jest.resetModules()
    jest.doMock('../middleware/auth', () => {
      const actual = jest.requireActual('../middleware/auth')
      return {
        ...actual,
        protect: (req, _res, next) => {
          req.user = { id: 'u1', role: req.headers['x-test-role'], email: 'tester@sentinel.test' }
          next()
        },
      }
    })
    svc = require('../services/threatExplanationService')
    app = express()
    app.use(express.json())
    app.use('/api/threats', require('../routes/threats'))
  })

  // The file-level beforeEach restores all mocks, so the spy is created per test.
  beforeEach(() => jest.spyOn(svc, 'explainThreat'))

  afterAll(() => jest.dontMock('../middleware/auth'))

  test('viewers are refused (403) and the service is not called', async () => {
    const r = await request(app).get(`/api/threats/${THREAT_ID}/explanation`).set('x-test-role', 'viewer')
    expect(r.status).toBe(403)
    expect(svc.explainThreat).not.toHaveBeenCalled()
  })

  test.each(['analyst', 'admin'])('%s gets the explanation', async (role) => {
    svc.explainThreat.mockResolvedValue({ threatId: THREAT_ID, predictedClass: 'DDoS', contributions: [] })
    const r = await request(app).get(`/api/threats/${THREAT_ID}/explanation`).set('x-test-role', role)
    expect(r.status).toBe(200)
    expect(r.body.data.predictedClass).toBe('DDoS')
  })

  test('a refusal carries its reason code', async () => {
    svc.explainThreat.mockRejectedValue(new svc.ExplanationError('NOT_REPRODUCED', 409, 'not reproduced'))
    const r = await request(app).get(`/api/threats/${THREAT_ID}/explanation`).set('x-test-role', 'analyst')
    expect(r.status).toBe(409)
    expect(r.body.errors.reason).toBe('NOT_REPRODUCED')
  })

  test('an invalid id is rejected before any lookup', async () => {
    const r = await request(app).get('/api/threats/not-an-id/explanation').set('x-test-role', 'analyst')
    expect(r.status).toBe(400)
    expect(svc.explainThreat).not.toHaveBeenCalled()
  })
})
