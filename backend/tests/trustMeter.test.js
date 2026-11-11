'use strict'
/**
 * AI Trust Meter: assessment rules (pure), agreement between the rules and their MongoDB filters, and the read API
 * (auth, viewer redaction, bounds, injection, no writes). In-memory MongoDB; only authentication is stubbed.
 */
process.env.SENTINEL_KEY = process.env.SENTINEL_KEY || 'unit-test-sentinel-key-trust-meter'
process.env.NODE_ENV = 'test'

const express = require('express')
const request = require('supertest')
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../middleware/auth', () => ({
  protect: (req, res, next) =>
    req.headers['x-test-role']
      ? ((req.user = { role: req.headers['x-test-role'], _id: 'u1' }), next())
      : res.status(401).json({ success: false }),
  restrictTo:
    (...roles) =>
    (req, res, next) =>
      roles.includes(req.user.role) ? next() : res.status(403).json({ success: false }),
  requirePermission: () => (req, res, next) => next(),
}))

const AIPrediction = require('../models/AIPrediction')
const ThreatLog = require('../models/ThreatLog')
const { STATES, STATE_ORDER, assessPrediction, stateFilter } = require('../utils/trustAssessment')

const base = (over = {}) => ({
  inputSource: 'network_traffic',
  sourceIP: '203.0.113.50',
  predictedClass: 'DDoS',
  classProbabilities: { BENIGN: 0.02, DDoS: 0.97, PortScan: 0.01 },
  threatScore: 0.94,
  modelVersion: 'xgb_cicids_v1',
  modelType: 'ensemble',
  isAnomaly: true,
  anomalyScore: 0.4,
  incompleteInput: false,
  defaultedFeatures: [],
  ...over,
})
const codes = (a) => a.reasons.map((r) => r.code)

describe('assessPrediction rules', () => {
  test('1. full evidence, nothing found: NO_ISSUES, with the explicit non-correctness caveat in the data', () => {
    const a = assessPrediction(base())
    expect(a.state).toBe(STATES.NO_ISSUES)
    expect(a.input).toMatchObject({ status: 'complete', defaultedCount: 0, providedCount: 50, expectedFeatures: 53 })
    expect(a.classifier.note).toMatch(/not a measured probability that this prediction is correct/)
    expect(codes(a)).toEqual(['SIGNALS_ALIGNED', 'PROVENANCE_UNKNOWN'])
  })

  test('2-3. missing fields, including non-zero defaulted ones: INCOMPLETE with the exact features', () => {
    const a = assessPrediction(base({ defaultedFeatures: ['flow_duration', 'bwd_psh_flags'], incompleteInput: true }))
    expect(a.state).toBe(STATES.INCOMPLETE)
    expect(a.input).toMatchObject({ defaultedCount: 2, providedCount: 48, fabricatedDefaults: ['flow_duration'] })
    expect(codes(a)).toEqual(expect.arrayContaining(['DEFAULTED_FEATURES', 'FABRICATED_DEFAULTS']))
  })

  test('4. missing zero-default fields the engine still called complete are reported as incomplete', () => {
    const a = assessPrediction(base({ defaultedFeatures: ['bwd_psh_flags', 'fwd_urg_flags'], incompleteInput: false }))
    expect(a.state).toBe(STATES.INCOMPLETE)
    expect(a.input.engineFlaggedIncomplete).toBe(false)
    expect(codes(a)).not.toContain('FABRICATED_DEFAULTS')
  })

  test('4b/11. historical record without completeness metadata: unverified, incompleteInput=false is not proof', () => {
    const a = assessPrediction(base({ defaultedFeatures: undefined, incompleteInput: false }))
    expect(a.state).toBe(STATES.INSUFFICIENT)
    expect(a.input.status).toBe('unverified')
    expect(a.input.providedCount).toBeNull()
    const r = a.reasons.find((x) => x.code === 'COMPLETENESS_UNVERIFIED')
    expect(r.description).toMatch(/does not prove/)
  })

  test('historical record flagged incomplete by the engine but without the list', () => {
    const a = assessPrediction(base({ defaultedFeatures: undefined, incompleteInput: true }))
    expect(a.state).toBe(STATES.INCOMPLETE)
    expect(codes(a)).toContain('ENGINE_INCOMPLETE_FLAG')
  })

  test('5. invalid stored probabilities: REVIEW, invalid labels named, confidence not shown', () => {
    const a = assessPrediction(base({ classProbabilities: { DDoS: 1.7, BENIGN: -0.1 } }))
    expect(a.state).toBe(STATES.REVIEW)
    expect(a.classifier.invalidProbabilityLabels.sort()).toEqual(['BENIGN', 'DDoS'])
    expect(a.classifier.confidence).toBeNull()
  })

  test('6. missing classifier confidence: INSUFFICIENT, never reconstructed', () => {
    const a = assessPrediction(base({ classProbabilities: undefined }))
    expect(a.state).toBe(STATES.INSUFFICIENT)
    expect(a.classifier).toMatchObject({ status: 'unavailable', confidence: null, topClasses: [] })
  })

  test('7-8. missing or out-of-range anomaly signal: INSUFFICIENT', () => {
    expect(assessPrediction(base({ anomalyScore: undefined })).anomaly.status).toBe('unavailable')
    const out = assessPrediction(base({ anomalyScore: -0.3 }))
    expect(out.anomaly.status).toBe('uninterpretable')
    expect(out.state).toBe(STATES.INSUFFICIENT)
  })

  test('9. unverifiable model version: REVIEW', () => {
    for (const modelVersion of ['v2.1-fallback', '', undefined]) {
      const a = assessPrediction(base({ modelVersion }))
      expect(a.state).toBe(STATES.REVIEW)
      expect(codes(a)).toContain('MODEL_VERSION_UNVERIFIED')
    }
  })

  test('10/17. dataset-level metrics never appear as per-prediction reasons', () => {
    const text = JSON.stringify(assessPrediction(base()))
    expect(text).not.toMatch(/98\.97|15\.2|recall|accuracy|trustworth/i)
  })

  test('12. BENIGN with anomaly flag: REVIEW (signal conflict), not proof of attack', () => {
    const a = assessPrediction(base({ predictedClass: 'BENIGN', classProbabilities: { BENIGN: 0.9, DDoS: 0.1 } }))
    expect(a.state).toBe(STATES.REVIEW)
    const r = a.reasons.find((x) => x.code === 'SIGNAL_CONFLICT')
    expect(r.description).toMatch(/does not show that the flow is an attack/)
  })

  test('13. high confidence does not override incomplete input', () => {
    const a = assessPrediction(base({ classProbabilities: { DDoS: 0.999 }, defaultedFeatures: ['flow_iat_min'] }))
    expect(a.classifier.confidence).toBe(0.999)
    expect(a.state).toBe(STATES.INCOMPLETE)
  })

  test('14. confidence (class probability) and threat score are reported separately', () => {
    const a = assessPrediction(base({ classProbabilities: { DDoS: 0.61, BENIGN: 0.39 }, threatScore: 0.94 }))
    expect(a.classifier.confidence).toBe(0.61)
    expect(a.threatScore).toBe(0.94)
    expect(a.classifier.topClasses).toEqual([
      { label: 'DDoS', probability: 0.61 },
      { label: 'BENIGN', probability: 0.39 },
    ])
  })

  test('15. no numeric trust/reliability score anywhere in the assessment', () => {
    const a = assessPrediction(base())
    const keys = JSON.stringify(Object.keys(a)) + JSON.stringify(a.reasons.map((r) => Object.keys(r)))
    expect(keys).not.toMatch(/trustScore|reliability|probabilityCorrect/i)
    expect(typeof a.state).toBe('string')
  })

  test('16. state precedence and reason selection', () => {
    expect(assessPrediction(base({ predictedClass: 'UNINSPECTED_TRAFFIC', defaultedFeatures: ['x'] })).state).toBe(
      STATES.UNAVAILABLE
    )
    const unknown = assessPrediction(base({ predictedClass: 'Unknown' }))
    expect(unknown.state).toBe(STATES.REVIEW)
    expect(codes(unknown)).toEqual(expect.arrayContaining(['UNKNOWN_OVERRIDE', 'CONFIDENCE_UNAVAILABLE']))
    const queued = assessPrediction(
      base({ predictedClass: 'BENIGN', isAnomaly: false, needsReview: true, honeypotCorroborated: true })
    )
    expect(queued.reasons.find((r) => r.code === 'IN_REVIEW_QUEUE').source).toMatch(/honeypotCorroborated/)
    expect(assessPrediction(base({ isAnomaly: false, anomalyScore: 0 })).reasons.map((r) => r.code)).toContain(
      'NO_ANOMALY_FLAG'
    )
  })

  test('rule-based honeypot classifications are out of scope', () => {
    expect(assessPrediction(base({ inputSource: 'honeypot_log', modelType: 'rules' }))).toBeNull()
  })
})

let mongo
const app = express().use(express.json()).use('/api/ai', require('../routes/aiEngine'))
const get = (path, role = 'admin') => {
  const r = request(app).get('/api/ai' + path)
  return role ? r.set('x-test-role', role) : r
}
const ids = {}

// One stored record per interesting case; `expect` is the state the rules give it.
const FIXTURES = [
  ['complete', base(), STATES.NO_ISSUES],
  ['incomplete', base({ defaultedFeatures: ['flow_duration'] }), STATES.INCOMPLETE],
  ['flag-only', base({ defaultedFeatures: undefined, incompleteInput: true }), STATES.INCOMPLETE],
  ['historical', base({ defaultedFeatures: undefined }), STATES.INSUFFICIENT],
  ['no-anomaly', base({ anomalyScore: undefined }), STATES.INSUFFICIENT],
  ['bad-anomaly', base({ anomalyScore: -0.5 }), STATES.INSUFFICIENT],
  ['no-confidence', base({ classProbabilities: { BENIGN: 1 } }), STATES.INSUFFICIENT],
  ['conflict', base({ predictedClass: 'BENIGN', classProbabilities: { BENIGN: 0.8 } }), STATES.REVIEW],
  ['unknown', base({ predictedClass: 'Unknown' }), STATES.REVIEW],
  ['fallback', base({ modelVersion: 'v2.1-fallback' }), STATES.REVIEW],
  ['bad-probs', base({ classProbabilities: { DDoS: 0.97, BENIGN: 1.5 } }), STATES.REVIEW],
  ['queued', base({ needsReview: true }), STATES.REVIEW],
  [
    'degraded',
    base({ predictedClass: 'UNINSPECTED_TRAFFIC', classProbabilities: { UNINSPECTED_TRAFFIC: 1 } }),
    STATES.UNAVAILABLE,
  ],
]

beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
  for (const [name, doc] of FIXTURES) {
    const d = { ...doc, rawFeatures: { secret: 'raw-request-field' } }
    if (d.defaultedFeatures === undefined) delete d.defaultedFeatures
    if (d.anomalyScore === undefined) delete d.anomalyScore
    ids[name] = (
      await AIPrediction.collection.insertOne({ ...d, createdAt: new Date(), updatedAt: new Date() })
    ).insertedId
  }
  const threat = await ThreatLog.create({
    severity: 'HIGH',
    sourceIP: '203.0.113.50',
    attackType: 'DDoS',
    predictionId: ids.complete,
  })
  await AIPrediction.collection.updateOne(
    { _id: ids.complete },
    { $set: { generatedThreat: threat._id, featureVector: Array(53).fill(1) } }
  )
  ids.threat = threat._id
  ids.honeypot = (
    await AIPrediction.create({
      inputSource: 'honeypot_log',
      modelType: 'rules',
      predictedClass: 'SSH Brute Force',
      threatScore: 0.5,
    })
  )._id
})

afterAll(async () => {
  await mongoose.disconnect()
  await mongo.stop()
})

describe('stateFilter agrees with assessPrediction on stored records', () => {
  test.each(STATE_ORDER)('%s', async (state) => {
    const docs = await AIPrediction.find({ $and: [{ inputSource: 'network_traffic' }, stateFilter(state)] }).lean()
    const expected = FIXTURES.filter(([, , s]) => s === state)
      .map(([n]) => String(ids[n]))
      .sort()
    expect(docs.map((d) => String(d._id)).sort()).toEqual(expected)
    for (const d of docs) expect(assessPrediction(d).state).toBe(state)
  })
})

describe('GET /api/ai/trust/predictions', () => {
  test('requires authentication', async () => {
    expect((await get('/trust/predictions', null)).status).toBe(401)
  })

  test('lists ML predictions only, with assessment, summary denominators and facets; no raw request data', async () => {
    const res = await get('/trust/predictions?limit=50')
    expect(res.status).toBe(200)
    expect(res.body.data).toHaveLength(FIXTURES.length)
    expect(res.body.data.every((p) => p.trust && p.inputSource === 'network_traffic')).toBe(true)
    expect(JSON.stringify(res.body)).not.toMatch(/raw-request-field|featureVector/)
    expect(res.body.summary.inScope).toBe(FIXTURES.length)
    expect(res.body.summary.byState).toEqual({
      UNAVAILABLE: 1,
      INCOMPLETE: 2,
      REVIEW: 5,
      INSUFFICIENT: 4,
      NO_ISSUES: 1,
    })
    expect(res.body.summary.completenessRecorded).toBe(
      FIXTURES.filter(([, d]) => Array.isArray(d.defaultedFeatures)).length
    )
    expect(res.body.facets.classes).toEqual(expect.arrayContaining(['BENIGN', 'DDoS', 'Unknown']))
    expect(res.body.facets.classes).not.toContain('SSH Brute Force')
  })

  test('state, class, model version and search filters', async () => {
    const st = await get('/trust/predictions?state=INCOMPLETE')
    expect(st.body.data.map((p) => String(p._id)).sort()).toEqual(
      [String(ids.incomplete), String(ids['flag-only'])].sort()
    )
    expect((await get('/trust/predictions?predictedClass=Unknown')).body.data).toHaveLength(1)
    expect((await get('/trust/predictions?modelVersion=v2.1-fallback')).body.data).toHaveLength(1)
    expect((await get('/trust/predictions?q=203.0.113')).body.data).toHaveLength(FIXTURES.length)
    expect((await get('/trust/predictions?q=.*')).body.data).toHaveLength(0)
    expect((await get('/trust/predictions?state=BOGUS')).body.data).toHaveLength(FIXTURES.length)
  })

  test('pagination is bounded and injection-shaped parameters are ignored', async () => {
    const r = await get('/trust/predictions?limit=100000')
    expect(r.body.pagination.limit).toBe(50)
    const inj = await get('/trust/predictions?predictedClass[$ne]=x&state[$gt]=&q[$regex]=.*&from[$gt]=1')
    expect(inj.status).toBe(200)
    expect(inj.body.data).toHaveLength(FIXTURES.length)
  })

  test('viewer: IPs redacted, same assessments', async () => {
    const r = await get('/trust/predictions?limit=50', 'viewer')
    expect(r.status).toBe(200)
    expect(r.body.data.every((p) => p.sourceIP === '203.0.113.xxx')).toBe(true)
    expect(r.body.summary.byState.REVIEW).toBe(5)
  })

  test('reads never write', async () => {
    const before = await AIPrediction.find().sort({ _id: 1 }).lean()
    await get('/trust/predictions?limit=50')
    await get(`/trust/predictions/${ids.complete}`)
    expect(await AIPrediction.find().sort({ _id: 1 }).lean()).toEqual(before)
  })
})

describe('GET /api/ai/trust/predictions/:id', () => {
  test('detail with linked threat and explanation availability (admin)', async () => {
    const r = await get(`/trust/predictions/${ids.complete}`)
    expect(r.status).toBe(200)
    const p = r.body.data.prediction
    expect(p.trust.state).toBe('NO_ISSUES')
    expect(p.threat).toMatchObject({ _id: String(ids.threat), severity: 'HIGH' })
    expect(p.explanation).toEqual({ storedVector: true, available: true, requiresRole: false })
    expect(JSON.stringify(r.body)).not.toMatch(/featureVector"|raw-request-field/)
  })

  test('viewer cannot be offered SHAP (admin/analyst endpoint) and gets redacted IPs', async () => {
    const p = (await get(`/trust/predictions/${ids.complete}`, 'viewer')).body.data.prediction
    expect(p.explanation).toEqual({ storedVector: true, available: false, requiresRole: true })
    expect(p.sourceIP).toBe('203.0.113.xxx')
  })

  test('invalid id 400, unknown 404, honeypot rule verdict 404 with reason', async () => {
    expect((await get('/trust/predictions/not-an-id')).status).toBe(400)
    expect((await get(`/trust/predictions/${new mongoose.Types.ObjectId()}`)).status).toBe(404)
    const hp = await get(`/trust/predictions/${ids.honeypot}`)
    expect(hp.status).toBe(404)
    expect(hp.body.error).toMatch(/Rule-based honeypot/)
  })
})

describe('defaultedFeatures metadata on store (backward compatible)', () => {
  const aiService = require('../services/aiService')
  beforeAll(() => {
    jest.spyOn(require('../services/aiEngineService'), 'getAlertThreshold').mockResolvedValue(0.9)
  })
  const store = (extra) =>
    aiService.storePrediction({
      inputSource: 'network_traffic',
      sourceIP: '198.51.100.1',
      predictedClass: 'BENIGN',
      threatScore: 0.1,
      ...extra,
    })

  test('a well-formed list is kept (deduplicated); absent stays absent', async () => {
    const a = await store({ defaultedFeatures: ['flow_duration', 'flow_duration', 'bwd_psh_flags'] })
    expect((await AIPrediction.findById(a._id).lean()).defaultedFeatures).toEqual(['flow_duration', 'bwd_psh_flags'])
    const b = await store({})
    expect((await AIPrediction.findById(b._id).lean()).defaultedFeatures).toBeUndefined()
  })

  test('malformed lists are dropped, never stored', async () => {
    for (const bad of ['flow_duration', [{ $gt: 1 }], ['<script>'], Array(54).fill('a')]) {
      const p = await store({ defaultedFeatures: bad })
      expect((await AIPrediction.findById(p._id).lean()).defaultedFeatures).toBeUndefined()
    }
  })
})
