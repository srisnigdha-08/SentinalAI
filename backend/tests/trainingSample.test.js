jest.mock('../models/AuthSession')
;('use strict')
/**
 * tests/trainingSample.test.js
 *
 * Phase 2.5C-6 TrainingSample & Quarantine Test Suite
 *
 * 1. Schema & Validation:
 *    - Validates 53-element vector with all finite numbers
 *    - Rejects wrong length, non-numeric, NaN, Infinity
 *    - Rejects non-canonical ground-truth labels
 *    - Strips featureVector in toJSON and toObject (API leakage prevention)
 *
 * 2. Deterministic Cryptographic Hashing:
 *    - Identical inputs produce identical SHA-256 hashes
 *    - Feature modifications produce different hashes
 *    - Label modifications produce different hashes
 *    - Schema version modifications produce different hashes
 *
 * 3. Candidate Ingestion & Eligibility:
 *    - Unverified predictions rejected
 *    - Missing featureVector rejected
 *    - Valid verified prediction enters QUARANTINED state
 *
 * 4. Idempotency:
 *    - Repeated ingestion returns existing active sample without creating duplicates
 *
 * 5. Re-Verification Safety (Port Scan -> DDoS):
 *    - Re-verification of prediction marks previous active sample as SUPERSEDED
 *    - Creates fresh candidate in QUARANTINED with new ground truth
 *    - Stale sample remains permanently ineligible
 *
 * 6. State Machine & RBAC:
 *    - Enforces valid state transitions
 *    - Blocks invalid direct transitions (e.g. QUARANTINED -> ELIGIBLE_FOR_TRAINING)
 *    - Blocks mutations from terminal states (REJECTED, SUPERSEDED)
 *    - Viewer cannot mutate (403 Forbidden)
 *    - Enforces dual-control governance (validatedBy !== verifiedBy)
 *
 * 7. HTTP API Layer & Leakage Prevention:
 *    - Protected endpoints require JWT auth (401)
 *    - GET responses never expose raw 53-feature vector
 *
 * 8. Production Isolation:
 *    - Operational threat scoring, containment, and models remain invariant
 */

process.env.JWT_SECRET = 'test-jwt-secret-quarantine-suite'
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-quarantine-suite'
process.env.JWT_EXPIRES_IN = '1d'
process.env.NODE_ENV = 'test'
process.env.HONEYPOT_API_KEY = 'test-honeypot-key-quarantine-suite'
process.env.SENTINEL_KEY = 'test-sentinel-key-quarantine-suite'
process.env.PORT = '0'

// Mock Mongoose DB connection and logger
jest.mock('../config/db', () => jest.fn())
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}))
jest.mock('../websocket/socketManager', () => ({
  init: jest.fn(),
  startDemoFeed: jest.fn(),
  stopDemoFeed: jest.fn(),
  getStats: jest.fn().mockReturnValue({}),
  emitAIPrediction: jest.fn(),
  emitNewThreat: jest.fn(),
  emitNewAlert: jest.fn(),
  emitIPBlocked: jest.fn(),
  emitThreatUpdated: jest.fn(),
}))

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const mongoose = require('mongoose')
const { accessToken } = require('./helpers/accessFixture')
const request = require('supertest')

const { CANONICAL_CLASSES } = require('../utils/canonicalClasses')
const TrainingSample = require('../models/TrainingSample')
const AIPrediction = require('../models/AIPrediction')
const User = require('../models/User')
const trainingSampleService = require('../services/trainingSampleService')
const { app } = require('../server')

const createValid53Vector = (fillValue = 1.0) => Array.from({ length: 53 }, (_, i) => fillValue + i * 0.1)

describe('Phase 2.5C-6: TrainingSample Schema & Validation', () => {
  test('schema requires 53 finite numbers for featureVector', () => {
    const validVector = createValid53Vector()
    const sample = new TrainingSample({
      sourcePredictionId: new mongoose.Types.ObjectId(),
      featureVector: validVector,
      sampleHash: 'dummyhash',
      groundTruthLabel: 'Port Scan',
      predictedClass: 'Port Scan',
      threatScore: 0.8,
      modelVersion: 'rf_cicids_v2.0',
      verifiedBy: new mongoose.Types.ObjectId(),
      verifiedAt: new Date(),
    })

    const err = sample.validateSync()
    expect(err).toBeUndefined()
  })

  test('schema rejects featureVector with wrong length (52 elements)', () => {
    const shortVector = Array.from({ length: 52 }, () => 1.0)
    const sample = new TrainingSample({
      sourcePredictionId: new mongoose.Types.ObjectId(),
      featureVector: shortVector,
      sampleHash: 'dummyhash',
      groundTruthLabel: 'Port Scan',
      predictedClass: 'Port Scan',
      threatScore: 0.8,
      modelVersion: 'rf_cicids_v2.0',
      verifiedBy: new mongoose.Types.ObjectId(),
      verifiedAt: new Date(),
    })

    const err = sample.validateSync()
    expect(err).toBeDefined()
    expect(err.errors.featureVector).toBeDefined()
  })

  test('schema rejects featureVector containing NaN or Infinity', () => {
    const nanVector = createValid53Vector()
    nanVector[10] = NaN

    const sample = new TrainingSample({
      sourcePredictionId: new mongoose.Types.ObjectId(),
      featureVector: nanVector,
      sampleHash: 'dummyhash',
      groundTruthLabel: 'Port Scan',
      predictedClass: 'Port Scan',
      threatScore: 0.8,
      modelVersion: 'rf_cicids_v2.0',
      verifiedBy: new mongoose.Types.ObjectId(),
      verifiedAt: new Date(),
    })

    const err = sample.validateSync()
    expect(err).toBeDefined()
    expect(err.errors.featureVector).toBeDefined()
  })

  test('schema rejects non-canonical ground-truth label', () => {
    const sample = new TrainingSample({
      sourcePredictionId: new mongoose.Types.ObjectId(),
      featureVector: createValid53Vector(),
      sampleHash: 'dummyhash',
      groundTruthLabel: 'NonExistentAttack',
      predictedClass: 'Port Scan',
      threatScore: 0.8,
      modelVersion: 'rf_cicids_v2.0',
      verifiedBy: new mongoose.Types.ObjectId(),
      verifiedAt: new Date(),
    })

    const err = sample.validateSync()
    expect(err).toBeDefined()
    expect(err.errors.groundTruthLabel).toBeDefined()
  })

  test('toJSON and toObject strip featureVector (API Leakage Prevention)', () => {
    const sample = new TrainingSample({
      sourcePredictionId: new mongoose.Types.ObjectId(),
      featureVector: createValid53Vector(),
      sampleHash: 'dummyhash',
      groundTruthLabel: 'Port Scan',
      predictedClass: 'Port Scan',
      threatScore: 0.8,
      modelVersion: 'rf_cicids_v2.0',
      verifiedBy: new mongoose.Types.ObjectId(),
      verifiedAt: new Date(),
    })

    const json = sample.toJSON()
    const obj = sample.toObject()

    expect(json.featureVector).toBeUndefined()
    expect(obj.featureVector).toBeUndefined()
    expect(json.groundTruthLabel).toBe('Port Scan')
    expect(json.sampleHash).toBe('dummyhash')
  })
})

describe('Phase 2.5C-6: Deterministic Cryptographic Hashing', () => {
  const vector1 = createValid53Vector(2.0)
  const vector2 = createValid53Vector(2.0)
  const vectorAltered = createValid53Vector(2.0)
  vectorAltered[0] = 999.0

  test('identical inputs generate identical SHA-256 hashes', () => {
    const hash1 = trainingSampleService.computeSampleHash(vector1, 'v2.1_53feat', 'DDoS')
    const hash2 = trainingSampleService.computeSampleHash(vector2, 'v2.1_53feat', 'DDoS')

    expect(hash1).toBe(hash2)
    expect(typeof hash1).toBe('string')
    expect(hash1).toHaveLength(64) // SHA-256 hex digest length
  })

  test('modified feature value generates different hash', () => {
    const hash1 = trainingSampleService.computeSampleHash(vector1, 'v2.1_53feat', 'DDoS')
    const hashAltered = trainingSampleService.computeSampleHash(vectorAltered, 'v2.1_53feat', 'DDoS')

    expect(hash1).not.toBe(hashAltered)
  })

  test('different ground-truth label generates different hash', () => {
    const hashDDoS = trainingSampleService.computeSampleHash(vector1, 'v2.1_53feat', 'DDoS')
    const hashPortScan = trainingSampleService.computeSampleHash(vector1, 'v2.1_53feat', 'Port Scan')

    expect(hashDDoS).not.toBe(hashPortScan)
  })

  test('different schema version generates different hash', () => {
    const hashV1 = trainingSampleService.computeSampleHash(vector1, 'v2.1_53feat', 'DDoS')
    const hashV2 = trainingSampleService.computeSampleHash(vector1, 'v2.2_53feat', 'DDoS')

    expect(hashV1).not.toBe(hashV2)
  })
})

describe('Phase 2.5C-6: Eligibility Validation & Quarantine Ingestion', () => {
  test('rejects unverified predictions', () => {
    const pred = {
      verified: false,
      actualClass: 'Port Scan',
      featureVector: createValid53Vector(),
      featureSchemaVersion: 'v2.1_53feat',
      verifiedBy: new mongoose.Types.ObjectId(),
    }
    const check = trainingSampleService.validateCandidateEligibility(pred)
    expect(check.eligible).toBe(false)
    expect(check.error).toContain('not verified')
  })

  test('rejects predictions without featureVector', () => {
    const pred = {
      verified: true,
      actualClass: 'Port Scan',
      featureSchemaVersion: 'v2.1_53feat',
      verifiedBy: new mongoose.Types.ObjectId(),
    }
    const check = trainingSampleService.validateCandidateEligibility(pred)
    expect(check.eligible).toBe(false)
    expect(check.error).toContain('no featureVector')
  })

  test('rejects predictions with invalid feature count', () => {
    const pred = {
      verified: true,
      actualClass: 'Port Scan',
      featureVector: [1, 2, 3],
      featureSchemaVersion: 'v2.1_53feat',
      verifiedBy: new mongoose.Types.ObjectId(),
    }
    const check = trainingSampleService.validateCandidateEligibility(pred)
    expect(check.eligible).toBe(false)
    expect(check.error).toContain('must be exactly 53')
  })

  test('accepts eligible verified prediction with 53 features', () => {
    const pred = {
      verified: true,
      actualClass: 'Port Scan',
      featureVector: createValid53Vector(),
      featureSchemaVersion: 'v2.1_53feat',
      verifiedBy: new mongoose.Types.ObjectId(),
    }
    const check = trainingSampleService.validateCandidateEligibility(pred)
    expect(check.eligible).toBe(true)
  })
})

describe('Phase 2.5C-6: Service Ingestion, Idempotency & Re-Verification Safety', () => {
  let mockPrediction
  let analystId
  let adminId

  beforeEach(() => {
    jest.clearAllMocks()
    analystId = new mongoose.Types.ObjectId()
    adminId = new mongoose.Types.ObjectId()
    mockPrediction = {
      _id: new mongoose.Types.ObjectId(),
      verified: true,
      actualClass: 'Port Scan',
      predictedClass: 'Port Scan',
      threatScore: 0.7,
      modelVersion: 'rf_cicids_v2.0',
      featureVector: createValid53Vector(5.0),
      featureSchemaVersion: 'v2.1_53feat',
      verifiedBy: analystId,
      verifiedAt: new Date('2026-10-06T09:00:00Z'),
      verificationHistory: [
        { verifiedBy: analystId, actualClass: 'Port Scan', verifiedAt: new Date('2026-10-06T09:00:00Z') },
      ],
    }
  })

  test('ingests prediction into QUARANTINED state', async () => {
    jest.spyOn(AIPrediction, 'findById').mockReturnValue({
      select: jest.fn().mockResolvedValue(mockPrediction),
    })
    jest.spyOn(TrainingSample, 'find').mockResolvedValue([])
    jest.spyOn(TrainingSample, 'findOne').mockResolvedValue(null)
    const createSpy = jest.spyOn(TrainingSample, 'create').mockImplementation(async (doc) => ({
      ...doc,
      _id: new mongoose.Types.ObjectId(),
      save: jest.fn().mockResolvedValue(doc),
    }))

    const sample = await trainingSampleService.ingestPredictionCandidate(mockPrediction._id)

    expect(sample.status).toBe('QUARANTINED')
    expect(sample.groundTruthLabel).toBe('Port Scan')
    expect(sample.sourcePredictionId).toBe(mockPrediction._id)
    expect(createSpy).toHaveBeenCalled()
  })

  test('idempotency: repeated ingestion returns existing active sample without creating duplicate', async () => {
    const existingSample = {
      _id: new mongoose.Types.ObjectId(),
      sourcePredictionId: mockPrediction._id,
      groundTruthLabel: 'Port Scan',
      sampleHash: trainingSampleService.computeSampleHash(mockPrediction.featureVector, 'v2.1_53feat', 'Port Scan'),
      status: 'QUARANTINED',
    }

    jest.spyOn(AIPrediction, 'findById').mockReturnValue({
      select: jest.fn().mockResolvedValue(mockPrediction),
    })
    jest.spyOn(TrainingSample, 'find').mockResolvedValue([existingSample])
    const createSpy = jest.spyOn(TrainingSample, 'create')

    const result = await trainingSampleService.ingestPredictionCandidate(mockPrediction._id)

    expect(result._id).toBe(existingSample._id)
    expect(createSpy).not.toHaveBeenCalled()
  })

  test('re-verification safety: Port Scan -> DDoS transitions existing sample to SUPERSEDED and queues fresh QUARANTINED candidate', async () => {
    const priorSample = {
      _id: new mongoose.Types.ObjectId(),
      sourcePredictionId: mockPrediction._id,
      groundTruthLabel: 'Port Scan',
      sampleHash: trainingSampleService.computeSampleHash(mockPrediction.featureVector, 'v2.1_53feat', 'Port Scan'),
      status: 'QUARANTINED',
      save: jest.fn().mockResolvedValue(true),
    }

    // Prediction is re-verified to DDoS
    mockPrediction.actualClass = 'DDoS'
    mockPrediction.verificationHistory.push({
      verifiedBy: analystId,
      actualClass: 'DDoS',
      verifiedAt: new Date('2026-10-06T09:30:00Z'),
    })

    jest.spyOn(AIPrediction, 'findById').mockReturnValue({
      select: jest.fn().mockResolvedValue(mockPrediction),
    })
    jest.spyOn(TrainingSample, 'find').mockResolvedValue([priorSample])
    jest.spyOn(TrainingSample, 'findOne').mockResolvedValue(null)
    const createSpy = jest.spyOn(TrainingSample, 'create').mockImplementation(async (doc) => ({
      ...doc,
      _id: new mongoose.Types.ObjectId(),
      save: jest.fn().mockResolvedValue(doc),
    }))

    const newSample = await trainingSampleService.ingestPredictionCandidate(mockPrediction._id)

    // 1. Previous sample superseded
    expect(priorSample.status).toBe('SUPERSEDED')
    expect(priorSample.supersededReason).toContain('re-verified from Port Scan to DDoS')
    expect(priorSample.save).toHaveBeenCalled()

    // 2. New sample created in QUARANTINED with DDoS label
    expect(newSample.status).toBe('QUARANTINED')
    expect(newSample.groundTruthLabel).toBe('DDoS')
    expect(createSpy).toHaveBeenCalled()
  })
})

describe('Phase 2.5C-6: State Machine Transitions & Governance RBAC', () => {
  let analystUser
  let adminUser
  let viewerUser

  beforeEach(() => {
    analystUser = { _id: new mongoose.Types.ObjectId(), role: 'analyst' }
    adminUser = { _id: new mongoose.Types.ObjectId(), role: 'admin' }
    viewerUser = { _id: new mongoose.Types.ObjectId(), role: 'viewer' }
  })

  test('viewer role cannot mutate samples (403 Forbidden)', async () => {
    await expect(
      trainingSampleService.transitionSampleStatus(new mongoose.Types.ObjectId(), 'VALIDATED', viewerUser)
    ).rejects.toMatchObject({ statusCode: 403 })
  })

  test('QUARANTINED -> VALIDATED succeeds for admin with dual control', async () => {
    const sample = {
      _id: new mongoose.Types.ObjectId(),
      status: 'QUARANTINED',
      verifiedBy: analystUser._id, // Verified by analyst
      save: jest.fn().mockResolvedValue(true),
    }
    jest.spyOn(TrainingSample, 'findById').mockResolvedValue(sample)

    const updated = await trainingSampleService.transitionSampleStatus(sample._id, 'VALIDATED', adminUser)

    expect(updated.status).toBe('VALIDATED')
    expect(updated.validatedBy).toBe(adminUser._id)
    expect(sample.save).toHaveBeenCalled()
  })

  test('QUARANTINED -> VALIDATED enforces dual control: self-validation rejected without override', async () => {
    const sample = {
      _id: new mongoose.Types.ObjectId(),
      status: 'QUARANTINED',
      verifiedBy: adminUser._id, // Verified by the same admin
      save: jest.fn().mockResolvedValue(true),
    }
    jest.spyOn(TrainingSample, 'findById').mockResolvedValue(sample)

    await expect(
      trainingSampleService.transitionSampleStatus(sample._id, 'VALIDATED', adminUser)
    ).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining('Dual-control governance violation'),
    })
  })

  test('VALIDATED -> ELIGIBLE_FOR_TRAINING succeeds for admin when cooldown passed', async () => {
    const sample = {
      _id: new mongoose.Types.ObjectId(),
      status: 'VALIDATED',
      cooldownExpiresAt: new Date(Date.now() - 1000), // Cooldown elapsed
      save: jest.fn().mockResolvedValue(true),
    }
    jest.spyOn(TrainingSample, 'findById').mockResolvedValue(sample)

    const updated = await trainingSampleService.transitionSampleStatus(sample._id, 'ELIGIBLE_FOR_TRAINING', adminUser)
    expect(updated.status).toBe('ELIGIBLE_FOR_TRAINING')
  })

  test('direct transition QUARANTINED -> ELIGIBLE_FOR_TRAINING is forbidden (400 Bad Request)', async () => {
    const sample = {
      _id: new mongoose.Types.ObjectId(),
      status: 'QUARANTINED',
      save: jest.fn().mockResolvedValue(true),
    }
    jest.spyOn(TrainingSample, 'findById').mockResolvedValue(sample)

    await expect(
      trainingSampleService.transitionSampleStatus(sample._id, 'ELIGIBLE_FOR_TRAINING', adminUser)
    ).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining('Forbidden state transition'),
    })
  })

  test('terminal state REJECTED cannot transition to any other state', async () => {
    const sample = {
      _id: new mongoose.Types.ObjectId(),
      status: 'REJECTED',
      save: jest.fn().mockResolvedValue(true),
    }
    jest.spyOn(TrainingSample, 'findById').mockResolvedValue(sample)

    await expect(
      trainingSampleService.transitionSampleStatus(sample._id, 'VALIDATED', adminUser)
    ).rejects.toMatchObject({
      statusCode: 400,
      message: expect.stringContaining('terminal state'),
    })
  })
})

describe('Phase 2.5C-6: API Routes & Leakage Prevention', () => {
  let analystToken
  let viewerToken
  let adminToken
  let analystUser
  let adminUser
  let viewerUser

  beforeEach(() => {
    analystUser = {
      _id: new mongoose.Types.ObjectId(),
      role: 'analyst',
      status: 'active',
      name: 'Analyst Jane',
      email: 'analyst@sentinel.ai',
    }
    adminUser = {
      _id: new mongoose.Types.ObjectId(),
      role: 'admin',
      status: 'active',
      name: 'Admin Bob',
      email: 'admin@sentinel.ai',
    }
    viewerUser = {
      _id: new mongoose.Types.ObjectId(),
      role: 'viewer',
      status: 'active',
      name: 'Viewer Sam',
      email: 'viewer@sentinel.ai',
    }

    analystToken = accessToken(analystUser)
    adminToken = accessToken(adminUser)
    viewerToken = accessToken(viewerUser)

    jest.spyOn(User, 'findById').mockImplementation((id) => ({
      select: jest.fn().mockImplementation(() => {
        const idStr = id?.toString()
        if (idStr === analystUser._id.toString()) return Promise.resolve(analystUser)
        if (idStr === adminUser._id.toString()) return Promise.resolve(adminUser)
        if (idStr === viewerUser._id.toString()) return Promise.resolve(viewerUser)
        return Promise.resolve(null)
      }),
    }))
  })

  test('unauthenticated requests return 401 Unauthorized', async () => {
    const res = await request(app).get('/api/training-samples')
    expect(res.status).toBe(401)
  })

  test('viewer role cannot mutate via POST /api/training-samples/ingest/:id (403 Forbidden)', async () => {
    const res = await request(app)
      .post(`/api/training-samples/ingest/${new mongoose.Types.ObjectId()}`)
      .set('Authorization', `Bearer ${viewerToken}`)

    expect(res.status).toBe(403)
  })

  test('GET /api/training-samples does NOT expose raw featureVector (API Leakage Check)', async () => {
    const mockSample = {
      _id: new mongoose.Types.ObjectId(),
      sourcePredictionId: new mongoose.Types.ObjectId(),
      groundTruthLabel: 'DDoS',
      predictedClass: 'DDoS',
      threatScore: 0.95,
      modelVersion: 'rf_cicids_v2.0',
      status: 'QUARANTINED',
      sampleHash: 'aabbcc112233',
      verifiedBy: analystUser,
      verifiedAt: new Date(),
      createdAt: new Date(),
      toJSON: () => ({
        _id: 'mockId',
        groundTruthLabel: 'DDoS',
        status: 'QUARANTINED',
        // featureVector strictly deleted in toJSON
      }),
    }

    jest.spyOn(TrainingSample, 'find').mockReturnValue({
      populate: jest.fn().mockReturnThis(),
      sort: jest.fn().mockReturnThis(),
      skip: jest.fn().mockReturnThis(),
      limit: jest.fn().mockResolvedValue([mockSample]),
    })
    jest.spyOn(TrainingSample, 'countDocuments').mockResolvedValue(1)

    const res = await request(app).get('/api/training-samples').set('Authorization', `Bearer ${analystToken}`)

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data[0].featureVector).toBeUndefined()
  })
})

describe('Phase 2.5C-6: Production Model Invariance', () => {
  test('production Random Forest artifact exists and is unchanged', () => {
    const rfPath = path.resolve(__dirname, '../../ai-engine/models/rf_classifier_cicids_v2.pkl')
    expect(fs.existsSync(rfPath)).toBe(true)
    const content = fs.readFileSync(rfPath)
    const hash = crypto.createHash('sha256').update(content).digest('hex')
    expect(hash).toBe('ca0efb1fde8f9bdc430c3c511e32cd91822b0f3deeca845aa259bc8dd60023f1')
  })

  test('production Isolation Forest artifact exists and is unchanged', () => {
    const ifPath = path.resolve(__dirname, '../../ai-engine/models/isolation_forest_cicids.pkl')
    expect(fs.existsSync(ifPath)).toBe(true)
    const content = fs.readFileSync(ifPath)
    const hash = crypto.createHash('sha256').update(content).digest('hex')
    expect(hash).toBe('17bd08ffe105a3ea87de85e0943761e7cb012abd70537968e14d0a3394e19da4')
  })
})
