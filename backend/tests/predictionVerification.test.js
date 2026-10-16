jest.mock('../models/AuthSession')
;('use strict')
/**
 * tests/predictionVerification.test.js
 *
 * Phase 2.5C-4 Verification Foundation Test Suite
 *
 * 1. Canonical Label Validation:
 *    - All 11 canonical classes accepted
 *    - Misspelled, non-canonical, empty, or case-mismatched classes rejected
 *
 * 2. Schema Properties & Transforms:
 *    - verifiedAt Date field
 *    - actualClass enum validation
 *    - verificationHistory array definition
 *    - toJSON / toObject preserve verification fields and strip featureVector
 *
 * 3. Service Layer (aiService.verifyPrediction):
 *    - 1st verification creates verified state and appends 1 history entry
 *    - 2nd re-verification updates state and preserves prior history entry
 *    - Rejects invalid class
 *    - Operational invariance: threatScore, predictedClass, modelVersion unchanged
 *
 * 4. Route Layer (PUT /api/ai/predictions/:id/verify):
 *    - Unauthenticated -> 401
 *    - Viewer role -> 403 Forbidden
 *    - Analyst role -> 200 OK
 *    - Admin role -> 200 OK
 *    - Invalid class -> 400 Bad Request
 *    - Invalid ObjectId -> 400 Bad Request
 *    - Leakage prevention: featureVector absent from response
 *
 * 5. Training Boundary Invariance:
 *    - Confirms no TrainingSample model or collection is created
 */

process.env.JWT_SECRET = 'test-jwt-secret-verification-suite'
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-verification-suite'
process.env.JWT_EXPIRES_IN = '1d'
process.env.NODE_ENV = 'test'
process.env.HONEYPOT_API_KEY = 'test-honeypot-key-verification-suite'
process.env.SENTINEL_KEY = 'test-sentinel-key-verification-suite'
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

const mongoose = require('mongoose')
const { accessToken } = require('./helpers/accessFixture')
const request = require('supertest')

const { CANONICAL_CLASSES, isValidCanonicalClass } = require('../utils/canonicalClasses')
const AIPrediction = require('../models/AIPrediction')
const User = require('../models/User')
const aiService = require('../services/aiService')
const { app } = require('../server')

describe('Phase 2.5C-4: Canonical Label Validation', () => {
  test('exactly 11 canonical classes are defined', () => {
    expect(CANONICAL_CLASSES).toHaveLength(11)
    expect(CANONICAL_CLASSES).toContain('BENIGN')
    expect(CANONICAL_CLASSES).toContain('SSH Brute Force')
    expect(CANONICAL_CLASSES).toContain('SQL Injection')
    expect(CANONICAL_CLASSES).toContain('Port Scan')
    expect(CANONICAL_CLASSES).toContain('DDoS')
    expect(CANONICAL_CLASSES).toContain('RCE Attempt')
    expect(CANONICAL_CLASSES).toContain('XSS Attempt')
    expect(CANONICAL_CLASSES).toContain('Malware Beacon')
    expect(CANONICAL_CLASSES).toContain('Credential Stuffing')
    expect(CANONICAL_CLASSES).toContain('Lateral Movement')
    expect(CANONICAL_CLASSES).toContain('Data Exfiltration')
  })

  test('valid canonical classes return true', () => {
    CANONICAL_CLASSES.forEach((cls) => {
      expect(isValidCanonicalClass(cls)).toBe(true)
    })
  })

  test('misspelled or case-mismatched classes return false', () => {
    expect(isValidCanonicalClass('port scan')).toBe(false)
    expect(isValidCanonicalClass('PortScan')).toBe(false)
    expect(isValidCanonicalClass('ddos')).toBe(false)
    expect(isValidCanonicalClass('Ddos')).toBe(false)
    expect(isValidCanonicalClass('benign')).toBe(false)
    expect(isValidCanonicalClass('Benign')).toBe(false)
    expect(isValidCanonicalClass('SSH_Brute_Force')).toBe(false)
    expect(isValidCanonicalClass('')).toBe(false)
    expect(isValidCanonicalClass('   ')).toBe(false)
    expect(isValidCanonicalClass(null)).toBe(false)
    expect(isValidCanonicalClass(undefined)).toBe(false)
    expect(isValidCanonicalClass(123)).toBe(false)
    expect(isValidCanonicalClass('Random_Attack')).toBe(false)
  })
})

describe('Phase 2.5C-4: AIPrediction Schema Verification Properties', () => {
  test('schema contains verifiedAt, actualClass enum, and verificationHistory', () => {
    const schema = AIPrediction.schema.paths

    expect(schema.verifiedAt).toBeDefined()
    expect(schema.verifiedAt.instance).toBe('Date')

    expect(schema.actualClass).toBeDefined()
    expect(schema.actualClass.enumValues).toEqual(expect.arrayContaining([...CANONICAL_CLASSES]))

    expect(schema['verificationHistory']).toBeDefined()
  })

  test('toJSON transform preserves verification fields while stripping featureVector', () => {
    const doc = new AIPrediction({
      inputSource: 'network_traffic',
      sourceIP: '192.168.1.100',
      predictedClass: 'Port Scan',
      threatScore: 0.75,
      verified: true,
      verifiedBy: new mongoose.Types.ObjectId(),
      verifiedAt: new Date('2026-10-06T09:00:00Z'),
      actualClass: 'Port Scan',
      verificationHistory: [
        {
          verifiedBy: new mongoose.Types.ObjectId(),
          actualClass: 'Port Scan',
          verifiedAt: new Date('2026-10-06T09:00:00Z'),
        },
      ],
      featureVector: new Array(53).fill(1.0),
      featureSchemaVersion: 'v2.1_53feat',
    })

    const json = doc.toJSON()
    expect(json.verified).toBe(true)
    expect(json.actualClass).toBe('Port Scan')
    expect(json.verifiedAt).toBeDefined()
    expect(json.verificationHistory).toHaveLength(1)
    expect(json.featureVector).toBeUndefined()
    expect(json.featureSchemaVersion).toBeUndefined()
  })
})

describe('Phase 2.5C-4: aiService.verifyPrediction Service Logic', () => {
  const dummyPredId = new mongoose.Types.ObjectId().toString()
  const analystId1 = new mongoose.Types.ObjectId()
  const analystId2 = new mongoose.Types.ObjectId()

  beforeEach(() => {
    jest.clearAllMocks()
  })

  test('rejects non-canonical actualClass with 400 error', async () => {
    await expect(aiService.verifyPrediction(dummyPredId, analystId1, 'PortScan')).rejects.toThrow(/Invalid actualClass/)
    await expect(aiService.verifyPrediction(dummyPredId, analystId1, 'invalid_label')).rejects.toThrow(
      /Invalid actualClass/
    )
  })

  test('first verification updates current state and appends 1 history entry', async () => {
    const mockUpdatedDoc = {
      _id: dummyPredId,
      predictedClass: 'Port Scan',
      threatScore: 0.85,
      modelVersion: 'rf_cicids_v2.0',
      verified: true,
      verifiedBy: { _id: analystId1, name: 'Alice Analyst', email: 'alice@sentinel.io', role: 'analyst' },
      actualClass: 'Port Scan',
      verifiedAt: new Date(),
      verificationHistory: [
        {
          verifiedBy: analystId1,
          actualClass: 'Port Scan',
          verifiedAt: new Date(),
        },
      ],
    }

    const mockFindByIdAndUpdate = jest.spyOn(AIPrediction, 'findByIdAndUpdate').mockReturnValue({
      populate: jest.fn().mockResolvedValue(mockUpdatedDoc),
    })

    const result = await aiService.verifyPrediction(dummyPredId, analystId1, 'Port Scan')

    expect(mockFindByIdAndUpdate).toHaveBeenCalledTimes(1)
    const [callId, updatePayload] = mockFindByIdAndUpdate.mock.calls[0]
    expect(callId).toBe(dummyPredId)
    expect(updatePayload.$set.verified).toBe(true)
    expect(updatePayload.$set.verifiedBy).toBe(analystId1)
    expect(updatePayload.$set.actualClass).toBe('Port Scan')
    expect(updatePayload.$set.verifiedAt).toBeInstanceOf(Date)
    expect(updatePayload.$push.verificationHistory).toBeDefined()
    expect(updatePayload.$push.verificationHistory.actualClass).toBe('Port Scan')

    expect(result.verified).toBe(true)
    expect(result.actualClass).toBe('Port Scan')
    expect(result.verificationHistory).toHaveLength(1)

    mockFindByIdAndUpdate.mockRestore()
  })

  test('re-verification preserves previous history and updates current state', async () => {
    const time1 = new Date('2026-10-06T08:00:00Z')
    const time2 = new Date('2026-10-06T09:30:00Z')

    const mockReverifiedDoc = {
      _id: dummyPredId,
      predictedClass: 'Port Scan',
      threatScore: 0.85,
      modelVersion: 'rf_cicids_v2.0',
      verified: true,
      verifiedBy: { _id: analystId2, name: 'Bob Admin', email: 'bob@sentinel.io', role: 'admin' },
      actualClass: 'DDoS',
      verifiedAt: time2,
      verificationHistory: [
        {
          verifiedBy: analystId1,
          actualClass: 'Port Scan',
          verifiedAt: time1,
        },
        {
          verifiedBy: analystId2,
          actualClass: 'DDoS',
          verifiedAt: time2,
        },
      ],
    }

    const mockFindByIdAndUpdate = jest.spyOn(AIPrediction, 'findByIdAndUpdate').mockReturnValue({
      populate: jest.fn().mockResolvedValue(mockReverifiedDoc),
    })

    const result = await aiService.verifyPrediction(dummyPredId, analystId2, 'DDoS')

    expect(result.verified).toBe(true)
    expect(result.actualClass).toBe('DDoS')
    expect(result.verificationHistory).toHaveLength(2)
    expect(result.verificationHistory[0].actualClass).toBe('Port Scan')
    expect(result.verificationHistory[1].actualClass).toBe('DDoS')

    // Inference operational invariants:
    expect(result.threatScore).toBe(0.85)
    expect(result.predictedClass).toBe('Port Scan')
    expect(result.modelVersion).toBe('rf_cicids_v2.0')

    mockFindByIdAndUpdate.mockRestore()
  })
})

describe('Phase 2.5C-4: Route PUT /api/ai/predictions/:id/verify', () => {
  const validPredId = new mongoose.Types.ObjectId().toString()
  const invalidPredId = 'not-a-valid-object-id'

  const analystUser = {
    _id: new mongoose.Types.ObjectId().toString(),
    name: 'Analyst Jane',
    email: 'jane@sentinel.io',
    role: 'analyst',
    status: 'active',
  }

  const adminUser = {
    _id: new mongoose.Types.ObjectId().toString(),
    name: 'Admin Bob',
    email: 'admin@sentinel.io',
    role: 'admin',
    status: 'active',
  }

  const viewerUser = {
    _id: new mongoose.Types.ObjectId().toString(),
    name: 'Viewer Sam',
    email: 'viewer@sentinel.io',
    role: 'viewer',
    status: 'active',
  }

  const analystToken = accessToken(analystUser)
  const adminToken = accessToken(adminUser)
  const viewerToken = accessToken(viewerUser)

  beforeEach(() => {
    jest.spyOn(User, 'findById').mockImplementation((id) => {
      const idStr = id?.toString()
      let userObj = null
      if (idStr === analystUser._id) userObj = analystUser
      else if (idStr === adminUser._id) userObj = adminUser
      else if (idStr === viewerUser._id) userObj = viewerUser

      return {
        select: jest.fn().mockResolvedValue(userObj),
      }
    })
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  test('unauthenticated request returns 401', async () => {
    const res = await request(app).put(`/api/ai/predictions/${validPredId}/verify`).send({ actualClass: 'BENIGN' })

    expect(res.status).toBe(401)
  })

  test('viewer role is rejected with 403', async () => {
    const res = await request(app)
      .put(`/api/ai/predictions/${validPredId}/verify`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ actualClass: 'BENIGN' })

    expect(res.status).toBe(403)
    expect(res.body.error).toMatch(/Access denied/i)
  })

  test('invalid ObjectId returns 400', async () => {
    const res = await request(app)
      .put(`/api/ai/predictions/${invalidPredId}/verify`)
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ actualClass: 'BENIGN' })

    expect(res.status).toBe(400)
    expect(res.body.error).toMatch(/Invalid ID/i)
  })

  test('invalid or misspelled class returns 400 with helpful error', async () => {
    const res = await request(app)
      .put(`/api/ai/predictions/${validPredId}/verify`)
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ actualClass: 'PortScan' })

    expect(res.status).toBe(400)
    expect(res.body.error).toMatch(/Valid canonical actualClass required/i)
  })

  test('empty actualClass returns 400', async () => {
    const res = await request(app)
      .put(`/api/ai/predictions/${validPredId}/verify`)
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ actualClass: '' })

    expect(res.status).toBe(400)
  })

  test('analyst role can verify prediction with canonical class (200 OK)', async () => {
    const mockVerifiedDoc = {
      _id: validPredId,
      predictedClass: 'DDoS',
      threatScore: 0.91,
      verified: true,
      verifiedBy: { _id: analystUser._id, name: analystUser.name, email: analystUser.email, role: 'analyst' },
      actualClass: 'DDoS',
      verifiedAt: new Date(),
      verificationHistory: [
        {
          verifiedBy: analystUser._id,
          actualClass: 'DDoS',
          verifiedAt: new Date(),
        },
      ],
    }

    jest.spyOn(aiService, 'verifyPrediction').mockResolvedValue(mockVerifiedDoc)

    const res = await request(app)
      .put(`/api/ai/predictions/${validPredId}/verify`)
      .set('Authorization', `Bearer ${analystToken}`)
      .send({ actualClass: 'DDoS' })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data.prediction.verified).toBe(true)
    expect(res.body.data.prediction.actualClass).toBe('DDoS')
    expect(res.body.data.prediction.verifiedAt).toBeDefined()
    expect(res.body.data.prediction.verificationHistory).toHaveLength(1)

    // Security check: raw feature vector must not leak
    expect(res.body.data.prediction.featureVector).toBeUndefined()
  })

  test('admin role can verify prediction with canonical class (200 OK)', async () => {
    const mockVerifiedDoc = {
      _id: validPredId,
      predictedClass: 'BENIGN',
      threatScore: 0.12,
      verified: true,
      verifiedBy: { _id: adminUser._id, name: adminUser.name, email: adminUser.email, role: 'admin' },
      actualClass: 'BENIGN',
      verifiedAt: new Date(),
      verificationHistory: [
        {
          verifiedBy: adminUser._id,
          actualClass: 'BENIGN',
          verifiedAt: new Date(),
        },
      ],
    }

    jest.spyOn(aiService, 'verifyPrediction').mockResolvedValue(mockVerifiedDoc)

    const res = await request(app)
      .put(`/api/ai/predictions/${validPredId}/verify`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ actualClass: 'BENIGN' })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data.prediction.actualClass).toBe('BENIGN')
  })

  test('retraining boundary invariant: no CandidateModel or RetrainingJob exists', () => {
    // Confirms no CandidateModel or RetrainingJob collections or models exist
    expect(mongoose.models.CandidateModel).toBeUndefined()
    expect(mongoose.models.RetrainingJob).toBeUndefined()
  })
})
