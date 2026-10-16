'use strict'

const crypto = require('crypto')
const mongoose = require('mongoose')
const TrainingSample = require('../models/TrainingSample')
const AIPrediction = require('../models/AIPrediction')
const { CANONICAL_CLASSES, isValidCanonicalClass } = require('../utils/canonicalClasses')
const logger = require('../utils/logger')

const SUPPORTED_SCHEMA_VERSION = 'v2.1_53feat'
const REQUIRED_FEATURE_COUNT = 53

/**
 * Computes a deterministic SHA-256 hash of a sample's features and label.
 * Format: `${schemaVersion}|${groundTruthLabel}|${canonicalFeatureString}`
 * Numeric precision: 6 decimal places per float (IEEE-754 normalized).
 */
const computeSampleHash = (vector, schemaVersion, label) => {
  if (!Array.isArray(vector) || vector.length !== REQUIRED_FEATURE_COUNT) {
    throw new Error(`Vector must be an array of exactly ${REQUIRED_FEATURE_COUNT} elements`)
  }
  if (!vector.every((n) => typeof n === 'number' && Number.isFinite(n))) {
    throw new Error('All feature vector values must be finite numbers')
  }
  const cleanVersion = typeof schemaVersion === 'string' ? schemaVersion.trim() : ''
  const cleanLabel = typeof label === 'string' ? label.trim() : ''
  const normFeatures = vector.map((n) => Number(n).toFixed(6)).join(',')
  const payload = `${cleanVersion}|${cleanLabel}|${normFeatures}`
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex')
}

/**
 * Validates feature vector structure and values.
 */
const validateFeatureVector = (vector, schemaVersion) => {
  if (!Array.isArray(vector)) {
    return { valid: false, error: 'featureVector must be an array' }
  }
  if (vector.length !== REQUIRED_FEATURE_COUNT) {
    return {
      valid: false,
      error: `featureVector length must be exactly ${REQUIRED_FEATURE_COUNT}, received ${vector.length}`,
    }
  }
  if (!vector.every((n) => typeof n === 'number' && Number.isFinite(n))) {
    return { valid: false, error: 'featureVector contains NaN, Infinity, or non-numeric values' }
  }
  if (schemaVersion !== SUPPORTED_SCHEMA_VERSION) {
    return {
      valid: false,
      error: `Unsupported featureSchemaVersion: ${schemaVersion}. Expected ${SUPPORTED_SCHEMA_VERSION}`,
    }
  }
  return { valid: true }
}

/**
 * Checks whether an AIPrediction document meets all eligibility criteria for TrainingSample creation.
 */
const validateCandidateEligibility = (prediction) => {
  if (!prediction) {
    return { eligible: false, error: 'Prediction document not found' }
  }
  if (prediction.verified !== true) {
    return { eligible: false, error: 'Prediction is not verified (verified !== true)' }
  }
  if (!prediction.actualClass || !isValidCanonicalClass(prediction.actualClass)) {
    return {
      eligible: false,
      error: `Prediction actualClass is not a valid canonical class: ${prediction.actualClass}`,
    }
  }
  if (!prediction.featureVector) {
    return { eligible: false, error: 'Prediction has no featureVector captured' }
  }
  const vectorCheck = validateFeatureVector(prediction.featureVector, prediction.featureSchemaVersion)
  if (!vectorCheck.valid) {
    return { eligible: false, error: vectorCheck.error }
  }
  if (!prediction.verifiedBy) {
    return { eligible: false, error: 'Prediction missing verifiedBy attribution' }
  }
  return { eligible: true }
}

/**
 * Ingests an eligible verified AIPrediction into the TrainingSample collection.
 * Enforces:
 * 1. Eligibility validation (fails fast if unverified or features invalid)
 * 2. Idempotency (repeated calls with identical ground truth return existing sample)
 * 3. Re-verification safety (prior active samples for this prediction are marked SUPERSEDED)
 * 4. Initial state is always QUARANTINED (never directly VALIDATED or ELIGIBLE)
 */
const ingestPredictionCandidate = async (predictionId, options = {}) => {
  const prediction = await AIPrediction.findById(predictionId).select('+featureVector +featureSchemaVersion')
  if (!prediction) {
    const err = new Error('Prediction not found')
    err.statusCode = 404
    throw err
  }

  const eligibility = validateCandidateEligibility(prediction)
  if (!eligibility.eligible) {
    const err = new Error(`Ineligible prediction: ${eligibility.error}`)
    err.statusCode = 400
    throw err
  }

  const sampleHash = computeSampleHash(
    prediction.featureVector,
    prediction.featureSchemaVersion,
    prediction.actualClass
  )

  // Check for any currently active samples originating from this prediction
  const activeSamples = await TrainingSample.find({
    sourcePredictionId: prediction._id,
    status: { $in: ['QUARANTINED', 'VALIDATED', 'ELIGIBLE_FOR_TRAINING'] },
  })

  for (const existing of activeSamples) {
    if (existing.groundTruthLabel === prediction.actualClass && existing.sampleHash === sampleHash) {
      // Idempotent hit: exact same prediction, vector, and label already active
      logger.info(
        `[TrainingSample] Idempotent ingestion request for prediction ${prediction._id}. Returning sample ${existing._id}`
      )
      return existing
    }

    // Re-verification scenario: prediction was re-verified to a different canonical class!
    // Supersede the existing active sample to prevent stale ground-truth leakage
    existing.status = 'SUPERSEDED'
    existing.supersededAt = new Date()
    existing.supersededReason = `Prediction re-verified from ${existing.groundTruthLabel} to ${prediction.actualClass}`
    await existing.save()
    logger.info(
      `[TrainingSample] Superseded sample ${existing._id} for prediction ${prediction._id} due to re-verification`
    )
  }

  // Check duplicate frequency across other samples with identical feature vector & label
  const identicalDuplicate = await TrainingSample.findOne({
    sampleHash,
    status: { $in: ['QUARANTINED', 'VALIDATED', 'ELIGIBLE_FOR_TRAINING'] },
  })
  if (identicalDuplicate) {
    identicalDuplicate.duplicateCount = (identicalDuplicate.duplicateCount || 1) + 1
    await identicalDuplicate.save()
  }

  const cooldownMs = typeof options.cooldownMs === 'number' ? options.cooldownMs : 0
  const quarantinedAt = new Date()
  const cooldownExpiresAt = new Date(quarantinedAt.getTime() + cooldownMs)
  const sourceVerificationIndex = Math.max(0, (prediction.verificationHistory?.length || 1) - 1)

  const newSample = await TrainingSample.create({
    sourcePredictionId: prediction._id,
    sourceVerificationIndex,
    featureVector: prediction.featureVector,
    featureSchemaVersion: prediction.featureSchemaVersion,
    sampleHash,
    groundTruthLabel: prediction.actualClass,
    predictedClass: prediction.predictedClass,
    threatScore: prediction.threatScore,
    modelVersion: prediction.modelVersion,
    inputSource: prediction.inputSource || 'network_traffic',
    sourceIP: prediction.sourceIP || null,
    targetIP: prediction.targetIP || null,
    status: 'QUARANTINED',
    quarantinedAt,
    cooldownExpiresAt,
    verifiedBy: prediction.verifiedBy,
    verifiedAt: prediction.verifiedAt || new Date(),
    duplicateCount: 1,
  })

  logger.info(
    `[TrainingSample] Ingested candidate ${newSample._id} in QUARANTINED state for prediction ${prediction._id}`
  )
  return newSample
}

/**
 * Transitions a TrainingSample between state machine lifecycle stages.
 * Enforces:
 * - RBAC: Admin vs Analyst vs Viewer permissions
 * - Dual-control governance: validatedBy !== verifiedBy
 * - Cooldown enforcement before ELIGIBLE_FOR_TRAINING
 * - Terminal state immutability (REJECTED and SUPERSEDED are terminal)
 */
const transitionSampleStatus = async (sampleId, targetStatus, user, metadata = {}) => {
  if (!user) {
    const err = new Error('Authentication required')
    err.statusCode = 401
    throw err
  }
  if (user.role === 'viewer') {
    const err = new Error('Access denied: viewers cannot mutate training samples')
    err.statusCode = 403
    throw err
  }

  const sample = await TrainingSample.findById(sampleId)
  if (!sample) {
    const err = new Error('Training sample not found')
    err.statusCode = 404
    throw err
  }

  const current = sample.status

  // Terminal state protection
  if (current === 'REJECTED' || current === 'SUPERSEDED') {
    const err = new Error(`Cannot transition sample from terminal state '${current}'`)
    err.statusCode = 400
    throw err
  }

  if (current === targetStatus) {
    return sample // Idempotent no-op
  }

  // 1. Transition: QUARANTINED -> VALIDATED
  if (current === 'QUARANTINED' && targetStatus === 'VALIDATED') {
    if (user.role !== 'admin') {
      const err = new Error('Access denied: only administrators can validate quarantined samples')
      err.statusCode = 403
      throw err
    }

    // Dual-control check
    const isSelfValidation = sample.verifiedBy && sample.verifiedBy.toString() === user._id.toString()
    if (isSelfValidation && !metadata.bypassDualControl) {
      const err = new Error(
        'Dual-control governance violation: validator cannot be the same user who submitted verification'
      )
      err.statusCode = 400
      throw err
    }

    sample.status = 'VALIDATED'
    sample.validatedBy = user._id
    sample.validatedAt = new Date()
    await sample.save()
    logger.info(`[TrainingSample] Sample ${sample._id} validated by admin ${user._id}`)
    return sample
  }

  // 2. Transition: QUARANTINED or VALIDATED -> REJECTED
  if ((current === 'QUARANTINED' || current === 'VALIDATED') && targetStatus === 'REJECTED') {
    if (current === 'VALIDATED' && user.role !== 'admin') {
      const err = new Error('Access denied: only administrators can reject an already validated sample')
      err.statusCode = 403
      throw err
    }
    const reason = typeof metadata.reason === 'string' ? metadata.reason.trim() : ''
    if (!reason) {
      const err = new Error('Rejection reason is required')
      err.statusCode = 400
      throw err
    }

    sample.status = 'REJECTED'
    sample.rejectionReason = reason
    await sample.save()
    logger.info(`[TrainingSample] Sample ${sample._id} rejected: ${reason}`)
    return sample
  }

  // 3. Transition: VALIDATED -> ELIGIBLE_FOR_TRAINING
  if (current === 'VALIDATED' && targetStatus === 'ELIGIBLE_FOR_TRAINING') {
    if (user.role !== 'admin') {
      const err = new Error('Access denied: only administrators can promote samples to ELIGIBLE_FOR_TRAINING')
      err.statusCode = 403
      throw err
    }

    if (sample.cooldownExpiresAt && Date.now() < new Date(sample.cooldownExpiresAt).getTime()) {
      const remainingSec = Math.ceil((new Date(sample.cooldownExpiresAt).getTime() - Date.now()) / 1000)
      const err = new Error(`Quarantine cooldown active. Sample eligible in ${remainingSec} seconds`)
      err.statusCode = 400
      throw err
    }

    sample.status = 'ELIGIBLE_FOR_TRAINING'
    await sample.save()
    logger.info(`[TrainingSample] Sample ${sample._id} promoted to ELIGIBLE_FOR_TRAINING`)
    return sample
  }

  // 4. Transition: ANY ACTIVE -> SUPERSEDED
  if (['QUARANTINED', 'VALIDATED', 'ELIGIBLE_FOR_TRAINING'].includes(current) && targetStatus === 'SUPERSEDED') {
    if (user.role !== 'admin') {
      const err = new Error('Access denied: only administrators can supersede active samples manually')
      err.statusCode = 403
      throw err
    }

    sample.status = 'SUPERSEDED'
    sample.supersededAt = new Date()
    sample.supersededReason = metadata.reason || 'Manually superseded by administrator'
    await sample.save()
    logger.info(`[TrainingSample] Sample ${sample._id} superseded`)
    return sample
  }

  // All other transitions are forbidden by state machine
  const err = new Error(`Forbidden state transition from '${current}' to '${targetStatus}'`)
  err.statusCode = 400
  throw err
}

/**
 * Out-of-band synchronization hook triggered after an AIPrediction verification is saved.
 * Executes cleanly in background without throwing or blocking live operations.
 */
const syncPredictionToQuarantine = async (predictionId) => {
  try {
    const prediction = await AIPrediction.findById(predictionId).select('+featureVector +featureSchemaVersion')
    if (!prediction) return null

    // If prediction is not verified or lacks 53-features, quietly skip
    if (
      !prediction.verified ||
      !prediction.featureVector ||
      prediction.featureVector.length !== REQUIRED_FEATURE_COUNT
    ) {
      return null
    }

    return await ingestPredictionCandidate(predictionId)
  } catch (e) {
    logger.debug(`[TrainingSample] Out-of-band sync for prediction ${predictionId} skipped/failed: ${e.message}`)
    return null
  }
}

/**
 * Returns paginated list of TrainingSamples with safe metadata (featureVector stripped).
 */
const listSamples = async (query = {}) => {
  const page = Math.max(1, parseInt(query.page, 10) || 1)
  const limit = Math.min(100, Math.max(1, parseInt(query.limit, 10) || 20))
  const skip = (page - 1) * limit

  const filter = {}
  if (query.status) filter.status = query.status
  if (query.groundTruthLabel) filter.groundTruthLabel = query.groundTruthLabel
  if (query.sourcePredictionId) filter.sourcePredictionId = query.sourcePredictionId

  const [data, total] = await Promise.all([
    TrainingSample.find(filter)
      .populate('verifiedBy', 'name email role')
      .populate('validatedBy', 'name email role')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit),
    TrainingSample.countDocuments(filter),
  ])

  return { data, total, page, limit }
}

/**
 * Retrieves a single TrainingSample by ID with safe metadata.
 */
const getSampleById = async (id) => {
  return TrainingSample.findById(id)
    .populate('verifiedBy', 'name email role')
    .populate('validatedBy', 'name email role')
}

module.exports = {
  SUPPORTED_SCHEMA_VERSION,
  REQUIRED_FEATURE_COUNT,
  computeSampleHash,
  validateFeatureVector,
  validateCandidateEligibility,
  ingestPredictionCandidate,
  transitionSampleStatus,
  syncPredictionToQuarantine,
  listSamples,
  getSampleById,
}
