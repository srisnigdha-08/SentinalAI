'use strict'
/**
 * AI Trust Meter read API: stored ML predictions with their deterministic trust assessment. Read-only, bounded,
 * projected; every filter value is type-checked and regex input is escaped.
 */
const mongoose = require('mongoose')
const AIPrediction = require('../models/AIPrediction')
const { escapeRegex, parsePagination } = require('../utils/querySecurity')
const { redactAIPrediction, isPrivilegedRole } = require('../utils/redact')
const { STATES, STATE_ORDER, ML_SCOPE, assessPrediction, stateFilter } = require('../utils/trustAssessment')

// Never returned: raw request record (attacker/replay controlled), vectors, per-feature importance.
const LIST_FIELDS =
  'inputSource sourceIP targetIP predictedClass classProbabilities threatScore modelVersion modelType isAnomaly anomalyScore needsReview incompleteInput defaultedFeatures honeypotCorroborated verified actualClass generatedThreat createdAt'
const SORTS = {
  newest: { createdAt: -1, _id: -1 },
  oldest: { createdAt: 1, _id: 1 },
  score: { threatScore: -1, _id: -1 },
}
const str = (v, max) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null)
const date = (v) => {
  if (typeof v !== 'string' || !v) return null
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? null : d
}

/** Scope + non-state filters, shared by the list and its summary counts. */
function baseFilter({ q, predictedClass, modelVersion, from, to } = {}) {
  const and = [ML_SCOPE]
  const cls = str(predictedClass, 60)
  if (cls) and.push({ predictedClass: cls })
  const ver = str(modelVersion, 80)
  if (ver) and.push({ modelVersion: ver })
  const range = {}
  const f = date(from)
  const t = date(to)
  if (f) range.$gte = f
  if (t) range.$lte = t
  if (Object.keys(range).length) and.push({ createdAt: range })
  const safeQ = escapeRegex(q, 64)
  if (safeQ) {
    and.push({
      $or: [{ sourceIP: { $regex: safeQ, $options: 'i' } }, { predictedClass: { $regex: safeQ, $options: 'i' } }],
    })
  }
  return { $and: and }
}

const shape = (doc, role) => {
  const out = redactAIPrediction(doc, role)
  delete out.rawFeatures
  const threat = doc.generatedThreat
  out.generatedThreat = threat ? String(threat._id || threat) : null
  return { ...out, trust: assessPrediction(doc) }
}

async function listPredictions(query = {}, role = 'viewer') {
  const { page, limit, skip } = parsePagination({
    page: query.page,
    limit: query.limit,
    defaultLimit: 20,
    maxLimit: 50,
  })
  const base = baseFilter(query)
  const state = typeof query.state === 'string' && STATE_ORDER.includes(query.state) ? query.state : null
  const filter = state ? { $and: [base, stateFilter(state)] } : base
  const sort = SORTS[query.sort] || SORTS.newest

  const [total, docs, counts, classes, versions] = await Promise.all([
    AIPrediction.countDocuments(filter),
    AIPrediction.find(filter).select(LIST_FIELDS).sort(sort).skip(skip).limit(limit).lean(),
    Promise.all(STATE_ORDER.map((s) => AIPrediction.countDocuments({ $and: [base, stateFilter(s)] }))),
    AIPrediction.distinct('predictedClass', ML_SCOPE),
    AIPrediction.distinct('modelVersion', ML_SCOPE),
  ])
  const byState = Object.fromEntries(STATE_ORDER.map((s, i) => [s, counts[i]]))
  return {
    data: docs.map((d) => shape(d, role)),
    total,
    page,
    limit,
    summary: {
      // Denominator: ML predictions matching the non-state filters (rule-based honeypot verdicts excluded).
      inScope: counts.reduce((a, b) => a + b, 0),
      byState,
      completenessRecorded: await AIPrediction.countDocuments({
        $and: [base, { defaultedFeatures: { $type: 'array' } }],
      }),
    },
    facets: {
      classes: classes
        .filter((c) => typeof c === 'string')
        .sort()
        .slice(0, 50),
      modelVersions: versions
        .filter((v) => typeof v === 'string' && v)
        .sort()
        .slice(0, 20),
    },
  }
}

async function getPrediction(id, role = 'viewer') {
  if (!mongoose.isValidObjectId(id)) return null
  const doc = await AIPrediction.findOne({ $and: [{ _id: id }, ML_SCOPE] })
    .select(LIST_FIELDS + ' inferenceTimeMs')
    .populate('generatedThreat', 'severity status attackType predictionId')
    .lean()
  if (!doc) return { outOfScope: Boolean(await AIPrediction.exists({ _id: id })) }
  // Only whether a valid vector was stored (it is validated on write); the vector itself is never returned.
  const hasStoredVector = Boolean(await AIPrediction.exists({ _id: id, featureVector: { $type: 'array' } }))
  const threat = doc.generatedThreat && typeof doc.generatedThreat === 'object' ? doc.generatedThreat : null
  const out = shape(doc, role)
  out.threat = threat
    ? { _id: String(threat._id), severity: threat.severity, status: threat.status, attackType: threat.attackType }
    : null
  out.explanation = {
    storedVector: hasStoredVector,
    // SHAP is served per threat (GET /api/threats/:id/explanation, admin/analyst) for threats raised by this prediction.
    available: Boolean(hasStoredVector && threat && isPrivilegedRole(role)),
    requiresRole: !isPrivilegedRole(role),
  }
  return { prediction: out }
}

module.exports = { listPredictions, getPrediction, baseFilter, STATES }
