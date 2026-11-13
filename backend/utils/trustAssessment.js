'use strict'
/**
 * AI Trust Meter: a deterministic, categorical assessment of how far one stored ML prediction can be interpreted.
 *
 * It never produces a "trust %". Classifier probability is reported as the model's output, not as a probability of
 * being correct, and the anomaly signal is reported with the detector's own boundary (isAnomaly), not as a
 * probability. Every reason names the stored field it comes from. Nothing here changes scoring, actions or blocking.
 *
 * States (first match wins, and stateFilter() builds the equivalent MongoDB query for each):
 *   UNAVAILABLE   no model prediction (engine unavailable or result rejected: UNINSPECTED_TRAFFIC)
 *   INCOMPLETE    the engine recorded missing raw features (serving defaults used), or flagged incompleteInput
 *   REVIEW        a recorded factor weakens interpretation (signal conflict, review queue, Unknown override,
 *                 unverifiable model version, invalid probabilities)
 *   INSUFFICIENT  a dimension cannot be assessed from what was stored (completeness, confidence, anomaly signal)
 *   NO_ISSUES     none of the checks above found a problem; this does not establish that the prediction is correct
 */

// Where a flow came from (AIPrediction.captureSource, set by the receiving route). Older records lack the field.
const CAPTURE_PROVENANCE = {
  live_passive: {
    code: 'PROVENANCE_LIVE_PASSIVE', value: 'LIVE_PASSIVE', title: 'Captured live (passive capture)',
    detail: 'The capture service read this flow from a network interface on this host (receive-only).',
    impact: 'Live traffic from this network, scored by a model trained on CICIDS2017.',
  },
  pcap_replay: {
    code: 'PROVENANCE_PCAP_REPLAY', value: 'PCAP_REPLAY', title: 'Replayed from a recorded PCAP',
    detail: 'The capture service extracted this flow from a recorded capture file.',
    impact: 'Recorded traffic, not live traffic.',
  },
  dataset_replay: {
    code: 'PROVENANCE_DATASET_REPLAY', value: 'DATASET_REPLAY', title: 'Replayed from a dataset',
    detail: 'A recorded dataset flow (e.g. CICIDS2017) submitted by the replay tool.',
    impact: 'Recorded benchmark traffic, not live traffic.',
  },
  manual: {
    code: 'PROVENANCE_MANUAL', value: 'MANUAL', title: 'Submitted manually',
    detail: 'An analyst submitted this flow record through the API.',
    impact: 'Not observed on the network by SentinelAI.',
  },
  unknown: {
    code: 'PROVENANCE_UNKNOWN', value: 'UNKNOWN', title: 'Capture source not recorded',
    detail: 'This prediction does not record whether the flow was captured live or replayed from a dataset (e.g. CICIDS2017).',
    impact: 'Do not assume this was live traffic.',
  },
}

const EXPECTED_FEATURES = 53
// Computed by the engine itself, never expected from callers (ai-engine/inference/main.py _NOT_SENT_BY_CALLERS).
const ENGINE_DERIVED_FEATURES = ['payload_entropy', 'time_of_day_sin', 'time_of_day_cos']
// Missing fields whose serving default is an invented non-zero measurement (main.py FABRICATED_DEFAULT_FEATURES).
const FABRICATED_DEFAULT_FEATURES = [
  'flow_duration',
  'total_fwd_packets',
  'total_len_fwd_packets',
  'fwd_packet_len_max',
  'fwd_packet_len_min',
  'fwd_packet_len_mean',
  'flow_bytes_per_sec',
  'flow_packets_per_sec',
  'flow_iat_mean',
  'flow_iat_max',
  'flow_iat_min',
  'syn_flag_count',
  'fwd_header_len',
]

const STATES = Object.freeze({
  UNAVAILABLE: 'UNAVAILABLE',
  INCOMPLETE: 'INCOMPLETE',
  REVIEW: 'REVIEW',
  INSUFFICIENT: 'INSUFFICIENT',
  NO_ISSUES: 'NO_ISSUES',
})
const STATE_ORDER = [STATES.UNAVAILABLE, STATES.INCOMPLETE, STATES.REVIEW, STATES.INSUFFICIENT, STATES.NO_ISSUES]

/** Predictions this assessment applies to: model-scored flows, not rule-based honeypot classifications. */
const ML_SCOPE = { inputSource: { $ne: 'honeypot_log' }, modelType: { $ne: 'rules' } }

const isNum = (v) => typeof v === 'number' && Number.isFinite(v)
const plainProbabilities = (p) => {
  if (!p) return null
  if (p instanceof Map) return Object.fromEntries(p)
  return typeof p === 'object' && !Array.isArray(p) ? p : null
}
const versionUnverifiable = (v) => typeof v !== 'string' || v === '' || /fallback/i.test(v)

// ---- MongoDB equivalents of the rules below (kept next to them; a test checks both agree) ----
const BAD_PROBABILITY_EXPR = {
  $expr: {
    $gt: [
      {
        $size: {
          $filter: {
            input: { $objectToArray: { $ifNull: ['$classProbabilities', {}] } },
            cond: { $or: [{ $not: [{ $isNumber: '$$this.v' }] }, { $lt: ['$$this.v', 0] }, { $gt: ['$$this.v', 1] }] },
          },
        },
      },
      0,
    ],
  },
}
const NO_CONFIDENCE_EXPR = {
  $expr: {
    $eq: [
      {
        $size: {
          $filter: {
            input: { $objectToArray: { $ifNull: ['$classProbabilities', {}] } },
            cond: { $and: [{ $eq: ['$$this.k', '$predictedClass'] }, { $isNumber: '$$this.v' }] },
          },
        },
      },
      0,
    ],
  },
}
const Q = {
  UNAVAILABLE: { predictedClass: 'UNINSPECTED_TRAFFIC' },
  INCOMPLETE: { $or: [{ incompleteInput: true }, { 'defaultedFeatures.0': { $exists: true } }] },
  REVIEW: {
    $or: [
      { needsReview: true },
      { predictedClass: 'BENIGN', isAnomaly: true },
      { predictedClass: 'Unknown' },
      { modelVersion: { $exists: false } },
      { modelVersion: { $in: [null, ''] } },
      { modelVersion: { $regex: 'fallback', $options: 'i' } },
      BAD_PROBABILITY_EXPR,
    ],
  },
  INSUFFICIENT: {
    $or: [
      { defaultedFeatures: { $exists: false } },
      { defaultedFeatures: null },
      { anomalyScore: { $exists: false } },
      { anomalyScore: null },
      { anomalyScore: { $lt: 0 } },
      { anomalyScore: { $gt: 1 } },
      NO_CONFIDENCE_EXPR,
    ],
  },
}

/** MongoDB filter selecting exactly the predictions whose assessed state is `state`. */
function stateFilter(state) {
  const i = STATE_ORDER.indexOf(state)
  if (i < 0) return null
  const higher = STATE_ORDER.slice(0, i).map((s) => Q[s])
  if (state === STATES.NO_ISSUES) return { $nor: higher }
  return higher.length ? { $and: [{ $nor: higher }, Q[state]] } : Q[state]
}

// ---- Assessment ----
function classifierDimension(p) {
  const probs = plainProbabilities(p.classProbabilities)
  const entries = probs ? Object.entries(probs) : []
  const invalid = entries.filter(([, v]) => !isNum(v) || v < 0 || v > 1).map(([k]) => k)
  const valid = entries.filter(([, v]) => isNum(v) && v >= 0 && v <= 1)
  const top = [...valid]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
    .slice(0, 3)
    .map(([label, probability]) => ({ label, probability }))
  // Read by label, never by array position.
  const own = probs ? probs[p.predictedClass] : undefined
  const confidence = isNum(own) && own >= 0 && own <= 1 ? own : null
  return {
    status: confidence === null ? 'unavailable' : 'available',
    predictedClass: p.predictedClass ?? null,
    confidence,
    topClasses: top,
    invalidProbabilityLabels: invalid,
    note: 'The share of model output assigned to the predicted class. It is not a measured probability that this prediction is correct.',
  }
}

function anomalyDimension(p) {
  if (!isNum(p.anomalyScore)) {
    return { status: 'unavailable', isAnomaly: null, anomalyScore: null }
  }
  if (p.anomalyScore < 0 || p.anomalyScore > 1) {
    return { status: 'uninterpretable', isAnomaly: p.isAnomaly === true, anomalyScore: p.anomalyScore }
  }
  return {
    status: 'available',
    isAnomaly: p.isAnomaly === true,
    anomalyScore: p.anomalyScore,
    note: 'Isolation Forest signal: 0 inside the detector’s configured boundary; above 0, how far past it (saturating at 1). Not a probability of attack.',
  }
}

function inputDimension(p) {
  const raw = p.defaultedFeatures
  const recorded = Array.isArray(raw)
  const defaulted = recorded ? raw.filter((f) => typeof f === 'string') : []
  const fabricated = defaulted.filter((f) => FABRICATED_DEFAULT_FEATURES.includes(f))
  let status = recorded ? 'complete' : 'unverified'
  if (defaulted.length || p.incompleteInput === true) status = 'incomplete'
  return {
    status,
    expectedFeatures: EXPECTED_FEATURES,
    engineDerived: ENGINE_DERIVED_FEATURES.length,
    callerExpected: EXPECTED_FEATURES - ENGINE_DERIVED_FEATURES.length,
    defaultedRecorded: recorded,
    defaultedCount: recorded ? defaulted.length : null,
    providedCount: recorded ? EXPECTED_FEATURES - ENGINE_DERIVED_FEATURES.length - defaulted.length : null,
    defaultedFeatures: defaulted,
    fabricatedDefaults: fabricated,
    engineFlaggedIncomplete: p.incompleteInput === true,
  }
}

function reason(code, kind, title, description, value, source, interpretation) {
  return { code, kind, title, description, value, source, interpretation }
}

/**
 * @param {object} p   stored AIPrediction (lean)
 * @returns {object|null} { state, reasons, classifier, threatScore, anomaly, input, modelVersion, provenance } or
 *   null when the record is out of scope (rule-based honeypot classification).
 */
function assessPrediction(p) {
  if (!p || typeof p !== 'object') return null
  if (p.inputSource === 'honeypot_log' || p.modelType === 'rules') return null

  const classifier = classifierDimension(p)
  const anomaly = anomalyDimension(p)
  const input = inputDimension(p)
  const threatScore = isNum(p.threatScore) && p.threatScore >= 0 && p.threatScore <= 1 ? p.threatScore : null
  const reasons = []
  const flags = { UNAVAILABLE: false, INCOMPLETE: false, REVIEW: false, INSUFFICIENT: false }

  if (p.predictedClass === 'UNINSPECTED_TRAFFIC') {
    flags.UNAVAILABLE = true
    reasons.push(
      reason(
        'NO_MODEL_PREDICTION',
        'blocks',
        'No model prediction',
        'The AI engine was unavailable or its result was rejected as invalid, so the flow was stored as uninspected traffic with a fixed placeholder score.',
        'UNINSPECTED_TRAFFIC',
        'predictedClass',
        'Do not read the class, confidence or score as a model judgement.'
      )
    )
  }

  if (input.status === 'incomplete') {
    flags.INCOMPLETE = true
    if (input.defaultedCount) {
      reasons.push(
        reason(
          'DEFAULTED_FEATURES',
          'limits',
          `${input.defaultedCount} input feature${input.defaultedCount === 1 ? ' was' : 's were'} missing`,
          'The engine recorded these raw features as not sent under any recognised name; serving defaults (often 0) were scored in their place. Training data never had missing values.',
          input.defaultedFeatures.join(', '),
          'defaultedFeatures',
          'The score describes a partly substituted flow. Weigh it accordingly.'
        )
      )
      if (input.fabricatedDefaults.length) {
        reasons.push(
          reason(
            'FABRICATED_DEFAULTS',
            'limits',
            'Non-zero serving defaults were used',
            'Missing fields whose default is an invented non-zero measurement. Any one of them makes the engine treat the input as incomplete and never auto-block it.',
            input.fabricatedDefaults.join(', '),
            'defaultedFeatures',
            'These values were not observed in the flow.'
          )
        )
      }
    } else {
      reasons.push(
        reason(
          'ENGINE_INCOMPLETE_FLAG',
          'limits',
          'Input marked incomplete by the engine',
          'The engine flagged this input as incomplete (too many or fabricated defaults). Which features were missing was not stored for this record.',
          'incompleteInput = true',
          'incompleteInput',
          'The score describes a partly substituted flow.'
        )
      )
    }
  } else if (input.status === 'unverified') {
    flags.INSUFFICIENT = true
    reasons.push(
      reason(
        'COMPLETENESS_UNVERIFIED',
        'unknown',
        'Input completeness cannot be verified',
        'Which features were sent was not recorded for this prediction (older records, or a path that did not store it). incompleteInput = false here does not prove that all features were supplied: up to 5 missing zero-default fields are not flagged, and a stored 0 may be real or a default.',
        null,
        'defaultedFeatures (absent)',
        'Treat completeness as unknown.'
      )
    )
  }

  if (classifier.invalidProbabilityLabels.length) {
    flags.REVIEW = true
    reasons.push(
      reason(
        'INVALID_PROBABILITIES',
        'limits',
        'Stored class probabilities are invalid',
        'One or more stored class probabilities are not numbers in [0, 1].',
        classifier.invalidProbabilityLabels.join(', '),
        'classProbabilities',
        'The probability breakdown cannot be relied on.'
      )
    )
  }
  if (classifier.status === 'unavailable' && !flags.UNAVAILABLE) {
    flags.INSUFFICIENT = true
    reasons.push(
      reason(
        'CONFIDENCE_UNAVAILABLE',
        'unknown',
        'Classifier confidence not available',
        p.predictedClass === 'Unknown'
          ? 'The class "Unknown" is set by the anomaly tier, not by the classifier, so it has no classifier probability.'
          : 'No stored probability exists for the predicted class.',
        p.predictedClass ?? null,
        'classProbabilities',
        'Confidence cannot be shown for this prediction.'
      )
    )
  }
  if (p.predictedClass === 'Unknown') {
    flags.REVIEW = true
    reasons.push(
      reason(
        'UNKNOWN_OVERRIDE',
        'limits',
        'Classifier output overridden as Unknown',
        'The anomaly tier replaced the classifier’s label because the flow was flagged as anomalous.',
        'Unknown',
        'predictedClass',
        'The flow is unusual to the detector; no attack type is established.'
      )
    )
  }

  if (anomaly.status === 'unavailable' && !flags.UNAVAILABLE) {
    flags.INSUFFICIENT = true
    reasons.push(
      reason(
        'ANOMALY_UNAVAILABLE',
        'unknown',
        'Anomaly signal not recorded',
        'No Isolation Forest score is stored for this prediction.',
        null,
        'anomalyScore',
        'Signal agreement cannot be evaluated.'
      )
    )
  } else if (anomaly.status === 'uninterpretable') {
    flags.INSUFFICIENT = true
    reasons.push(
      reason(
        'ANOMALY_UNINTERPRETABLE',
        'unknown',
        'Anomaly signal outside its defined range',
        'The stored anomaly score is outside [0, 1], the range the engine produces.',
        String(anomaly.anomalyScore),
        'anomalyScore',
        'The anomaly signal is not interpreted.'
      )
    )
  }

  if (p.predictedClass === 'BENIGN' && p.isAnomaly === true) {
    flags.REVIEW = true
    reasons.push(
      reason(
        'SIGNAL_CONFLICT',
        'limits',
        'Classifier says BENIGN, anomaly detector flagged the flow',
        'The two models point in different directions. This warrants attention but does not show that the flow is an attack.',
        `isAnomaly = true, anomalyScore = ${anomaly.anomalyScore ?? 'n/a'}`,
        'predictedClass, isAnomaly',
        'Review the flow before relying on the BENIGN label.'
      )
    )
  }
  if (p.needsReview === true) {
    flags.REVIEW = true
    reasons.push(
      reason(
        'IN_REVIEW_QUEUE',
        'limits',
        'Placed in the analyst review queue',
        p.honeypotCorroborated
          ? 'Classified BENIGN/Unknown although this source IP attacked the honeypot recently.'
          : 'The engine returned REVIEW (anomalous but classified BENIGN).',
        p.honeypotCorroborated ? 'honeypotCorroborated = true' : 'needsReview = true',
        p.honeypotCorroborated ? 'needsReview, honeypotCorroborated' : 'needsReview',
        'An analyst should verify the class.'
      )
    )
  }
  if (versionUnverifiable(p.modelVersion) && !flags.UNAVAILABLE) {
    flags.REVIEW = true
    reasons.push(
      reason(
        'MODEL_VERSION_UNVERIFIED',
        'limits',
        'Model version could not be verified',
        'The stored model version is missing or names a fallback, so the producing model cannot be identified.',
        p.modelVersion || null,
        'modelVersion',
        'Which model produced this output is uncertain.'
      )
    )
  }

  // Informational evidence (never changes the state)
  if (anomaly.status === 'available' && p.predictedClass !== 'BENIGN' && p.predictedClass !== 'UNINSPECTED_TRAFFIC') {
    reasons.push(
      anomaly.isAnomaly
        ? reason(
            'SIGNALS_ALIGNED',
            'info',
            'Both signals flag the flow',
            'The classifier predicted an attack class and the anomaly detector also flagged the flow. Agreement does not establish correctness.',
            `anomalyScore = ${anomaly.anomalyScore}`,
            'isAnomaly, anomalyScore',
            'Supporting, not confirming, evidence.'
          )
        : reason(
            'NO_ANOMALY_FLAG',
            'info',
            'Anomaly detector did not flag the flow',
            'The flow is inside the detector’s boundary. This neither confirms nor contradicts the classifier’s attack label.',
            'isAnomaly = false',
            'isAnomaly',
            'Neutral evidence.'
          )
    )
  }
  if (p.verified === true && p.actualClass) {
    reasons.push(
      reason(
        'ANALYST_VERIFIED',
        'info',
        p.actualClass === p.predictedClass ? 'Analyst confirmed the class' : 'Analyst recorded a different class',
        'An analyst verified this prediction.',
        `actualClass = ${p.actualClass}`,
        'verified, actualClass',
        p.actualClass === p.predictedClass ? 'Confirmed by a human.' : 'The model label was judged wrong.'
      )
    )
  }
  const prov = CAPTURE_PROVENANCE[p.captureSource] || CAPTURE_PROVENANCE.unknown
  reasons.push(
    reason(prov.code, 'info', prov.title, prov.detail, p.captureSource || p.inputSource || null,
      p.captureSource ? 'captureSource' : 'inputSource', prov.impact)
  )

  const state = STATE_ORDER.find((s) => s === STATES.NO_ISSUES || flags[s])
  return {
    state,
    reasons,
    classifier,
    threatScore,
    anomaly,
    input,
    modelVersion: { value: p.modelVersion || null, verifiable: !versionUnverifiable(p.modelVersion) },
    provenance: prov.value,
  }
}

module.exports = {
  STATES,
  STATE_ORDER,
  ML_SCOPE,
  EXPECTED_FEATURES,
  FABRICATED_DEFAULT_FEATURES,
  assessPrediction,
  stateFilter,
}
