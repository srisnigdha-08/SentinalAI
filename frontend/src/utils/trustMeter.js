// AI Trust Meter presentation helpers. The assessment itself is computed by the backend
// (backend/utils/trustAssessment.js); this file only labels it. No numeric trust score exists anywhere.

// Colours stay off red: a trust state is not a threat severity. Each state also has an icon and text.
export const STATE_META = Object.freeze({
  NO_ISSUES: {
    label: 'No identified issues',
    icon: '✓',
    color: '#00ff88',
    description: 'The available checks found no problem with this prediction’s input or signals. This does not establish that the prediction is correct.',
  },
  REVIEW: {
    label: 'Review recommended',
    icon: '◐',
    color: '#ffaa00',
    description: 'One or more recorded factors weaken how far this prediction can be relied on.',
  },
  INCOMPLETE: {
    label: 'Input incomplete',
    icon: '◌',
    color: '#f5c542',
    description: 'Expected input features were missing and serving defaults were scored in their place.',
  },
  INSUFFICIENT: {
    label: 'Insufficient evidence',
    icon: '?',
    color: '#7ab3cc',
    description: 'At least one dimension (input completeness, confidence or anomaly signal) cannot be assessed from what was stored.',
  },
  UNAVAILABLE: {
    label: 'No model prediction',
    icon: '∅',
    color: '#8ba3b5',
    description: 'The AI engine was unavailable or its result was rejected, so there is no model judgement to assess.',
  },
})
export const STATE_KEYS = Object.keys(STATE_META)

export const REASON_KIND = Object.freeze({
  blocks: { label: 'PREVENTS INTERPRETATION', color: '#8ba3b5' },
  limits: { label: 'LIMITS INTERPRETATION', color: '#ffaa00' },
  unknown: { label: 'CANNOT BE ASSESSED', color: '#7ab3cc' },
  info: { label: 'CONTEXT', color: '#00d4ff' },
})

// Dataset-level findings from documented evaluations. They are never per-prediction reasons, and the three are
// separate evaluations that must not be compared as if they measured the same thing.
export const MODEL_LIMITATIONS = Object.freeze({
  model: 'xgb_cicids_v1',
  trainedOn: 'De-duplicated CICIDS2017 flows (10 classes).',
  evaluations: [
    {
      id: 'random',
      title: 'Random split, CICIDS2017 (in-distribution)',
      result: '98.97% accuracy, macro F1 0.874',
      caveat: 'Train and test rows come from the same capture sessions, so this measures fit to CICIDS2017, not transfer to other networks.',
      source: 'README.md; docs/AI_ENGINE_STUDY_GUIDE.md',
    },
    {
      id: 'chronological',
      title: 'Chronological split, CICIDS2017',
      result: 'About 91.0% of attack flows alerted at a 0.134% benign alert rate (macro F1 0.772)',
      caveat: 'Later capture days held out; same dataset and testbed.',
      source: 'docs/AI_ENGINE_STUDY_GUIDE.md',
    },
    {
      id: '2018dev',
      title: 'Six CSE-CIC-IDS2018 development days (diagnostic)',
      result: '15.2% attack recall at the 0.90 alert line (7,219 of 47,553 attack flows); 0.24% benign false-alarm rate (198 of 81,821)',
      caveat: 'A different network and attack tooling. Diagnostic only, run 2026-11-11; the locked 2018 test days were not used.',
      source: 'Local diagnostic run deployed_2018dev_diagnostic_20261111 (results.json; not committed to the repository)',
    },
  ],
  takeaway:
    'The model generalises poorly beyond the dataset it was trained on. High classifier confidence does not mean a prediction transfers to a different environment. These are dataset-level results: they do not show that any single prediction is right or wrong.',
})

export const pct = (v, digits = 1) => (typeof v === 'number' && Number.isFinite(v) ? `${(v * 100).toFixed(digits)}%` : 'Unavailable')

/** Plain-language one-liner for the list, built only from the assessment. */
export function stateSummary(trust) {
  if (!trust) return 'Not assessed'
  const limits = (trust.reasons || []).filter((r) => r.kind !== 'info')
  if (!limits.length) return STATE_META[trust.state]?.label || trust.state
  const first = limits[0].title
  return limits.length > 1 ? `${first} (+${limits.length - 1} more)` : first
}

export function inputSummary(input) {
  if (!input) return 'Unavailable'
  if (input.status === 'complete') return `${input.providedCount} of ${input.callerExpected} caller features sent (+${input.engineDerived} engine-derived = ${input.expectedFeatures})`
  if (input.status === 'incomplete' && input.defaultedRecorded) return `${input.defaultedCount} of ${input.callerExpected} caller features missing (defaults used)`
  if (input.status === 'incomplete') return 'Marked incomplete by the engine; missing features not recorded'
  return 'Completeness not recorded for this prediction'
}

export function anomalySummary(anomaly) {
  if (!anomaly || anomaly.status === 'unavailable') return 'Not recorded'
  if (anomaly.status === 'uninterpretable') return `Out of range (${anomaly.anomalyScore}); not interpreted`
  return anomaly.isAnomaly ? `Flagged as unusual (signal ${anomaly.anomalyScore})` : 'Not flagged (inside the detector boundary)'
}
