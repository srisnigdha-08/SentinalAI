// Display helpers for the AI engine's drift report (GET /api/ai/engine/drift) and deception recommendation.
// These describe screening statistics; a "drift" status means "re-evaluate the model", not proof of failure.

const TONES = {
  ok:                { label: 'NO DRIFT',          badgeType: 'ok',   color: '#00ff88' },
  drift:             { label: 'DRIFT DETECTED',    badgeType: 'warn', color: '#ffaa00' },
  insufficient_data: { label: 'COLLECTING SAMPLES', badgeType: 'info', color: '#00d4ff' },
}

export function driftSummary(report) {
  if (!report || typeof report !== 'object') {
    return { label: 'UNAVAILABLE', badgeType: 'live', color: '#ff2d55', detail: 'AI engine drift report unavailable.' }
  }
  const tone = TONES[report.status] || { label: String(report.status || 'UNKNOWN').toUpperCase(), badgeType: 'info', color: '#7ab3cc' }
  const samples = Number(report.samples) || 0
  const minSamples = Number(report.min_samples) || 0
  let detail
  if (report.status === 'insufficient_data') {
    detail = `${samples} of ${minSamples} live flows needed before drift is assessed.`
  } else {
    const drifted = Array.isArray(report.drifted_features) ? report.drifted_features.length : 0
    const informative = Number(report.informative_features) || 0
    const pct = typeof report.drifted_fraction === 'number' ? (report.drifted_fraction * 100).toFixed(1) : '—'
    detail = `${drifted} of ${informative} features outside training range (${pct}%) over the last ${samples} flows.`
  }
  return { ...tone, detail }
}

/** Top shifted features, largest first, for a small table. PSI reports (benign quantiles) carry `psi`;
 *  the older scaler-statistics reports carry mean shift (sd) and variance ratio. */
export function topShiftRows(report, limit = 5) {
  return (Array.isArray(report?.top_shifts) ? report.top_shifts : []).slice(0, limit).map(r => ({
    feature: r.feature,
    value: typeof r.psi === 'number'
      ? `PSI ${r.psi.toFixed(3)}`
      : `${typeof r.mean_shift_sd === 'number' ? r.mean_shift_sd.toFixed(2) : '—'} · ${typeof r.variance_ratio === 'number' ? r.variance_ratio.toFixed(2) : '—'}×`,
    flagged: Array.isArray(report?.drifted_features) && report.drifted_features.includes(r.feature),
  }))
}

/** Global SHAP summary (GET /api/ai/engine/explain-global) as rows for a small table. */
export function globalShapRows(summary, limit = 8) {
  const rows = Array.isArray(summary?.overall) ? summary.overall : []
  const max = rows.reduce((m, r) => Math.max(m, Number(r.mean_abs_shap) || 0), 0)
  return rows.slice(0, limit).map(r => ({
    feature: r.feature,
    value: (Number(r.mean_abs_shap) || 0).toFixed(4),
    pct: max ? Math.round(((Number(r.mean_abs_shap) || 0) / max) * 100) : 0,
  }))
}

/** Recent predicted-class mix as [{ cls, count, pct }], most frequent first. */
export function classMixRows(report) {
  const mix = report?.recent_class_mix && typeof report.recent_class_mix === 'object' ? report.recent_class_mix : {}
  const total = Object.values(mix).reduce((a, b) => a + (Number(b) || 0), 0)
  return Object.entries(mix)
    .map(([cls, count]) => ({ cls, count: Number(count) || 0 }))
    .sort((a, b) => b.count - a.count)
    .map(r => ({ ...r, pct: total ? ((r.count / total) * 100).toFixed(1) : '0.0' }))
}

/** How much of the Q-learner's table came from real scored sessions versus its starting seed. */
export function learnerProvenanceSummary(prov) {
  if (!prov || prov.seedEpisodes == null) return 'Training data origin unknown (Q-table predates provenance tracking).'
  const sessions = `${prov.sessionEpisodes} update${prov.sessionEpisodes === 1 ? '' : 's'} from scored sessions`
  if (!prov.synthetic) return `${sessions}; started from an empty table.`
  return `${sessions}; ${prov.seedEpisodes} inherited from a synthetic warm start, not attacker data.`
}

export function recommendationSummary(rec) {
  if (!rec?.nextProfile) return null
  if (rec.nextProfile === rec.activeProfile) {
    return `Keep serving ${rec.activeProfile}${rec.explored ? ' (exploration pick)' : ''}.`
  }
  const best = rec.policy === 'ucb1' ? ' (highest upper confidence bound)' : ' (best known Q-value)'
  return `Switch ${rec.activeProfile} → ${rec.nextProfile}${rec.explored ? ' (exploration pick)' : best}.`
}
