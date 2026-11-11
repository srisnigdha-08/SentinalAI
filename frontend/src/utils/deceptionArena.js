// Deception Arena presentation helpers. Metrics and conclusions are computed by the backend
// (backend/utils/deceptionArenaMetrics.js); this file only labels, formats and exports them.

export const STATUS_META = Object.freeze({
  CREATED: { label: 'Waiting for runner', color: '#7ab3cc', icon: '○' },
  RUNNING: { label: 'Running', color: '#00d4ff', icon: '▶' },
  COMPLETED: { label: 'Completed', color: '#00ff88', icon: '✓' },
  FAILED: { label: 'Failed', color: '#ffaa00', icon: '✖' },
  CANCELLED: { label: 'Cancelled', color: '#8ba3b5', icon: '■' },
})

export const KIND_META = Object.freeze({
  SCRIPTED: {
    label: 'Scripted (controlled)',
    color: '#00d4ff',
    help: 'A fixed command script with fixed timing. It cannot react to the persona, so it checks the mechanics, not attacker engagement.',
  },
  SIMULATED: {
    label: 'Simulated attacker',
    color: '#ffaa00',
    help: 'A model attacker whose behaviour depends on the persona through assumed parameters. Results reflect those assumptions, not real attackers.',
  },
})

export const TERMINATION_LABEL = Object.freeze({
  completed: 'Completed script',
  attacker_left: 'Attacker left',
  fingerprinted: 'Honeypot fingerprinted',
  time_limit: 'Hit time limit',
  not_recorded: 'Not recorded',
})

export const fmt = (v, unit = '') => (typeof v === 'number' && Number.isFinite(v) ? `${v}${unit}` : 'Not measured')

export function interval(p) {
  if (!p || !p.pairs) return 'No paired observations'
  if (!p.ci95) return `Mean ${fmt(p.meanDifference)} over ${p.pairs} pair${p.pairs === 1 ? '' : 's'}; too few for an interval`
  return `Mean ${p.meanDifference} (95% CI ${p.ci95[0]} to ${p.ci95[1]}), ${p.pairs} pairs`
}

/** Per-trial rows for charts: one row per trial index with both strategies’ raw values (missing stays null). */
export function trialRows(trials = [], pick) {
  const rows = new Map()
  for (const t of trials) {
    const row = rows.get(t.index) || { trial: t.index + 1, STATIC: null, ADAPTIVE: null }
    const v = pick(t)
    row[t.strategy] = typeof v === 'number' && Number.isFinite(v) ? v : null
    rows.set(t.index, row)
  }
  return [...rows.values()].sort((a, b) => a.trial - b.trial)
}

const csvCell = (v) => {
  const s = v === null || v === undefined ? '' : String(v)
  // Neutralise spreadsheet formulas and quote everything.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s
  return `"${safe.replace(/"/g, '""')}"`
}

/** One CSV row per trial, with the experiment’s identity and provenance on every row. */
export function trialsCsv(experiment) {
  const head = ['experimentId', 'scenario', 'scenarioKind', 'seed', 'strategy', 'trial', 'pairPosition', 'persona', 'recommendedPersona', 'appliedPersona', 'explored', 'durationSeconds', 'commands', 'uniqueCommands', 'termination', 'fingerprinted', 'learnerReward', 'startedAt', 'endedAt']
  const lines = [head.map(csvCell).join(',')]
  for (const t of [...(experiment.trials || [])].sort((a, b) => a.index - b.index || (a.strategy < b.strategy ? 1 : -1))) {
    const cmds = Array.isArray(t.commands) ? t.commands : []
    lines.push([
      experiment.experimentId, experiment.scenario, experiment.kind, experiment.seed, t.strategy, t.index + 1, t.pairPosition, t.persona,
      t.decision?.recommendedPersona, t.decision?.appliedPersona, t.decision ? t.decision.explored : '', t.durationSeconds, cmds.length,
      new Set(cmds.map((c) => c.command)).size, t.termination, t.fingerprinted, t.reward, t.startedAt, t.endedAt,
    ].map(csvCell).join(','))
  }
  return lines.join('\r\n') + '\r\n'
}

/** JSON evidence bundle: raw observations kept apart from derived results. */
export function evidenceJson(experiment, results) {
  const { trials, events, ...config } = experiment
  return JSON.stringify({
    exportedAt: new Date().toISOString(),
    observations: { trials, events },
    configuration: config,
    derived: results,
    note: 'observations are what the runner recorded; derived holds metrics and rule-based conclusions computed from them.',
  }, null, 2)
}
