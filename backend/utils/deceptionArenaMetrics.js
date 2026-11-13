'use strict'
/**
 * Deception Arena metrics and conclusions. Pure and deterministic: the same trials always give the same numbers and
 * the same wording. Conclusions follow the fixed rules in conclude(); nothing claims that the adaptive strategy is
 * better unless a paired interval excludes zero, and even then the claim is limited to the scenario that produced it.
 */
const { getMitreTechniquesForSession } = require('./mitreMapping')

// Allowlisted scenarios; must match SCENARIOS in ai-engine/demo/deception_arena.py (a test checks this).
const SCENARIOS = Object.freeze({
  scripted_recon: { kind: 'SCRIPTED', title: 'Scripted reconnaissance (fixed script)' },
  scripted_dropper: { kind: 'SCRIPTED', title: 'Scripted dropper (fixed script)' },
  persona_sensitive_sim: { kind: 'SIMULATED', title: 'Persona-sensitive simulated attacker (assumed preferences)' },
  profile_recon_scanner: { kind: 'SIMULATED', title: 'Reconnaissance scanner (automated, fast, shallow)' },
  profile_credential_bruteforcer: {
    kind: 'SIMULATED',
    title: 'Credential brute-forcer (many logins, little shell activity)',
  },
  profile_interactive_explorer: { kind: 'SIMULATED', title: 'Interactive explorer (human-paced, deep discovery)' },
  profile_persistence_seeker: { kind: 'SIMULATED', title: 'Persistence seeker (cron, keys, services)' },
  profile_cautious_fingerprinter: {
    kind: 'SIMULATED',
    title: 'Cautious fingerprinter (checks for virtualisation, leaves early)',
  },
  profile_opportunistic_dropper: { kind: 'SIMULATED', title: 'Opportunistic dropper (download and run a payload)' },
})
const MIN_PAIRS_FOR_INTERVAL = 10

// Two-sided 95% Student-t critical values (df 1-30, then 40, 50, 60); linear interpolation in between.
const T95 = [
  12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.16, 2.145, 2.131, 2.12, 2.11,
  2.101, 2.093, 2.086, 2.08, 2.074, 2.069, 2.064, 2.06, 2.056, 2.052, 2.048, 2.045, 2.042,
]
function t95(df) {
  if (df < 1) return null
  if (df <= 30) return T95[df - 1]
  const pts = [
    [30, 2.042],
    [40, 2.021],
    [50, 2.009],
    [60, 2.0],
  ]
  if (df >= 60) return 2.0
  for (let i = 1; i < pts.length; i++) {
    const [d1, v1] = pts[i - 1]
    const [d2, v2] = pts[i]
    if (df <= d2) return v1 + ((v2 - v1) * (df - d1)) / (d2 - d1)
  }
  return 2.0
}

const isNum = (v) => typeof v === 'number' && Number.isFinite(v)
const round = (v, d = 2) => (isNum(v) ? Math.round(v * 10 ** d) / 10 ** d : null)

/** n, mean, median, min, max, missing; null statistics when there is no observation. */
function describe(values) {
  const xs = values.filter(isNum).sort((a, b) => a - b)
  const n = xs.length
  const missing = values.length - n
  if (!n) return { n: 0, missing, mean: null, median: null, min: null, max: null }
  const mean = xs.reduce((a, b) => a + b, 0) / n
  const median = n % 2 ? xs[(n - 1) / 2] : (xs[n / 2 - 1] + xs[n / 2]) / 2
  return { n, missing, mean: round(mean), median: round(median), min: xs[0], max: xs[n - 1] }
}

const trialCommands = (t) =>
  Array.isArray(t.commands) ? t.commands.filter((c) => c && typeof c.command === 'string') : []
const trialTechniques = (t) =>
  getMitreTechniquesForSession(trialCommands(t).map((c) => ({ command: c.command, intent: c.intent })))

function strategySummary(trials) {
  const commandSets = trials.map((t) => new Set(trialCommands(t).map((c) => c.command)))
  const allCommands = new Set(commandSets.flatMap((s) => [...s]))
  const techniques = new Map()
  for (const t of trials) for (const tech of trialTechniques(t)) techniques.set(tech.id, tech)
  const personas = {}
  for (const t of trials) personas[t.persona] = (personas[t.persona] || 0) + 1
  const terminations = {}
  for (const t of trials) {
    const k = t.termination || 'not_recorded'
    terminations[k] = (terminations[k] || 0) + 1
  }
  const ordered = [...trials].sort((a, b) => a.index - b.index)
  let switches = 0
  for (let i = 1; i < ordered.length; i++) if (ordered[i].persona !== ordered[i - 1].persona) switches++
  const decisions = trials.filter((t) => t.decision)
  return {
    trials: trials.length,
    durationSeconds: describe(trials.map((t) => t.durationSeconds)),
    commands: describe(trials.map((t) => (Array.isArray(t.commands) ? trialCommands(t).length : null))),
    uniqueCommandsPerTrial: describe(commandSets.map((s) => s.size)),
    uniqueCommandsTotal: allCommands.size,
    techniques: [...techniques.values()].sort((a, b) => (a.id < b.id ? -1 : 1)),
    techniquesPerTrial: describe(trials.map((t) => trialTechniques(t).length)),
    // The learner's own reward (calc_reward). Reported, never used as the success criterion.
    reward: describe(trials.map((t) => t.reward)),
    personas,
    personaSwitches: switches,
    recommendations: decisions.length,
    recommendationsApplied: decisions.filter((t) => t.decision.recommendedPersona === t.decision.appliedPersona).length,
    explorations: decisions.filter((t) => t.decision.explored).length,
    terminations,
    fingerprinted: trials.filter((t) => t.fingerprinted).length,
  }
}

/** Paired differences (adaptive - static) for one outcome over pairs that have both values. */
function paired(staticTrials, adaptiveTrials, pick) {
  const byIndex = new Map(staticTrials.map((t) => [t.index, t]))
  const diffs = []
  let unpaired = 0
  for (const a of adaptiveTrials) {
    const s = byIndex.get(a.index)
    const x = s ? pick(s) : null
    const y = pick(a)
    if (isNum(x) && isNum(y)) diffs.push(y - x)
    else unpaired++
  }
  unpaired += staticTrials.filter((s) => !adaptiveTrials.some((a) => a.index === s.index)).length
  const n = diffs.length
  const out = { pairs: n, unpaired, meanDifference: null, sd: null, ci95: null, method: null }
  if (!n) return out
  const mean = diffs.reduce((a, b) => a + b, 0) / n
  out.meanDifference = round(mean)
  if (n >= 2) {
    const sd = Math.sqrt(diffs.reduce((a, d) => a + (d - mean) ** 2, 0) / (n - 1))
    out.sd = round(sd)
    if (n >= MIN_PAIRS_FOR_INTERVAL) {
      const half = t95(n - 1) * (sd / Math.sqrt(n))
      out.ci95 = [round(mean - half), round(mean + half)]
      out.method = 'paired t-interval (95%)'
    }
  }
  return out
}

function evaluate(experiment) {
  const trials = Array.isArray(experiment?.trials) ? experiment.trials : []
  const st = trials.filter((t) => t.strategy === 'STATIC')
  const ad = trials.filter((t) => t.strategy === 'ADAPTIVE')
  const comparison = {
    commands: paired(st, ad, (t) => (Array.isArray(t.commands) ? trialCommands(t).length : null)),
    durationSeconds: paired(st, ad, (t) => t.durationSeconds),
    techniques: paired(st, ad, (t) => (Array.isArray(t.commands) ? trialTechniques(t).length : null)),
  }
  const summary = { STATIC: strategySummary(st), ADAPTIVE: strategySummary(ad) }
  return { summary, comparison, conclusion: conclude(experiment, summary, comparison) }
}

const LIVE_CAVEAT =
  'Adaptive engagement benefit not yet established: no controlled experiment with real attackers exists.'

/** Deterministic findings. Each has a code, a level (finding/limitation) and fixed wording. */
function conclude(experiment, summary, comparison) {
  const kind = SCENARIOS[experiment?.scenario]?.kind || 'UNKNOWN'
  const findings = []
  const add = (code, level, text) => findings.push({ code, level, text })
  let headline

  if (experiment?.status !== 'COMPLETED') {
    headline = 'No conclusion: the experiment has not completed.'
    add(
      'NOT_COMPLETED',
      'limitation',
      `Status is ${experiment?.status || 'unknown'}; partial trials are shown as observations only.`
    )
  } else if (!summary.ADAPTIVE.trials) {
    headline = 'No comparison: the adaptive strategy was not run.'
    add('STATIC_ONLY', 'limitation', 'Only the static baseline was run, so the strategies cannot be compared.')
  } else if (kind === 'SCRIPTED') {
    headline = 'The scripted scenario does not measure adaptive attacker engagement.'
    add(
      'SCRIPT_FIXED',
      'limitation',
      'The scripted attacker runs the same commands with the same timing whatever persona it meets, so any engagement difference is impossible by construction.'
    )
    const same = ['commands', 'durationSeconds'].every(
      (k) => comparison[k].pairs > 0 && comparison[k].meanDifference === 0 && (comparison[k].sd ?? 0) === 0
    )
    add(
      'MECHANICS',
      'finding',
      same
        ? `Mechanics check: all ${comparison.commands.pairs} paired trials captured identical sessions under both strategies, as expected for a fixed script.`
        : 'Mechanics check: paired scripted trials differ, which a fixed script should not produce. Treat this run as a defect to investigate.'
    )
  } else if (kind === 'SIMULATED') {
    const c = comparison.commands
    if (c.pairs < MIN_PAIRS_FOR_INTERVAL) {
      headline = `Inconclusive: ${c.pairs} paired trial${c.pairs === 1 ? '' : 's'} is too few (at least ${MIN_PAIRS_FOR_INTERVAL} needed for an interval).`
      add('SMALL_SAMPLE', 'limitation', 'Raw observations are shown; no interval or difference is claimed.')
    } else if (c.ci95 && (c.ci95[0] > 0 || c.ci95[1] < 0)) {
      const dir = c.ci95[0] > 0 ? 'more' : 'fewer'
      headline = `In this simulation, the adaptive strategy captured ${dir} commands per session (mean difference ${c.meanDifference}, 95% CI ${c.ci95[0]} to ${c.ci95[1]}, ${c.pairs} pairs).`
      add(
        'SIM_ASSUMPTIONS',
        'limitation',
        'The simulated attacker’s persona preferences are assumed parameters, so this shows the learner can find the persona the simulator favours. It is not evidence about real attackers.'
      )
    } else {
      headline = `No difference in commands captured was established (mean difference ${c.meanDifference}, 95% CI ${c.ci95?.[0]} to ${c.ci95?.[1]}, ${c.pairs} pairs).`
      add(
        'SIM_ASSUMPTIONS',
        'limitation',
        'Even a difference here would reflect the simulator’s assumed persona preferences, not real attackers.'
      )
    }
    const d = comparison.durationSeconds
    if (d.ci95)
      add(
        'DURATION',
        'finding',
        `Session duration, adaptive minus static: mean ${d.meanDifference} s (95% CI ${d.ci95[0]} to ${d.ci95[1]}, ${d.pairs} pairs).`
      )
  } else {
    headline = 'No conclusion: the scenario is not recognised.'
  }

  if (summary.ADAPTIVE.trials) {
    const a = summary.ADAPTIVE
    add(
      'SWITCH_OVERHEAD',
      'finding',
      `The adaptive strategy changed persona ${a.personaSwitches} time${a.personaSwitches === 1 ? '' : 's'} in ${a.trials} trials. In a live deployment each change restarts Cowrie; that interruption was not measured here.`
    )
    add(
      'RECOMMENDATIONS',
      'finding',
      `${a.recommendationsApplied} of ${a.recommendations} recommendations were applied as recommended (${a.explorations} exploratory).`
    )
    add(
      'REWARD_NOT_OUTCOME',
      'limitation',
      'The reward is the learner’s own score (built from duration, commands, intents, login and fingerprint checks). It is shown for transparency but is not an independent success measure.'
    )
  }
  add(
    'ISOLATED_LEARNER',
    'limitation',
    'Trials used a temporary copy of the shipped seed Q-table; it reflects that seed, not the deployed learner’s current table, and nothing was saved.'
  )
  add('LIVE_CAVEAT', 'limitation', LIVE_CAVEAT)
  return { headline, kind, findings, adaptiveBenefitEstablished: false }
}

module.exports = { SCENARIOS, MIN_PAIRS_FOR_INTERVAL, describe, paired, evaluate, conclude, t95, LIVE_CAVEAT }
