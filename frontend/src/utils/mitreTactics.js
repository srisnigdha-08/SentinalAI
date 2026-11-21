// Rank 8: ATT&CK tactics for the techniques SentinelAI maps (ATT&CK Enterprise v20.1, verified 2026-11-16).
// Mirrors backend/utils/attackTechniques.js (frontend/tests/mitreTactics.test.mjs keeps both equal). Records store
// techniques as {id, name}; the tactic is derived from the id for display.
export const ATTACK_VERSION = 'ATT&CK Enterprise v20.1'

const D = ['Discovery']
const CA = ['Credential Access']
const EX = ['Execution']
const P_PE = ['Persistence', 'Privilege Escalation']

export const TECHNIQUE_TACTICS = Object.freeze({
  T1082: D, T1033: D, T1016: D, T1049: D, T1057: D, T1007: D, 'T1087.001': D, 'T1069.001': D, T1135: D, T1018: D,
  T1083: D, T1046: D,
  T1595: ['Reconnaissance'],
  T1003: CA, 'T1003.001': CA, 'T1003.002': CA, 'T1003.003': CA, 'T1003.008': CA, 'T1552.001': CA, 'T1555.004': CA,
  T1110: CA, 'T1110.004': CA,
  T1059: EX, 'T1059.001': EX, 'T1059.003': EX, 'T1059.004': EX, 'T1059.006': EX,
  'T1053.003': ['Execution', ...P_PE], 'T1053.005': ['Execution', ...P_PE],
  'T1543.002': P_PE, 'T1543.003': P_PE, T1098: P_PE, 'T1098.004': P_PE, 'T1136.001': ['Persistence'],
  'T1547.001': P_PE, 'T1548.001': ['Privilege Escalation'],
  T1027: ['Stealth'], 'T1070.003': ['Stealth'],
  T1690: ['Defense Impairment'], 'T1222.001': ['Defense Impairment'], 'T1222.002': ['Defense Impairment'],
  T1685: ['Defense Impairment'], 'T1685.005': ['Defense Impairment'], 'T1685.006': ['Defense Impairment'],
  T1686: ['Defense Impairment'],
  T1105: ['Command and Control'], T1095: ['Command and Control'], T1071: ['Command and Control'],
  T1190: ['Initial Access'], T1021: ['Lateral Movement'], T1048: ['Exfiltration'],
  T1485: ['Impact'], T1486: ['Impact'], T1490: ['Impact'], T1496: ['Impact'], T1498: ['Impact'],
})

/** Tactics of a technique: the record's own list when present, else the verified table; [] when unknown. */
export function tacticsOf(tech) {
  if (tech && Array.isArray(tech.tactics) && tech.tactics.length) return tech.tactics
  return (tech && TECHNIQUE_TACTICS[tech.id]) || []
}

/** "Discovery" / "Persistence, Privilege Escalation" / "tactic not mapped" for display. */
export function tacticText(tech) {
  const t = tacticsOf(tech)
  return t.length ? t.join(', ') : 'tactic not mapped'
}
