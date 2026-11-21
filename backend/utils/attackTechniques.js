'use strict'

/**
 * The MITRE ATT&CK Enterprise techniques SentinelAI maps to, with their official names and tactics.
 *
 * Verified on attack.mitre.org on 2026-11-16 against ATT&CK Enterprise v20.1. In v20 the former "Defense Evasion"
 * tactic is split into TA0005 "Stealth" and TA0112 "Defense Impairment", and several techniques moved:
 * Clear Windows Event Logs is T1685.005, Disable or Modify System Firewall is T1686, Prevent Command History Logging
 * is T1690, and T1222.001/.002 are named "Windows Permissions" / "Linux and Mac Permissions".
 *
 * Every mapping rule must reference an id from this table: t() throws for an unknown id, so no technique can be
 * invented in a rule. frontend/src/utils/mitreTactics.js mirrors the tactic column (a test keeps both equal).
 */

const ATTACK_VERSION = 'ATT&CK Enterprise v20.1 (verified 2026-11-16)'

const TACTICS = Object.freeze({
  TA0043: 'Reconnaissance',
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0003: 'Persistence',
  TA0004: 'Privilege Escalation',
  TA0005: 'Stealth',
  TA0112: 'Defense Impairment',
  TA0006: 'Credential Access',
  TA0007: 'Discovery',
  TA0008: 'Lateral Movement',
  TA0011: 'Command and Control',
  TA0010: 'Exfiltration',
  TA0040: 'Impact',
})

const P_PE = ['Persistence', 'Privilege Escalation']

const TECHNIQUES = Object.freeze({
  // Discovery (on-host)
  T1082: { name: 'System Information Discovery', tactics: ['Discovery'] },
  T1033: { name: 'System Owner/User Discovery', tactics: ['Discovery'] },
  T1016: { name: 'System Network Configuration Discovery', tactics: ['Discovery'] },
  T1049: { name: 'System Network Connections Discovery', tactics: ['Discovery'] },
  T1057: { name: 'Process Discovery', tactics: ['Discovery'] },
  T1007: { name: 'System Service Discovery', tactics: ['Discovery'] },
  'T1087.001': { name: 'Local Account', tactics: ['Discovery'] },
  'T1069.001': { name: 'Local Groups', tactics: ['Discovery'] },
  T1135: { name: 'Network Share Discovery', tactics: ['Discovery'] },
  T1018: { name: 'Remote System Discovery', tactics: ['Discovery'] },
  T1083: { name: 'File and Directory Discovery', tactics: ['Discovery'] },
  T1046: { name: 'Network Service Discovery', tactics: ['Discovery'] },
  // Reconnaissance (pre-compromise, seen in network traffic; never for commands run on the host)
  T1595: { name: 'Active Scanning', tactics: ['Reconnaissance'] },
  // Credential Access
  T1003: { name: 'OS Credential Dumping', tactics: ['Credential Access'] },
  'T1003.001': { name: 'LSASS Memory', tactics: ['Credential Access'] },
  'T1003.002': { name: 'Security Account Manager', tactics: ['Credential Access'] },
  'T1003.003': { name: 'NTDS', tactics: ['Credential Access'] },
  'T1003.008': { name: '/etc/passwd and /etc/shadow', tactics: ['Credential Access'] },
  'T1552.001': { name: 'Credentials In Files', tactics: ['Credential Access'] },
  'T1555.004': { name: 'Windows Credential Manager', tactics: ['Credential Access'] },
  T1110: { name: 'Brute Force', tactics: ['Credential Access'] },
  'T1110.004': { name: 'Credential Stuffing', tactics: ['Credential Access'] },
  // Execution
  T1059: { name: 'Command and Scripting Interpreter', tactics: ['Execution'] },
  'T1059.001': { name: 'PowerShell', tactics: ['Execution'] },
  'T1059.003': { name: 'Windows Command Shell', tactics: ['Execution'] },
  'T1059.004': { name: 'Unix Shell', tactics: ['Execution'] },
  'T1059.006': { name: 'Python', tactics: ['Execution'] },
  // Persistence / Privilege Escalation
  'T1053.003': { name: 'Cron', tactics: ['Execution', ...P_PE] },
  'T1053.005': { name: 'Scheduled Task', tactics: ['Execution', ...P_PE] },
  'T1543.002': { name: 'Systemd Service', tactics: P_PE },
  'T1543.003': { name: 'Windows Service', tactics: P_PE },
  T1098: { name: 'Account Manipulation', tactics: P_PE },
  'T1098.004': { name: 'SSH Authorized Keys', tactics: P_PE },
  'T1136.001': { name: 'Local Account', tactics: ['Persistence'] },
  'T1547.001': { name: 'Registry Run Keys / Startup Folder', tactics: P_PE },
  'T1548.001': { name: 'Setuid and Setgid', tactics: ['Privilege Escalation'] },
  // Stealth / Defense Impairment (v20)
  T1027: { name: 'Obfuscated Files or Information', tactics: ['Stealth'] },
  'T1070.003': { name: 'Clear Command History', tactics: ['Stealth'] },
  T1690: { name: 'Prevent Command History Logging', tactics: ['Defense Impairment'] },
  'T1222.001': { name: 'Windows Permissions', tactics: ['Defense Impairment'] },
  'T1222.002': { name: 'Linux and Mac Permissions', tactics: ['Defense Impairment'] },
  T1685: { name: 'Disable or Modify Tools', tactics: ['Defense Impairment'] },
  'T1685.005': { name: 'Clear Windows Event Logs', tactics: ['Defense Impairment'] },
  'T1685.006': { name: 'Clear Linux or Mac System Logs', tactics: ['Defense Impairment'] },
  T1686: { name: 'Disable or Modify System Firewall', tactics: ['Defense Impairment'] },
  // Command and Control
  T1105: { name: 'Ingress Tool Transfer', tactics: ['Command and Control'] },
  T1095: { name: 'Non-Application Layer Protocol', tactics: ['Command and Control'] },
  T1071: { name: 'Application Layer Protocol', tactics: ['Command and Control'] },
  // Initial Access / Lateral Movement / Exfiltration / Impact
  T1190: { name: 'Exploit Public-Facing Application', tactics: ['Initial Access'] },
  T1021: { name: 'Remote Services', tactics: ['Lateral Movement'] },
  T1048: { name: 'Exfiltration Over Alternative Protocol', tactics: ['Exfiltration'] },
  T1485: { name: 'Data Destruction', tactics: ['Impact'] },
  T1486: { name: 'Data Encrypted for Impact', tactics: ['Impact'] },
  T1490: { name: 'Inhibit System Recovery', tactics: ['Impact'] },
  T1496: { name: 'Resource Hijacking', tactics: ['Impact'] },
  T1498: { name: 'Network Denial of Service', tactics: ['Impact'] },
})

/** {id, name, tactics} for a registered id; throws for an id that is not in the verified table. */
function t(id) {
  const entry = TECHNIQUES[id]
  if (!entry) throw new Error(`ATT&CK technique ${id} is not in the verified table (utils/attackTechniques.js)`)
  return Object.freeze({ id, name: entry.name, tactics: Object.freeze([...entry.tactics]) })
}

/** Tactics for a stored technique (records persist {id, name}); [] for an unknown id. */
function tacticsFor(id) {
  return TECHNIQUES[id] ? [...TECHNIQUES[id].tactics] : []
}

/** A stored {id, name} technique with its tactics attached (for API responses). */
function withTactics(tech) {
  if (!tech || typeof tech.id !== 'string') return tech
  return { id: tech.id, name: tech.name, tactics: tacticsFor(tech.id) }
}

module.exports = { ATTACK_VERSION, TACTICS, TECHNIQUES, t, tacticsFor, withTactics }
