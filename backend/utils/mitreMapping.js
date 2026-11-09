/**
 * MITRE ATT&CK Mapping Utility
 * Maps command intents and threat classifications to MITRE technique IDs and names.
 */
const logger = require('./logger')

const MITRE_ATTACK_MAP = {
  CREDENTIAL_HARVEST: [{ id: 'T1003', name: 'OS Credential Dumping' }],
  MALWARE_DOWNLOAD: [{ id: 'T1105', name: 'Ingress Tool Transfer' }],
  REVERSE_SHELL: [
    { id: 'T1059', name: 'Command and Scripting Interpreter' },
    { id: 'T1071', name: 'Application Layer Protocol' },
  ],
  PERSISTENCE: [
    { id: 'T1543', name: 'Create or Modify System Process' },
    { id: 'T1053', name: 'Scheduled Task/Job' },
  ],
  PRIVILEGE_ESCALATION: [{ id: 'T1548', name: 'Abuse Elevation Control Mechanism' }],
  RECONNAISSANCE: [{ id: 'T1595', name: 'Active Scanning' }],
  DESTRUCTION: [{ id: 'T1485', name: 'Data Destruction' }],
}

const THREAT_MITRE_MAP = {
  'SSH Brute Force': [{ id: 'T1110', name: 'Brute Force' }],
  'SSH Intrusion Attempt': [
    { id: 'T1110', name: 'Brute Force' },
    { id: 'T1021', name: 'Remote Services' },
  ],
  'SQL Injection': [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
  DDoS: [{ id: 'T1498', name: 'Network Denial of Service' }],
  'Port Scan': [{ id: 'T1046', name: 'Network Service Discovery' }],
  'RCE Attempt': [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
  'XSS Attempt': [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
  'Malware Beacon': [{ id: 'T1071', name: 'Application Layer Protocol' }],
  'Credential Stuffing': [{ id: 'T1110', name: 'Brute Force' }],
  Ransomware: [{ id: 'T1486', name: 'Data Encrypted for Impact' }],
  'Lateral Movement': [{ id: 'T1021', name: 'Remote Services' }],
  'Data Exfiltration': [{ id: 'T1048', name: 'Exfiltration Over Alternative Protocol' }],
  'Zero-Day Exploit': [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
}

// Per-command techniques (Phase 5): finer than the intent map, e.g. T1003.008 rather than T1003. "Start" anchors
// a pattern at the beginning of a command segment (after ; & | or a subshell), so "id" does not match "hidden".
const START = String.raw`(?:^|[;&|(\x60]\s*|\$\(\s*)(?:sudo\s+|busybox\s+)?`
const cmd = (names) => new RegExp(`${START}(?:${names})(?:\\s|$|[;&|)])`, 'i')
const COMMAND_TECHNIQUES = [
  [cmd('uname|hostnamectl|lscpu|nproc|free|lsb_release'), { id: 'T1082', name: 'System Information Discovery' }],
  [/cat\s+\/proc\/(cpuinfo|version|meminfo)/i, { id: 'T1082', name: 'System Information Discovery' }],
  [cmd('whoami|id|who|w|last'), { id: 'T1033', name: 'System Owner/User Discovery' }],
  [cmd('ifconfig|netstat|ss|route|arp'), { id: 'T1016', name: 'System Network Configuration Discovery' }],
  [/(^|[;&|]\s*)ip\s+(a|addr|r|route)\b/i, { id: 'T1016', name: 'System Network Configuration Discovery' }],
  [cmd('ps|top|pstree'), { id: 'T1057', name: 'Process Discovery' }],
  [cmd('wget|curl|tftp|ftpget'), { id: 'T1105', name: 'Ingress Tool Transfer' }],
  [/\/etc\/(passwd|shadow)\b/i, { id: 'T1003.008', name: '/etc/passwd and /etc/shadow' }],
  [/\.aws\/credentials|\.ssh\/id_rsa\b|\.git-credentials/i, { id: 'T1552.001', name: 'Credentials In Files' }],
  [/crontab|\/etc\/cron/i, { id: 'T1053.003', name: 'Cron' }],
  [/systemctl\s+(enable|start)|\/etc\/systemd\//i, { id: 'T1543.002', name: 'Systemd Service' }],
  [/\b(bash|sh)\s+-i\b|\/dev\/tcp\//i, { id: 'T1059.004', name: 'Unix Shell' }],
  [/\bpython[0-9.]*\s+-c\b/i, { id: 'T1059.006', name: 'Python' }],
  [
    /\bchmod\s+(\+x|[0-7]*[1357][0-7]*\s)/i,
    { id: 'T1222.002', name: 'Linux and Mac File and Directory Permissions Modification' },
  ],
  [/history\s+-c|unset\s+HISTFILE|\.bash_history/i, { id: 'T1070.003', name: 'Clear Command History' }],
  [/authorized_keys/i, { id: 'T1098.004', name: 'SSH Authorized Keys' }],
  [cmd('useradd|adduser'), { id: 'T1136.001', name: 'Local Account' }],
  [/iptables\s+-F|ufw\s+disable|setenforce\s+0/i, { id: 'T1562.004', name: 'Disable or Modify System Firewall' }],
  [/xmrig|minerd|stratum\+tcp/i, { id: 'T1496', name: 'Resource Hijacking' }],
]

/** Techniques for a list of command strings, first occurrence order, de-duplicated by id. */
function getMitreTechniquesForCommands(commands) {
  const techniques = []
  const seen = new Set()
  for (const command of commands || []) {
    const text = String(command || '')
    for (const [pattern, tech] of COMMAND_TECHNIQUES) {
      if (!seen.has(tech.id) && pattern.test(text)) {
        seen.add(tech.id)
        techniques.push(tech)
      }
    }
  }
  return techniques
}

function getMitreTechniquesForIntents(intents) {
  const techniques = []
  const seen = new Set()

  for (const intent of intents) {
    if (!intent || intent === 'UNKNOWN') continue
    const mappings = MITRE_ATTACK_MAP[intent]
    if (mappings) {
      for (const tech of mappings) {
        if (!seen.has(tech.id)) {
          seen.add(tech.id)
          techniques.push(tech)
        }
      }
    } else {
      logger.warn(`[MITRE Mapping] No MITRE technique mapping found for intent: "${intent}"`)
    }
  }
  return techniques
}

function getMitreTechniquesForThreat(attackType) {
  if (!attackType || attackType === 'Unknown') return []
  const mappings = THREAT_MITRE_MAP[attackType]
  if (!mappings) {
    logger.warn(`[MITRE Mapping] No MITRE technique mapping found for threat attackType: "${attackType}"`)
    return []
  }
  return mappings
}

/** Intent techniques plus per-command techniques for a session's commands ({command, intent}). */
function getMitreTechniquesForSession(commands = []) {
  const merged = [...getMitreTechniquesForIntents(commands.map((c) => c.intent).filter(Boolean))]
  const seen = new Set(merged.map((t) => t.id))
  for (const tech of getMitreTechniquesForCommands(commands.map((c) => c.command))) {
    if (!seen.has(tech.id)) {
      seen.add(tech.id)
      merged.push(tech)
    }
  }
  return merged
}

module.exports = {
  MITRE_ATTACK_MAP,
  THREAT_MITRE_MAP,
  COMMAND_TECHNIQUES,
  getMitreTechniquesForIntents,
  getMitreTechniquesForCommands,
  getMitreTechniquesForSession,
  getMitreTechniquesForThreat,
}
