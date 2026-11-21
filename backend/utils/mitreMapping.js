/**
 * MITRE ATT&CK Mapping Utility
 * Maps command intents, commands and threat classifications to MITRE ATT&CK techniques (id, name, tactics).
 *
 * Every technique comes from utils/attackTechniques.js (verified against ATT&CK Enterprise v20.1), so ids, names and
 * tactics are official and no rule can reference an invented technique. Rank 8 corrections:
 *  - T1595 Active Scanning (Reconnaissance: probing a victim's infrastructure over the network, pre-compromise) was
 *    used for on-host reconnaissance commands. Commands such as uname, id, whoami and ifconfig are Discovery
 *    (T1082, T1033, T1016) and get those from the command rules; T1595 is kept only for network port scans.
 *  - Intent-level techniques are kept only where they hold for EVERY command that produces the intent; otherwise
 *    the precise per-command technique is used (e.g. `chmod +x` is not T1548, `crontab` is not T1543).
 *  - Windows-style rules apply only to sessions served as the simulated windows_srv persona (persona-gated), so a
 *    Linux session can never acquire a Windows-only technique.
 */
const logger = require('./logger')
const { t } = require('./attackTechniques')

// Intent -> techniques that are true for every command the intent rules can produce. An intent mapped to [] has no
// generic technique: its commands are mapped individually below (getMitreTechniquesForCommands).
const MITRE_ATTACK_MAP = {
  CREDENTIAL_HARVEST: [], // /etc/passwd|shadow -> T1003.008, credential files -> T1552.001, SAM -> T1003.002 ...
  MALWARE_DOWNLOAD: [t('T1105')], // every trigger downloads a file (wget/curl URL, certutil, bitsadmin, iwr)
  REVERSE_SHELL: [t('T1059')], // every trigger starts an interpreter; raw-socket channels add T1095 per command
  PERSISTENCE: [], // crontab -> T1053.003, systemctl enable -> T1543.002, schtasks -> T1053.005 ...
  PRIVILEGE_ESCALATION: [], // setuid bits -> T1548.001; plain chmod -> T1222.002 (not privilege escalation)
  RECONNAISSANCE: [], // on-host discovery: uname -> T1082, id/whoami -> T1033, ifconfig -> T1016 (never T1595)
  DESTRUCTION: [], // recursive wipes of system/user trees -> T1485; vssadmin delete shadows -> T1490 (per command)
}

const THREAT_MITRE_MAP = {
  'SSH Brute Force': [t('T1110')],
  'SSH Intrusion Attempt': [t('T1110'), t('T1021')],
  'SQL Injection': [t('T1190')],
  DDoS: [t('T1498')],
  // A port scan is observed as network traffic: Active Scanning when it comes from outside (Reconnaissance), Network
  // Service Discovery when a compromised host scans (Discovery). A flow cannot tell which, so both are candidates.
  'Port Scan': [t('T1595'), t('T1046')],
  'RCE Attempt': [t('T1190')],
  'XSS Attempt': [t('T1190')],
  'Malware Beacon': [t('T1071')],
  'Credential Stuffing': [t('T1110.004')],
  Ransomware: [t('T1486')],
  'Lateral Movement': [t('T1021')],
  'Data Exfiltration': [t('T1048')],
  'Zero-Day Exploit': [t('T1190')],
}

// Per-command techniques (Phase 5): finer than the intent map, e.g. T1003.008 rather than T1003. "Start" anchors
// a pattern at the beginning of a command segment (after ; & | or a subshell), so "id" does not match "hidden".
const START = String.raw`(?:^|[;&|(\x60]\s*|\$\(\s*)(?:sudo\s+|busybox\s+)?`
const cmd = (names) => new RegExp(`${START}(?:${names})(?:\\s|$|[;&|)])`, 'i')
const COMMAND_TECHNIQUES = [
  [cmd('uname|hostnamectl|lscpu|nproc|free|lsb_release'), t('T1082')],
  [/cat\s+\/proc\/(cpuinfo|version|meminfo)/i, t('T1082')],
  [cmd('whoami|id|who|w|last'), t('T1033')],
  [cmd('ifconfig|netstat|ss|route|arp'), t('T1016')],
  [/(^|[;&|]\s*)ip\s+(a|addr|r|route)\b/i, t('T1016')],
  [cmd('ps|top|pstree'), t('T1057')],
  [cmd('wget|curl|tftp|ftpget'), t('T1105')],
  [/\/etc\/(passwd|shadow)\b/i, t('T1003.008')],
  [/\.aws\/credentials|\.ssh\/id_rsa\b|\.git-credentials/i, t('T1552.001')],
  [/crontab|\/etc\/cron/i, t('T1053.003')],
  [/systemctl\s+(enable|start)|\/etc\/systemd\//i, t('T1543.002')],
  [/\b(bash|sh)\s+-i\b|\/dev\/tcp\//i, t('T1059.004')],
  [/\bpython[0-9.]*\s+-c\b/i, t('T1059.006')],
  // Raw TCP/UDP reverse-shell channels (not an application-layer protocol).
  [/\/dev\/(tcp|udp)\/|\bnc(at)?\s+[^;&|]*\s-e\s/i, t('T1095')],
  [/\bchmod\s+(\+x|[0-7]*[1357][0-7]*\s)/i, t('T1222.002')],
  [/\bchmod\s+([ugoa]*\+[rwx]*s|[2467][0-7]{3}\s)|\bsetuid\b/i, t('T1548.001')],
  [/history\s+-c|\.bash_history/i, t('T1070.003')],
  [/unset\s+HISTFILE|HISTSIZE=0|HISTFILESIZE=0/i, t('T1690')],
  [/authorized_keys/i, t('T1098.004')],
  [cmd('useradd|adduser'), t('T1136.001')],
  [/iptables\s+-F|ufw\s+disable/i, t('T1686')],
  [/setenforce\s+0/i, t('T1685')],
  // Clearing Linux system logs: deleting, shredding or truncating files under /var/log, or vacuuming the journal.
  // Reading a log (cat/tail/grep /var/log/...) and appending to one (>>) are not clearing and are not mapped.
  [
    /\b(rm|shred|truncate|unlink)\b[^;&|]*\/var\/log\b|(^|[^>])>\s*\/var\/log\/|\bjournalctl\b[^;&|]*--vacuum-/i,
    t('T1685.006'),
  ],
  [/xmrig|minerd|stratum\+tcp/i, t('T1496')],
  // Recursive deletion of the root or of system/user trees. `rm -rf /tmp/x` (often clean-up) is deliberately not
  // mapped: deleting one's own files is not evidence of data destruction.
  [
    /\brm\s+(-[a-z]*\s+)*-[a-z]*r[a-z]*\s+(-[a-z]+\s+)*(\/|\/\*|~|\/(home|root|etc|var|boot|usr|opt|srv)\/?)(\s|$|;)/i,
    t('T1485'),
  ],
]

// Windows-style command rules (the simulated windows_srv shell, utils/windowsPersona.js). Applied ONLY when the
// session's persona is windows_srv (see getMitreTechniquesForCommands), never to Linux sessions.
const WINDOWS_PERSONA = 'windows_srv'
const windowsRules = () => require('./windowsPersona').WINDOWS_COMMAND_TECHNIQUES

const strip = (tech) => ({ id: tech.id, name: tech.name, tactics: [...tech.tactics] })

/**
 * Techniques for a list of command strings, first occurrence order, de-duplicated by id.
 * opts.persona: the persona that served the session; Windows-style rules apply only for windows_srv.
 */
function getMitreTechniquesForCommands(commands, opts = {}) {
  const rules = opts.persona === WINDOWS_PERSONA ? [...COMMAND_TECHNIQUES, ...windowsRules()] : COMMAND_TECHNIQUES
  const techniques = []
  const seen = new Set()
  for (const command of commands || []) {
    const text = String(command || '')
    for (const [pattern, tech] of rules) {
      if (!seen.has(tech.id) && pattern.test(text)) {
        seen.add(tech.id)
        techniques.push(strip(tech))
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
          techniques.push(strip(tech))
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
  return mappings.map(strip)
}

/**
 * Intent techniques plus per-command techniques for a session's commands ({command, intent}).
 * opts.persona: the session's served persona (Windows-style rules only for windows_srv).
 */
function getMitreTechniquesForSession(commands = [], opts = {}) {
  const merged = [...getMitreTechniquesForIntents(commands.map((c) => c.intent).filter(Boolean))]
  const seen = new Set(merged.map((tech) => tech.id))
  for (const tech of getMitreTechniquesForCommands(
    commands.map((c) => c.command),
    opts
  )) {
    if (!seen.has(tech.id)) {
      seen.add(tech.id)
      merged.push(tech)
    }
  }
  return merged
}

/** Stored form ({id, name}): records keep their existing shape; tactics are derived from the id when read. */
const storedForm = (techniques) => (techniques || []).map((tech) => ({ id: tech.id, name: tech.name }))

module.exports = {
  MITRE_ATTACK_MAP,
  THREAT_MITRE_MAP,
  COMMAND_TECHNIQUES,
  WINDOWS_PERSONA,
  getMitreTechniquesForIntents,
  getMitreTechniquesForCommands,
  getMitreTechniquesForSession,
  getMitreTechniquesForThreat,
  storedForm,
}
