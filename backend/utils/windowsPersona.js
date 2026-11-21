'use strict'

/**
 * Rank 7/8: the experimental simulated Windows persona (windows_srv, honeypot/windows_persona). Intent and ATT&CK
 * rules for Windows-style commands; mirrors honeypot/windows_persona/telemetry.py (a shared corpus test keeps both in
 * step). The simulator executed nothing: these describe what an attacker attempted against a simulated shell.
 *
 * Both rule sets are persona-gated: intents only for sessions served as windows_srv (intentForSession) and techniques
 * only through mitreMapping.getMitreTechniquesForCommands(..., { persona: 'windows_srv' }).
 */
const { t } = require('./attackTechniques')

const WINDOWS_PERSONA = 'windows_srv'

// Same start anchor idea as mitreMapping.js: a command at the beginning of a segment, optionally after cmd /c or
// powershell [-flags].
const S = String.raw`(?:^|[;&|(]\s*)(?:cmd(?:\.exe)?\s+\/c\s+|powershell(?:\.exe)?\s+(?:-\w+\s+)*)?`
const c = (names) => new RegExp(`${S}(?:${names})(?:\\.exe)?(?=\\s|$|[;&|)])`, 'i')

// Rank 8 (F5): PowerShell's encoded-command flag. Required: a powershell invocation and an explicit -enc /
// -EncodedCommand (any unambiguous prefix from -enc on, or the -ec alias). Mirrors telemetry.py ENCODED_PS.
const ENCODED_PS =
  /(?:^|[\s;&|("'])powershell(?:\.exe)?\b[^;&|]*?\s[-/](?:ec|enc(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)\s+["']?([A-Za-z0-9+/=]{8,})/i
const REVERSE_SHELL_PAYLOAD = /tcpclient|invoke-powershelltcp|\$\w+\.getstream\(\)/i
const MAX_DECODED = 16 * 1024
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

/** The decoded script of `powershell -enc <base64>`, or null (no explicit flag, or not valid Base64/UTF-16LE). */
function encodedPowerShell(command) {
  const m = ENCODED_PS.exec(String(command || ''))
  if (!m) return null
  const raw = m[1]
  if (raw.length % 4 !== 0 || raw.length > 4 * MAX_DECODED || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) return null
  const bytes = Buffer.from(raw, 'base64')
  if (bytes.length % 2 !== 0) return null // Python's strict UTF-16LE decode refuses an odd byte count
  const text = bytes.toString('utf16le')
  return LONE_SURROGATE.test(text) ? null : text
}

const INTENT_RULES = [
  [
    'CREDENTIAL_HARVEST',
    /\\config\\(sam|system|security)\b|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)|unattend\.xml|web\.config|administrators_authorized_keys|mimikatz|sekurlsa|ntds\.dit|cmdkey\s+\/list|vaultcmd/i,
  ],
  [
    'MALWARE_DOWNLOAD',
    /certutil(\.exe)?\s+.*-urlcache|bitsadmin(\.exe)?\s+\/transfer|invoke-webrequest|\biwr\b|downloadstring|downloadfile|start-bitstransfer|(curl|wget)(\.exe)?\s+https?:\/\//i,
  ],
  [
    'PRIVILEGE_ESCALATION',
    /net\s+localgroup\s+administrators\s+\S+\s+\/add|runas\s+\/user|whoami\s+\/priv.*sedebug|takeown\s+\/f|icacls\s+.*\/grant/i,
  ],
  [
    'PERSISTENCE',
    /schtasks(\.exe)?\s+\/create|sc(\.exe)?\s+create|reg(\.exe)?\s+add\s+\S*\\run\b|new-service|register-scheduledtask|net\s+user\s+\S+\s+\S*\s*\/add|new-localuser/i,
  ],
  // Rank 8 (F5): plain reverse-shell indicators only; an encoded command needs a reverse-shell payload (below).
  ['REVERSE_SHELL', /nc(at)?(\.exe)?\s+.*-e\s+cmd|system\.net\.sockets\.tcpclient|invoke-powershelltcp/i],
  [
    'RECONNAISSANCE',
    c(
      String.raw`whoami|hostname|ver|systeminfo|ipconfig|netstat|tasklist|net\s+(user|localgroup|share|view|accounts)|sc\s+query|get-computerinfo|get-process|get-service|get-localuser|get-netipaddress|nltest|arp|route\s+print|query\s+user|quser|wmic`
    ),
  ],
  // Rank 8: clearing event logs is defense impairment (T1685.005), not destruction; it keeps its technique only.
  [
    'DESTRUCTION',
    /vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete|del\s+.*(\/s|\/q).*(\/s|\/q)|rd\s+\/s\s+\/q\s+c:\\|format\s+[a-z]:|cipher\s+\/w|remove-item\s+.*-recurse.*-force/i,
  ],
]

// Technique rules for windows_srv sessions only (mitreMapping applies them only for that persona).
const WINDOWS_COMMAND_TECHNIQUES = [
  [c(String.raw`systeminfo|ver|hostname|get-computerinfo|wmic\s+os`), t('T1082')],
  [c(String.raw`whoami|query\s+user|quser`), t('T1033')],
  [c(String.raw`ipconfig|route\s+print|arp|get-netipaddress`), t('T1016')],
  [c('netstat'), t('T1049')],
  [c('tasklist|get-process|ps|gps'), t('T1057')],
  [c(String.raw`sc\s+query|get-service|gsv|net\s+start`), t('T1007')],
  [c(String.raw`net\s+user|get-localuser|net\s+accounts`), t('T1087.001')],
  [c(String.raw`net\s+localgroup|get-localgroup`), t('T1069.001')],
  [c(String.raw`net\s+share|net\s+view`), t('T1135')],
  [c('ping|nltest'), t('T1018')],
  [c('dir|tree|get-childitem|gci|ls'), t('T1083')],
  [/\\config\\(sam|system|security)\b|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)/i, t('T1003.002')],
  [/mimikatz|sekurlsa/i, t('T1003.001')],
  [/ntds\.dit/i, t('T1003.003')],
  [/unattend\.xml|web\.config|administrators_authorized_keys/i, t('T1552.001')],
  [/cmdkey(\.exe)?\s+\/list|vaultcmd/i, t('T1555.004')],
  [
    /certutil(\.exe)?\s+.*-urlcache|bitsadmin(\.exe)?\s+\/transfer|invoke-webrequest|\biwr\b|downloadstring|downloadfile|start-bitstransfer/i,
    t('T1105'),
  ],
  [/(^|[\s;&|(])powershell(\.exe)?\b|invoke-expression|\biex\b/i, t('T1059.001')],
  [/(^|[\s;&|(])cmd(\.exe)?\s+\/[ck]\b/i, t('T1059.003')],
  [ENCODED_PS, t('T1027')],
  [/system\.net\.sockets\.tcpclient|tcpclient\(|invoke-powershelltcp/i, t('T1095')],
  [/schtasks(\.exe)?\s+\/create|register-scheduledtask/i, t('T1053.005')],
  [/sc(\.exe)?\s+create|new-service/i, t('T1543.003')],
  [/reg(\.exe)?\s+add\s+\S*\\run\b/i, t('T1547.001')],
  [/net\s+user\s+\S+\s+\S*\s*\/add|new-localuser/i, t('T1136.001')],
  [/net\s+localgroup\s+administrators\s+\S+\s+\/add/i, t('T1098')],
  [/icacls\s+.*\/grant|takeown\s+\/f/i, t('T1222.001')],
  [/vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete/i, t('T1490')],
  [
    /del\s+.*(\/s|\/q).*(\/s|\/q)|rd\s+\/s\s+\/q\s+c:\\|format\s+[a-z]:|cipher\s+\/w|remove-item\s+.*-recurse.*-force/i,
    t('T1485'),
  ],
  [/wevtutil(\.exe)?\s+cl|clear-eventlog/i, t('T1685.005')],
]

function classifyWindowsIntent(command, depth = 0) {
  const text = String(command || '')
  const decoded = depth === 0 ? encodedPowerShell(text) : null
  for (const [intent, pattern] of INTENT_RULES) {
    if (intent === 'REVERSE_SHELL' && decoded !== null && REVERSE_SHELL_PAYLOAD.test(decoded)) return intent
    if (pattern.test(text)) return intent
  }
  // A benign encoded command is classified by what it decodes to (never as a reverse shell by itself).
  if (decoded !== null) return classifyWindowsIntent(decoded, depth + 1)
  return 'UNKNOWN'
}

/**
 * The intent stored for a command. The Linux intent (collector classifyIntent) wins whenever it found something;
 * the Windows rules are consulted only when it did not AND the session was served as windows_srv. Read-only lookup;
 * any failure keeps the Linux intent.
 */
async function intentForSession(command, sessionId, linuxIntent, lookup = defaultLookup) {
  if (linuxIntent && linuxIntent !== 'UNKNOWN') return linuxIntent
  try {
    const served = await lookup(sessionId)
    return served === WINDOWS_PERSONA ? classifyWindowsIntent(command) : linuxIntent || 'UNKNOWN'
  } catch {
    return linuxIntent || 'UNKNOWN'
  }
}

async function defaultLookup(sessionId) {
  if (!sessionId) return null
  const HoneypotSession = require('../models/HoneypotSession')
  const s = await HoneypotSession.findOne({ sessionId: String(sessionId) })
    .select('servedProfile')
    .lean()
  return s?.servedProfile || null
}

module.exports = {
  WINDOWS_PERSONA,
  WINDOWS_COMMAND_TECHNIQUES,
  ENCODED_PS,
  encodedPowerShell,
  classifyWindowsIntent,
  intentForSession,
}
