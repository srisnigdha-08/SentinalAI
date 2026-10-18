'use strict'

const SECRET_KEYS =
  /password|passphrase|private.?key|replica.?key|credential|secret|token|api.?key|sentinel.?key|authorization|cookie/i

function redact(value, key = '') {
  if (SECRET_KEYS.test(key)) return '[REDACTED]'
  if (typeof value === 'string') {
    let safe = value.replace(/((?:mongodb(?:\+srv)?|https?):\/\/)[^\s/@]+:[^\s/@]+@/gi, '$1[REDACTED]@')
    safe = safe.replace(/eyJ[A-Za-z0-9_-]+(?:\.|%2e)[A-Za-z0-9_-]+(?:\.|%2e)[A-Za-z0-9_-]{16,}/gi, '[JWT REDACTED]')
    safe = safe.replace(
      /([?&](?:[\w-]*(?:password|secret|token|credential|api[_-]?key|authorization)[\w-]*)=)[^&\s#]*/gi,
      '$1[REDACTED]'
    )
    for (const [name, secret] of Object.entries(process.env)) {
      if (SECRET_KEYS.test(name) && secret && secret.length >= 8) safe = safe.split(secret).join('[REDACTED]')
    }
    return safe.replace(/(Bearer\s+)[^\s"']+/gi, '$1[REDACTED]')
  }
  if (Array.isArray(value)) return value.map((item) => redact(item))
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redact(item, name)]))
  return value
}

const IPV4_REGEX = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b/g
const IPV6_REGEX = /\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,6}):[0-9a-fA-F]{1,4}\b/g

function isPrivilegedRole(role) {
  return role === 'admin' || role === 'analyst'
}

function redactIP(ip) {
  if (typeof ip !== 'string' || !ip.trim()) return ip
  const trimmed = ip.trim()

  // IPv4 masking: replace last octet with 'xxx'
  if (/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}$/.test(trimmed)) {
    return trimmed.replace(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}$/, '$1xxx')
  }

  // IPv6 masking: replace last segment with 'xxxx'
  if (trimmed.includes(':')) {
    if (trimmed.endsWith('::')) return trimmed.slice(0, -2) + '::xxxx'
    const parts = trimmed.split(':')
    if (parts.length > 1) {
      parts[parts.length - 1] = 'xxxx'
      return parts.join(':')
    }
  }

  return trimmed
}

function redactTextWithIPs(text) {
  if (typeof text !== 'string') return text
  return text
    .replace(IPV4_REGEX, '$1xxx')
    .replace(IPV6_REGEX, '$1:xxxx')
}

function toPlainObject(doc) {
  if (!doc) return doc
  if (typeof doc.toObject === 'function') return doc.toObject()
  if (typeof doc.toJSON === 'function') return doc.toJSON()
  return JSON.parse(JSON.stringify(doc))
}

function redactThreat(threat, role = 'viewer') {
  if (!threat) return threat
  if (isPrivilegedRole(role)) return threat

  const clean = toPlainObject(threat)
  if (clean.sourceIP) {
    clean.sourceIP = redactIP(clean.sourceIP)
  }
  if (clean.destinationIP) {
    clean.destinationIP = redactIP(clean.destinationIP)
  }
  if (clean.payload !== undefined && clean.payload !== null) {
    clean.payload = '[REDACTED_PAYLOAD]'
  }
  if (clean.payloadHash !== undefined && clean.payloadHash !== null) {
    clean.payloadHash = '[REDACTED_HASH]'
  }
  if (clean.rawPacket !== undefined && clean.rawPacket !== null) {
    clean.rawPacket = '[REDACTED_PACKET]'
  }
  return clean
}

function redactHoneypotSession(session, role = 'viewer') {
  if (!session) return session
  if (isPrivilegedRole(role)) return session

  const clean = toPlainObject(session)
  if (clean.sourceIP) {
    clean.sourceIP = redactIP(clean.sourceIP)
  }
  if (clean.command !== undefined && clean.command !== null) {
    clean.command = '[REDACTED_COMMAND]'
  }
  if (clean.url !== undefined && clean.url !== null) {
    clean.url = redactTextWithIPs(clean.url)
  }
  if (Array.isArray(clean.commands)) {
    clean.commands = clean.commands.map((cmd) => {
      const c = typeof cmd === 'object' && cmd !== null ? { ...cmd } : { command: cmd }
      c.command = '[REDACTED_COMMAND]'
      if (c.input) c.input = '[REDACTED_COMMAND]'
      if (c.output) c.output = '[REDACTED_OUTPUT]'
      return c
    })
  }
  if (Array.isArray(clean.credentials)) {
    clean.credentials = clean.credentials.map((cred) => ({
      success: Boolean(cred?.success),
    }))
  } else if (clean.credentials && typeof clean.credentials === 'object') {
    clean.credentials = {
      username: clean.credentials.username ? '[REDACTED_USER]' : 'unknown',
      password: '[REDACTED_CREDENTIAL]',
      success: Boolean(clean.credentials.success),
    }
  }
  if (Array.isArray(clean.credentialsUsed)) {
    clean.credentialsUsed = clean.credentialsUsed.map((cred) => ({
      success: Boolean(cred?.success),
    }))
  } else if (clean.credentialsUsed && typeof clean.credentialsUsed === 'object') {
    clean.credentialsUsed = {
      username: clean.credentialsUsed.username ? '[REDACTED_USER]' : 'unknown',
      password: '[REDACTED_CREDENTIAL]',
      success: Boolean(clean.credentialsUsed.success),
    }
  }
  if (clean.iocExtracted && typeof clean.iocExtracted === 'object') {
    clean.iocExtracted = {
      ips: Array.isArray(clean.iocExtracted.ips) ? clean.iocExtracted.ips.map(redactIP) : [],
      urls: Array.isArray(clean.iocExtracted.urls) ? clean.iocExtracted.urls.map(redactTextWithIPs) : [],
      hashes: Array.isArray(clean.iocExtracted.hashes) ? clean.iocExtracted.hashes.map(() => '[REDACTED_HASH]') : [],
    }
  }
  if (Array.isArray(clean.malwareDownloaded)) {
    clean.malwareDownloaded = clean.malwareDownloaded.map(redactTextWithIPs)
  }
  if (Array.isArray(clean.filesAccessed)) {
    clean.filesAccessed = clean.filesAccessed.map(() => '[REDACTED_FILE]')
  }
  return clean
}

function redactCampaign(campaign, role = 'viewer') {
  if (!campaign) return campaign
  if (isPrivilegedRole(role)) return campaign

  const clean = toPlainObject(campaign)
  if (clean.sourceIP) clean.sourceIP = redactIP(clean.sourceIP)
  if (clean.attackerIP) clean.attackerIP = redactIP(clean.attackerIP)

  if (Array.isArray(clean.sourceIPs)) {
    clean.sourceIPs = clean.sourceIPs.map(redactIP)
  }
  if (Array.isArray(clean.relatedIPs)) {
    clean.relatedIPs = clean.relatedIPs.map(redactIP)
  }
  if (Array.isArray(clean.targetIPs)) {
    clean.targetIPs = clean.targetIPs.map(redactIP)
  }
  if (Array.isArray(clean.sessions)) {
    clean.sessions = clean.sessions.map((s) => redactHoneypotSession(s, role))
  }
  if (Array.isArray(clean.memberSessions)) {
    clean.memberSessions = clean.memberSessions.map((s) => redactHoneypotSession(s, role))
  }
  return clean
}

function redactAIPrediction(prediction, role = 'viewer') {
  if (!prediction) return prediction
  if (isPrivilegedRole(role)) return prediction

  const clean = toPlainObject(prediction)
  if (clean.sourceIP) {
    clean.sourceIP = redactIP(clean.sourceIP)
  }
  if (clean.targetIP) {
    clean.targetIP = redactIP(clean.targetIP)
  }
  if (clean.payload !== undefined && clean.payload !== null) {
    clean.payload = '[REDACTED_PAYLOAD]'
  }
  if (clean.rawFeatures !== undefined && clean.rawFeatures !== null) {
    clean.rawFeatures = '[REDACTED_FEATURES]'
  }
  if (clean.generatedThreat && typeof clean.generatedThreat === 'object') {
    if (clean.generatedThreat.sourceIP) {
      clean.generatedThreat.sourceIP = redactIP(clean.generatedThreat.sourceIP)
    }
  }
  return clean
}

function redactAlert(alert, role = 'viewer') {
  if (!alert) return alert
  if (isPrivilegedRole(role)) return alert

  const clean = toPlainObject(alert)
  if (clean.message) {
    clean.message = redactTextWithIPs(clean.message)
  }
  if (clean.title) {
    clean.title = redactTextWithIPs(clean.title)
  }
  return clean
}

function redactSystemHealth(health, role = 'viewer') {
  if (!health) return health
  if (isPrivilegedRole(role)) return health

  return {
    mode: health.mode || 'REAL_MODE',
    status: 'ok',
    timestamp: new Date().toISOString(),
  }
}

function redactCapturedCredentials(credentials) {
  if (!Array.isArray(credentials)) return []
  return credentials.map((cred) => ({
    username: typeof cred?.username === 'string' ? cred.username.slice(0, 100) : '',
    password: '***REDACTED***',
    success: Boolean(cred?.success),
  }))
}

redact.redact = redact
redact.isPrivilegedRole = isPrivilegedRole
redact.redactIP = redactIP
redact.redactTextWithIPs = redactTextWithIPs
redact.redactThreat = redactThreat
redact.redactHoneypotSession = redactHoneypotSession
redact.redactCampaign = redactCampaign
redact.redactAIPrediction = redactAIPrediction
redact.redactAlert = redactAlert
redact.redactSystemHealth = redactSystemHealth
redact.redactCapturedCredentials = redactCapturedCredentials

module.exports = redact
