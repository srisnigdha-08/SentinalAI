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
module.exports = redact
