const jwt = require('jsonwebtoken')
const redact = require('../utils/redact')
test('standalone and percent-dot JWTs never survive free-text or query log redaction', () => {
  const token = jwt.sign({ probe: 'offline-test' }, 'non-secret-offline-signing-fixture')
  for (const value of [token, token.replace(/\./g, '%2E')]) {
    const result = redact('request token ' + value)
    expect(result).not.toContain(value)
    expect(result).toContain('REDACTED')
  }
})
test.each(['password', 'refresh_token', 'api-key', 'authorization', 'secret'])(
  'redacts credential query parameter %s while preserving safe context',
  (name) => {
    expect(redact('GET /probe?' + name + '=private-probe-value&page=2')).toBe(
      'GET /probe?' + name + '=[REDACTED]&page=2'
    )
  }
)
test('redacts HTTP and MongoDB URL credentials including exported command text', () => {
  const value = redact(
    'curl https://user:private-probe-value@example.invalid/file mongodb://user:private-probe-value@localhost/db'
  )
  expect(value).not.toContain('private-probe-value')
  expect(value).toContain('example.invalid/file')
})

test('private key, passphrase and captured credential objects are masked before logging', () => {
  expect(
    redact({
      privateKey: 'unit-private-material',
      passphrase: 'unit-passphrase',
      credentials: [{ username: 'unit-user', password: 'unit-password' }],
    })
  ).toEqual({ privateKey: '[REDACTED]', passphrase: '[REDACTED]', credentials: '[REDACTED]' })
})
