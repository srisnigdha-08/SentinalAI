const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const Session = require('../../models/AuthSession')
const records = new Map()
function accessToken(user, seconds = 900) {
  const id = String(user._id)
  const sid = crypto.randomUUID()
  const now = Math.floor(Date.now() / 1000)
  records.set(sid, {
    _id: sid,
    user: id,
    authVersion: user.authVersion ?? 0,
    generation: 0,
    revokedAt: null,
    expiresAt: new Date(Date.now() + 30 * 86400000),
    refreshHash: 'unit-only-hash',
  })
  Session.findById.mockImplementation((key) => ({
    select: async () => records.get(key),
    then: (resolve, reject) => Promise.resolve(records.get(key)).then(resolve, reject),
  }))
  return jwt.sign(
    {
      id,
      role: user.role,
      sid,
      av: user.authVersion ?? 0,
      purpose: 'access',
      jti: crypto.randomBytes(32).toString('hex'),
      iat: now,
      exp: now + seconds,
    },
    process.env.JWT_SECRET,
    { algorithm: 'HS256', issuer: 'sentinelai', audience: 'sentinelai-browser' }
  )
}
module.exports = { accessToken }
