const crypto = require('crypto')
const { AuthError, REFRESH_SECONDS } = require('../services/authSessionService')
function clientOrigin() {
  try {
    return new URL(process.env.CLIENT_URL || 'http://localhost:3000').origin
  } catch {
    throw new AuthError('Invalid client origin configuration', 503)
  }
}
function allowedOrigins() {
  const origin = clientOrigin()
  const result = [origin]
  const url = new URL(origin)
  if (process.env.NODE_ENV !== 'production' && ['localhost', '127.0.0.1'].includes(url.hostname)) {
    url.hostname = url.hostname === 'localhost' ? '127.0.0.1' : 'localhost'
    result.push(url.origin)
  }
  return result
}
function policy() {
  const url = new URL(clientOrigin())
  if (process.env.NODE_ENV === 'production' && url.protocol !== 'https:')
    throw new AuthError('Production client origin must use HTTPS', 503)
  const secure = process.env.NODE_ENV === 'production' || url.protocol === 'https:'
  if (!secure && !['localhost', '127.0.0.1'].includes(url.hostname))
    throw new AuthError('Insecure cookie transport is limited to loopback development', 503)
  return { httpOnly: true, secure, sameSite: 'strict', path: '/api/auth' }
}
const names = () =>
  policy().secure
    ? { refresh: '__Secure-sentinel_refresh', csrf: '__Secure-sentinel_csrf' }
    : { refresh: 'sentinel_refresh_v2', csrf: 'sentinel_csrf_v2' }
function cookie(req, name) {
  const values = (req.headers.cookie || '')
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.startsWith(name + '='))
  if (values.length !== 1) return null
  try {
    return decodeURIComponent(values[0].slice(name.length + 1))
  } catch {
    return null
  }
}
const refreshCookie = (req) => cookie(req, names().refresh)
function setRefresh(res, token) {
  res.cookie(names().refresh, token, {
    ...policy(),
    maxAge: Math.max(0, require('jsonwebtoken').decode(token).exp * 1000 - Date.now()),
  })
}
function clearCookies(res) {
  res.clearCookie(names().refresh, policy())
  res.clearCookie(names().csrf, policy())
}
function csrfSignature(nonce) {
  return crypto
    .createHmac('sha256', process.env.JWT_REFRESH_SECRET)
    .update('sentinel-csrf-v2:' + nonce)
    .digest('hex')
}
function getCsrf(req, res, next) {
  try {
    if (req.headers.origin && !allowedOrigins().includes(req.headers.origin))
      throw new AuthError('Origin rejected', 403)
    if (req.headers['sec-fetch-site'] === 'cross-site') throw new AuthError('Origin rejected', 403)
    const nonce = crypto.randomBytes(32).toString('hex')
    res.set('Cache-Control', 'no-store')
    res.cookie(names().csrf, nonce, { ...policy(), maxAge: REFRESH_SECONDS * 1000 })
    res.json({ success: true, data: { csrfToken: nonce + '.' + csrfSignature(nonce) } })
  } catch (error) {
    next(error)
  }
}
function protectMutation(req, res, next) {
  try {
    if (!allowedOrigins().includes(req.headers.origin)) throw new AuthError('Origin rejected', 403)
    const nonce = cookie(req, names().csrf)
    const value = req.headers['x-csrf-token']
    const expected = nonce && nonce + '.' + csrfSignature(nonce)
    if (
      !nonce ||
      !/^[0-9a-f]{64}$/.test(nonce) ||
      typeof value !== 'string' ||
      Buffer.byteLength(value) !== Buffer.byteLength(expected) ||
      !crypto.timingSafeEqual(Buffer.from(value), Buffer.from(expected))
    )
      throw new AuthError('CSRF verification failed', 403)
    res.set('Cache-Control', 'no-store')
    next()
  } catch (error) {
    next(error)
  }
}
module.exports = { allowedOrigins, policy, names, refreshCookie, setRefresh, clearCookies, getCsrf, protectMutation }
