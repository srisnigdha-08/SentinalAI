const net = require('node:net')
const { ConfigurationError } = require('./validateEnv')
function topology(env = process.env) {
  const environment = env.NODE_ENV || 'development'
  if (!['development', 'production', 'test'].includes(environment))
    throw new ConfigurationError('NODE_ENV must be development, production or test')
  const mode = env.AUTH_REVOCATION_MODE || (environment === 'production' ? null : 'single')
  if (!['single', 'mongo-stream'].includes(mode))
    throw new ConfigurationError('AUTH_REVOCATION_MODE must explicitly be single or mongo-stream in production')
  const counts = [env.API_WORKERS, env.WEB_CONCURRENCY].filter((value) => value !== undefined)
  if (counts.some((value) => !/^[1-9][0-9]*$/.test(value)))
    throw new ConfigurationError('Worker count must be a positive integer')
  const multi =
    counts.some((value) => Number(value) > 1) || env.NODE_APP_INSTANCE !== undefined || require('node:cluster').isWorker
  if (multi && mode !== 'mongo-stream')
    throw new ConfigurationError('Multiple API workers require mongo-stream revocation; no single-process fallback')
  return { environment, mode }
}
function trustedProxy(env = process.env) {
  const value = env.TRUST_PROXY || '0'
  if (value === '0') return false
  if (value === '1' && env.NODE_ENV !== 'production') return 1
  const addresses = value.split(',').map((address) => address.trim())
  if (
    !addresses.every((address) => {
      const parts = address.split('/')
      const family = net.isIP(parts[0])
      return (
        family &&
        !['0.0.0.0', '::'].includes(parts[0]) &&
        (parts.length === 1 ||
          (parts.length === 2 &&
            /^\d+$/.test(parts[1]) &&
            Number(parts[1]) > 0 &&
            Number(parts[1]) <= (family === 4 ? 32 : 128)))
      )
    })
  )
    throw new ConfigurationError(
      'TRUST_PROXY must contain explicit trusted IP addresses/CIDRs; production hop-count trust is rejected'
    )
  return addresses
}
function secureTransport(req, trust, env = process.env) {
  if (env.NODE_ENV !== 'production' || req.socket?.encrypted) return true
  return Boolean(trust && trust(req.socket?.remoteAddress, 0) && req.headers['x-forwarded-proto'] === 'https')
}
function requireSecureApi(req, res, next) {
  if (!secureTransport(req, req.app.get('trust proxy fn')))
    return res.status(426).json({ success: false, error: 'HTTPS through a trusted proxy is required' })
  next()
}
module.exports = { topology, trustedProxy, secureTransport, requireSecureApi }
