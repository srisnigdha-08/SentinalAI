'use strict'
/**
 * Minimal Prometheus text-format metrics (no client library). Exposed at GET /metrics, which requires
 * `Authorization: Bearer <METRICS_TOKEN>` when METRICS_TOKEN is set, and otherwise answers loopback only.
 */
const counters = new Map() // name -> { help, values: Map(labelKey -> number) }
const gauges = new Map() // name -> { help, read: () => number }

const labelKey = (labels = {}) =>
  Object.keys(labels)
    .sort()
    .map((k) => `${k}="${String(labels[k]).replace(/["\\\n]/g, '_')}"`)
    .join(',')

const inc = (name, help, labels = {}, by = 1) => {
  if (!counters.has(name)) counters.set(name, { help, values: new Map() })
  const values = counters.get(name).values
  const key = labelKey(labels)
  values.set(key, (values.get(key) || 0) + by)
}

const gauge = (name, help, read) => gauges.set(name, { help, read })

const render = () => {
  const lines = []
  for (const [name, { help, values }] of counters) {
    lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} counter`)
    for (const [key, value] of values) lines.push(`${name}${key ? `{${key}}` : ''} ${value}`)
  }
  for (const [name, { help, read }] of gauges) {
    let value
    try {
      value = Number(read())
    } catch {
      value = NaN
    }
    lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} gauge`, `${name} ${Number.isFinite(value) ? value : 'NaN'}`)
  }
  return lines.join('\n') + '\n'
}

/** Express middleware counting requests and summing latency by method/route/status. */
const httpMiddleware = (req, res, next) => {
  const start = process.hrtime.bigint()
  res.on('finish', () => {
    const route = req.route?.path ? `${req.baseUrl || ''}${req.route.path}` : 'unmatched'
    const labels = { method: req.method, route, status: String(res.statusCode) }
    inc('sentinel_http_requests_total', 'HTTP requests by method, route and status', labels)
    inc(
      'sentinel_http_request_duration_seconds_sum',
      'Total HTTP request time by method, route and status',
      labels,
      Number(process.hrtime.bigint() - start) / 1e9
    )
  })
  next()
}

const isLoopback = (addr = '') => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(addr)

const handler = (req, res) => {
  const token = process.env.METRICS_TOKEN
  const authorized = token ? req.headers.authorization === `Bearer ${token}` : isLoopback(req.socket?.remoteAddress)
  if (!authorized) return res.status(403).json({ success: false, error: 'Metrics access denied' })
  res.set('Content-Type', 'text/plain; version=0.0.4').send(render())
}

const reset = () => {
  counters.clear()
  gauges.clear()
}

module.exports = { inc, gauge, render, httpMiddleware, handler, reset }
