'use strict'
/**
 * Database readiness for /health and /health/ready. mongoose.connection.readyState === 1 only says the driver believes
 * it is connected; a hung or unresponsive server keeps that state. The probe also sends a `ping` with a deadline.
 *
 * Results are cached for HEALTH_DB_PING_CACHE_MS (default 2000) and concurrent callers share one probe, because the
 * readiness endpoints are unauthenticated and polled by orchestrators.
 */
const mongoose = require('mongoose')

const ms = (value, fallback) => {
  const n = parseInt(value, 10)
  return Number.isInteger(n) && n >= 0 ? n : fallback
}

let cache = { at: 0, promise: null }

async function probe(timeoutMs) {
  const conn = mongoose.connection
  if (conn.readyState !== 1 || !conn.db) return { ok: false, state: 'disconnected' }
  let timer
  try {
    await Promise.race([
      conn.db.admin().ping(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('ping timeout')), timeoutMs)
      }),
    ])
    return { ok: true, state: 'connected' }
  } catch {
    return { ok: false, state: 'unresponsive' }
  } finally {
    clearTimeout(timer)
  }
}

/** { ok, state }: state is 'connected', 'disconnected' (driver not connected) or 'unresponsive' (ping failed). */
function databaseHealth() {
  const cacheMs = ms(process.env.HEALTH_DB_PING_CACHE_MS, 2000)
  const now = Date.now()
  if (cache.promise && now - cache.at < cacheMs) return cache.promise
  const promise = probe(ms(process.env.HEALTH_DB_PING_TIMEOUT_MS, 1000))
  cache = { at: now, promise }
  return promise
}

const resetCache = () => {
  cache = { at: 0, promise: null }
}

module.exports = { databaseHealth, resetCache }
