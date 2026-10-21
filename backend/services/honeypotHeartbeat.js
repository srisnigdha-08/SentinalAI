'use strict'

/**
 * Liveness of the honeypot node (L4). The Cowrie blocker plugin pulls GET /api/honeypot/ingest/check-block
 * every 2 s; each authenticated pull counts as a heartbeat. In memory: a backend restart shows "unknown"
 * until the next poll, a few seconds later.
 */
let lastSeen = null

const OFFLINE_AFTER_MS = () => (parseInt(process.env.HONEYPOT_HEARTBEAT_TIMEOUT_SECONDS, 10) || 30) * 1000

const beat = (now = new Date()) => {
  lastSeen = now
}

/** 'online' (polled within the timeout), 'offline' (polled before, not since) or 'unknown' (never polled). */
const status = (now = new Date()) => {
  if (!lastSeen) return { liveness: 'unknown', lastSeen: null }
  const online = now.getTime() - lastSeen.getTime() <= OFFLINE_AFTER_MS()
  return { liveness: online ? 'online' : 'offline', lastSeen: lastSeen.toISOString() }
}

const reset = () => {
  lastSeen = null
}

module.exports = { beat, status, reset }
