'use strict'
/**
 * Network capture status for the dashboard (docs/CAPTURE.md). The capture service (ai-engine/capture/service.py)
 * POSTs a heartbeat with its mode and counters; this module keeps the latest one in memory and answers one of:
 *   live_passive  a live passive capture is running and reported within the freshness window
 *   pcap_replay   a recorded-PCAP replay is running, or finished (with when)
 *   unavailable   no fresh heartbeat (never started, stopped, crashed) or the service reported it cannot capture
 * A replay is never reported as live: the mode comes from the service's own source kind, validated here.
 */
const MODES = ['live_passive', 'pcap_replay']
const STATUSES = ['starting', 'running', 'finished', 'unavailable']
const COUNTERS = ['packets', 'flows', 'posted', 'post_errors', 'rate_limited', 'dropped_packets']
const FRESH_MS = Math.max(5000, Number(process.env.CAPTURE_HEARTBEAT_STALE_MS) || 60000)

let latest = null

const str = (v, max) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null)
const isoOrNull = (v) => {
  const d = typeof v === 'string' ? new Date(v) : null
  return d && !isNaN(d.getTime()) ? d.toISOString() : null
}

/** Validate and store one heartbeat. Returns null when it is malformed (the route answers 400). */
function recordHeartbeat(body, now = Date.now()) {
  if (!body || typeof body !== 'object') return null
  if (!MODES.includes(body.mode) || !STATUSES.includes(body.status)) return null
  const counters = {}
  for (const k of COUNTERS) {
    const n = Number(body.counters && body.counters[k])
    counters[k] = Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0
  }
  latest = {
    mode: body.mode,
    status: body.status,
    interface: body.mode === 'live_passive' ? str(body.interface, 64) : null,
    startedAt: isoOrNull(body.startedAt),
    lastPacketAt: isoOrNull(body.lastPacketAt),
    lastError: str(body.lastError, 200),
    counters,
    receivedAt: new Date(now).toISOString(),
  }
  return latest
}

function getStatus(now = Date.now()) {
  if (!latest) {
    return { mode: 'unavailable', reason: 'No capture service has reported since the backend started.', fresh: false }
  }
  const age = now - Date.parse(latest.receivedAt)
  const fresh = age <= FRESH_MS
  if (latest.status === 'unavailable')
    return { mode: 'unavailable', reason: latest.lastError || 'The capture service reported it cannot capture.', fresh, last: latest }
  if (latest.mode === 'pcap_replay' && latest.status === 'finished')
    return { mode: 'pcap_replay', state: 'finished', fresh, last: latest }
  if (!fresh)
    return { mode: 'unavailable', reason: `No heartbeat for ${Math.round(age / 1000)} s (capture stopped or crashed).`, fresh, last: latest }
  return { mode: latest.mode, state: latest.status, fresh, last: latest }
}

function _reset() {
  latest = null
}

module.exports = { recordHeartbeat, getStatus, MODES, FRESH_MS, _reset }
