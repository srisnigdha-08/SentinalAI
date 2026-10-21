'use strict'
/**
 * SentinelAI — Threat Intelligence Enrichment Service (Phase 2.4B)
 *
 * Implements Option B: Asynchronous, decoupled threat intelligence enrichment
 * powered by AbuseIPDB.
 *
 * CRITICAL ARCHITECTURAL INVARIANTS:
 * 1. ZERO modification of ThreatScore, severity, or action.
 * 2. ZERO trigger of automated containment (BlockedIP / containmentService).
 * 3. Real-time ML detection never blocks waiting for external threat intelligence.
 * 4. Fails open and safe: API outages or missing keys never impede threat ingestion.
 */

const net = require('net')
const axios = require('axios')
const ThreatLog = require('../models/ThreatLog')
const socketManager = require('../websocket/socketManager')
const logger = require('../utils/logger')

// ── In-Memory Bounded Reputation Cache ───────────────────────────────────────
// Key: sanitized IP string -> Value: { intel: Object, timestamp: number }
// Limitation: Process-local in-memory cache for this backend instance.
const REPUTATION_CACHE = new Map()
const CACHE_TTL_MS = 60 * 60 * 1000 // 1 hour TTL
const MAX_CACHE_ENTRIES = 5000

/**
 * Validates whether an IP address is a public, routable internet address.
 * Rejects RFC-1918 private IPs, loopback, link-local, multicast, reserved ranges,
 * and malformed/non-IP strings.
 *
 * @param {string} ipStr
 * @returns {boolean} True if public and valid, false otherwise.
 */
function isPublicIP(ipStr) {
  if (!ipStr || typeof ipStr !== 'string') return false
  const ip = ipStr.trim()
  const version = net.isIP(ip)
  if (version === 0) return false // Malformed / non-IP

  if (version === 4) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return false
    const [b0, b1, b2] = parts

    // 0.0.0.0/8 (Current network)
    if (b0 === 0) return false
    // 10.0.0.0/8 (RFC-1918 Private)
    if (b0 === 10) return false
    // 100.64.0.0/10 (Shared Address Space / CGNAT)
    if (b0 === 100 && b1 >= 64 && b1 <= 127) return false
    // 127.0.0.0/8 (Loopback)
    if (b0 === 127) return false
    // 169.254.0.0/16 (Link-local)
    if (b0 === 169 && b1 === 254) return false
    // 172.16.0.0/12 (RFC-1918 Private)
    if (b0 === 172 && b1 >= 16 && b1 <= 31) return false
    // 192.0.0.0/24 (IETF Protocol Assignments)
    if (b0 === 192 && b1 === 0 && b2 === 0) return false
    // 192.0.2.0/24 (TEST-NET-1)
    if (b0 === 192 && b1 === 0 && b2 === 2) return false
    // 192.168.0.0/16 (RFC-1918 Private)
    if (b0 === 192 && b1 === 168) return false
    // 198.18.0.0/15 (Benchmarking)
    if (b0 === 198 && (b1 === 18 || b1 === 19)) return false
    // 198.51.100.0/24 (TEST-NET-2)
    if (b0 === 198 && b1 === 51 && b2 === 100) return false
    // 203.0.113.0/24 (TEST-NET-3)
    if (b0 === 203 && b1 === 0 && b2 === 113) return false
    // 224.0.0.0/4 (Multicast)
    if (b0 >= 224 && b0 <= 239) return false
    // 240.0.0.0/4 (Reserved)
    if (b0 >= 240) return false

    return true
  }

  if (version === 6) {
    const lower = ip.toLowerCase()
    // ::1 (Loopback), :: (Unspecified)
    if (lower === '::1' || lower === '::') return false
    // IPv4-mapped IPv6 (::ffff:192.168.1.1)
    if (lower.startsWith('::ffff:')) {
      const ipv4Part = lower.slice(7)
      return isPublicIP(ipv4Part)
    }
    // fe80::/10 (Link-local)
    if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb'))
      return false
    // fc00::/7 (Unique Local Address)
    if (lower.startsWith('fc') || lower.startsWith('fd')) return false
    // ff00::/8 (Multicast)
    if (lower.startsWith('ff')) return false

    return true
  }

  return false
}

/**
 * Checks cache for existing IP reputation result.
 * Evicts expired keys on lookup.
 *
 * @param {string} ip
 * @returns {Object|null}
 */
function getFromCache(ip) {
  if (!REPUTATION_CACHE.has(ip)) return null
  const entry = REPUTATION_CACHE.get(ip)
  const now = Date.now()
  if (now - entry.timestamp > CACHE_TTL_MS) {
    REPUTATION_CACHE.delete(ip)
    return null
  }
  return { ...entry.intel, cached: true }
}

/**
 * Inserts IP reputation into the bounded in-memory cache.
 *
 * @param {string} ip
 * @param {Object} intel
 */
function setInCache(ip, intel) {
  const now = Date.now()
  if (REPUTATION_CACHE.size >= MAX_CACHE_ENTRIES) {
    // 1. Evict expired entries
    for (const [key, value] of REPUTATION_CACHE.entries()) {
      if (now - value.timestamp > CACHE_TTL_MS) {
        REPUTATION_CACHE.delete(key)
      }
    }
    // 2. If still at max capacity, evict oldest entry (FIFO)
    if (REPUTATION_CACHE.size >= MAX_CACHE_ENTRIES) {
      const oldestKey = REPUTATION_CACHE.keys().next().value
      if (oldestKey) REPUTATION_CACHE.delete(oldestKey)
    }
  }
  REPUTATION_CACHE.set(ip, { intel, timestamp: now })
}

/**
 * Clears the in-memory cache. Provided for unit and integration testing.
 */
function clearCache() {
  REPUTATION_CACHE.clear()
}

/**
 * Asynchronously checks AbuseIPDB reputation for a given IP address.
 * Fails safely and returns normalized threatIntel payload without throwing.
 *
 * @param {string} ipStr
 * @returns {Promise<Object>} Normalized threatIntel subdocument
 */
async function queryAbuseIPDB(ipStr) {
  if (!ipStr || typeof ipStr !== 'string') {
    return {
      provider: 'AbuseIPDB',
      status: 'UNAVAILABLE',
      errorCode: 'INVALID_IP',
      cached: false,
    }
  }

  const cleanIP = ipStr.trim()

  // 1. Validate IP and reject private / loopback / malformed IPs
  const version = net.isIP(cleanIP)
  if (version === 0) {
    return {
      provider: 'AbuseIPDB',
      status: 'UNAVAILABLE',
      errorCode: 'INVALID_IP',
      cached: false,
    }
  }

  if (!isPublicIP(cleanIP)) {
    return {
      provider: 'AbuseIPDB',
      status: 'UNAVAILABLE',
      errorCode: 'PRIVATE_IP',
      cached: false,
    }
  }

  // 2. Check in-memory cache
  const cached = getFromCache(cleanIP)
  if (cached) {
    return cached
  }

  // 3. Check API key configuration
  const apiKey = process.env.ABUSEIPDB_API_KEY
  if (!apiKey || apiKey.trim() === '') {
    return {
      provider: 'AbuseIPDB',
      status: 'UNAVAILABLE',
      errorCode: 'NO_API_KEY',
      cached: false,
    }
  }

  // 4. Query AbuseIPDB API with strict timeout (2500ms)
  const url = 'https://api.abuseipdb.com/api/v2/check'
  try {
    const response = await axios.get(url, {
      headers: {
        Key: apiKey.trim(),
        Accept: 'application/json',
      },
      params: {
        ipAddress: cleanIP,
        maxAgeInDays: 90,
      },
      timeout: 2500, // Strict timeout to preserve resource bounds
    })

    if (response.status === 200 && response.data?.data) {
      const d = response.data.data
      const confidence = typeof d.abuseConfidenceScore === 'number' ? d.abuseConfidenceScore : 0
      const reports = typeof d.totalReports === 'number' ? d.totalReports : 0
      const lastReport = d.lastReportedAt ? new Date(d.lastReportedAt) : null

      const intel = {
        provider: 'AbuseIPDB',
        status: 'SUCCESS',
        abuseConfidenceScore: Math.min(Math.max(confidence, 0), 100),
        totalReports: reports,
        lastReportedAt: isNaN(lastReport?.getTime?.()) ? null : lastReport,
        countryCode: d.countryCode || null,
        isp: d.isp || null,
        domain: d.domain || null,
        lookupAt: new Date(),
        cached: false,
        errorCode: null,
      }

      setInCache(cleanIP, intel)
      return intel
    }

    return {
      provider: 'AbuseIPDB',
      status: 'FAILED',
      errorCode: `HTTP_${response.status}`,
      cached: false,
    }
  } catch (error) {
    const status = error.response?.status
    let errorCode = 'NETWORK_ERROR'

    if (error.code === 'ECONNABORTED' || error.message?.includes('timeout')) {
      errorCode = 'TIMEOUT'
    } else if (status === 429) {
      errorCode = 'RATE_LIMITED'
    } else if (status === 401 || status === 403) {
      errorCode = 'AUTH_ERROR'
    } else if (status) {
      errorCode = `HTTP_${status}`
    }

    const threatStatus = ['RATE_LIMITED', 'AUTH_ERROR'].includes(errorCode) ? 'UNAVAILABLE' : 'FAILED'

    logger.warn(`[ThreatIntel] AbuseIPDB lookup failed for ${cleanIP}: ${errorCode}`)
    return {
      provider: 'AbuseIPDB',
      status: threatStatus,
      errorCode,
      cached: false,
    }
  }
}

/**
 * Asynchronously enriches a ThreatLog document with AbuseIPDB threat intelligence.
 *
 * Trigger Policy:
 * Only threats with aiScore >= 0.70 are enriched (monitoring threshold policy).
 *
 * Strict Isolation:
 * Under NO circumstances modifies aiScore, severity, status, or containment.
 *
 * @param {Object} threat ThreatLog Mongoose document or plain object
 * @returns {Promise<Object|null>} The enriched ThreatLog or null
 */
async function enrichThreat(threat) {
  if (!threat || !threat._id) return null

  const score = threat.aiScore !== undefined ? threat.aiScore : threat.threatScore || 0

  // 1. Trigger policy: initial enrichment trigger is aiScore >= 0.70
  if (score < 0.7) {
    return null
  }

  try {
    const intel = await queryAbuseIPDB(threat.sourceIP)

    // Atomic update to ThreatLog: only sets threatIntel, never alters ThreatScore or status
    const updated = await ThreatLog.findByIdAndUpdate(
      threat._id,
      { $set: { threatIntel: intel } },
      { new: true, runValidators: true }
    )

    if (updated) {
      // Emit dedicated WebSocket event; never emits new_threat, new_alert, or ip_blocked
      socketManager.emitThreatIntelUpdated({
        threatId: updated._id,
        sourceIP: updated.sourceIP,
        threatIntel: intel,
      })
    }

    return updated
  } catch (err) {
    logger.error(`[ThreatIntel] Asynchronous enrichment failed for threat ${threat._id}: ${err.message}`)
    return null
  }
}

module.exports = {
  isPublicIP,
  getFromCache,
  setInCache,
  clearCache,
  queryAbuseIPDB,
  enrichThreat,
  getCacheSize: () => REPUTATION_CACHE.size,
}
