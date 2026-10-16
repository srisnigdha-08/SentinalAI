'use strict'

const net = require('net')

const DEFAULT_CONTAINMENT_DURATION_SECONDS = 3600 // 1 hour
const MIN_CONTAINMENT_DURATION_SECONDS = 60 // 1 minute
const MAX_CONTAINMENT_DURATION_SECONDS = 30 * 24 * 3600 // 30 days

const CORE_SERVICE_PORTS = [3000, 5000, 8000, 27017]

const PROTECTED_IPV4_PATTERNS = [
  /^127\./, // Loopback 127.0.0.0/8
  /^0\.0\.0\.0/, // Unspecified
  /^255\.255\.255\.255$/, // Limited broadcast
  /^(22[4-9]|23[0-9])\./, // Multicast 224.0.0.0/4 (224.0.0.0 to 239.255.255.255)
  /^169\.254\./, // Link-local 169.254.0.0/16 (RFC 3927)
]

const PROTECTED_IPV6_PATTERNS = [
  /^::1$/, // Loopback
  /^::$/, // Unspecified
  /^fe80:/i, // Link-local
  /^ff[0-9a-f]{2}:/i, // Multicast ff00::/8
]

/**
 * Normalizes an IP or CIDR string.
 */
const normalizeTarget = (rawTarget) => {
  if (typeof rawTarget !== 'string') return ''
  return rawTarget.trim().toLowerCase()
}

/**
 * Validates and analyzes a containment target (IPv4, IPv6, or CIDR).
 *
 * @param {string} rawTarget
 * @returns {{
 *   isValid: boolean,
 *   normalizedTarget: string,
 *   targetType: 'ipv4' | 'ipv6' | 'cidr' | null,
 *   ipPart: string,
 *   prefix: number | null,
 *   error?: string
 * }}
 */
const validateTarget = (rawTarget) => {
  const normalized = normalizeTarget(rawTarget)
  if (!normalized) {
    return {
      isValid: false,
      normalizedTarget: '',
      targetType: null,
      ipPart: '',
      prefix: null,
      error: 'Target is required',
    }
  }

  // Check if CIDR
  if (normalized.includes('/')) {
    const parts = normalized.split('/')
    if (parts.length !== 2) {
      return {
        isValid: false,
        normalizedTarget: normalized,
        targetType: null,
        ipPart: '',
        prefix: null,
        error: 'Invalid CIDR format',
      }
    }

    const [ipPart, prefixStr] = parts
    const prefix = parseInt(prefixStr, 10)

    if (isNaN(prefix) || String(prefix) !== prefixStr.trim()) {
      return {
        isValid: false,
        normalizedTarget: normalized,
        targetType: null,
        ipPart,
        prefix: null,
        error: 'CIDR prefix must be a non-negative integer',
      }
    }

    const ipFamily = net.isIP(ipPart)
    if (ipFamily === 4) {
      if (prefix < 0 || prefix > 32) {
        return {
          isValid: false,
          normalizedTarget: normalized,
          targetType: 'cidr',
          ipPart,
          prefix,
          error: 'IPv4 CIDR prefix must be between 0 and 32',
        }
      }
      return {
        isValid: true,
        normalizedTarget: `${ipPart}/${prefix}`,
        targetType: 'cidr',
        ipPart,
        prefix,
        isIPv4: true,
      }
    } else if (ipFamily === 6) {
      if (prefix < 0 || prefix > 128) {
        return {
          isValid: false,
          normalizedTarget: normalized,
          targetType: 'cidr',
          ipPart,
          prefix,
          error: 'IPv6 CIDR prefix must be between 0 and 128',
        }
      }
      return {
        isValid: true,
        normalizedTarget: `${ipPart}/${prefix}`,
        targetType: 'cidr',
        ipPart,
        prefix,
        isIPv6: true,
      }
    } else {
      return {
        isValid: false,
        normalizedTarget: normalized,
        targetType: null,
        ipPart,
        prefix: null,
        error: 'Invalid IP address in CIDR target',
      }
    }
  }

  // Handle explicit port inclusion in target (e.g., 192.168.1.1:5000)
  if (/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/.test(normalized)) {
    const [, ip, portStr] = normalized.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/)
    const portNum = parseInt(portStr, 10)
    if (CORE_SERVICE_PORTS.includes(portNum)) {
      return {
        isValid: false,
        normalizedTarget: normalized,
        targetType: null,
        ipPart: ip,
        prefix: null,
        error: `Target specifies protected core service port ${portNum}; port-level containment is prohibited to protect service availability`,
      }
    }
    return {
      isValid: false,
      normalizedTarget: normalized,
      targetType: null,
      ipPart: ip,
      prefix: null,
      error: 'Target contains port specification; containment targets must be pure IP or CIDR addresses without ports',
    }
  }

  // Single IP
  const ipFamily = net.isIP(normalized)
  if (ipFamily === 4) {
    return { isValid: true, normalizedTarget: normalized, targetType: 'ipv4', ipPart: normalized, prefix: null }
  } else if (ipFamily === 6) {
    return { isValid: true, normalizedTarget: normalized, targetType: 'ipv6', ipPart: normalized, prefix: null }
  }

  return {
    isValid: false,
    normalizedTarget: normalized,
    targetType: null,
    ipPart: '',
    prefix: null,
    error: 'Target must be a valid IPv4, IPv6, or CIDR address',
  }
}

/**
 * Checks safety exclusions to prevent self-lockout or catastrophic host disconnects.
 *
 * @param {{
 *   normalizedTarget: string,
 *   targetType: string,
 *   ipPart: string,
 *   prefix: number | null,
 *   port?: number | null
 * }} targetInfo
 * @returns {{
 *   isSafe: boolean,
 *   decision: 'ALLOWED' | 'DENIED' | 'REQUIRES_CONFIRMATION',
 *   reason?: string
 * }}
 */
const checkSafetyExclusions = (targetInfo) => {
  const { normalizedTarget, targetType, ipPart, prefix, port } = targetInfo

  // Core service port protection
  if (port && CORE_SERVICE_PORTS.includes(Number(port))) {
    return {
      isSafe: false,
      decision: 'DENIED',
      reason: `Targeting core service port ${port} is strictly prohibited to prevent service disruption`,
    }
  }

  // CIDR safety bounds: prevent /0 or overly broad blocks
  if (targetType === 'cidr') {
    if (prefix === 0) {
      return {
        isSafe: false,
        decision: 'DENIED',
        reason: 'Broad containment matching the entire Internet (/0) is prohibited to prevent self-lockout',
      }
    }

    if (targetInfo.isIPv4 && prefix < 24) {
      return {
        isSafe: false,
        decision: 'DENIED',
        reason: `IPv4 CIDR prefix /${prefix} is too broad. Minimum allowed prefix is /24 (maximum 256 hosts)`,
      }
    }

    if (targetInfo.isIPv6 && prefix < 64) {
      return {
        isSafe: false,
        decision: 'DENIED',
        reason: `IPv6 CIDR prefix /${prefix} is too broad. Minimum allowed prefix is /64`,
      }
    }
  }

  // IPv4 Protected Patterns (Loopback, 0.0.0.0, Broadcast, Multicast, Link-local)
  for (const pattern of PROTECTED_IPV4_PATTERNS) {
    if (pattern.test(ipPart)) {
      return {
        isSafe: false,
        decision: 'DENIED',
        reason: `Target ${normalizedTarget} matches protected network infrastructure or loopback address`,
      }
    }
  }

  // IPv6 Protected Patterns (::1, ::, Link-local, Multicast)
  for (const pattern of PROTECTED_IPV6_PATTERNS) {
    if (pattern.test(ipPart)) {
      return {
        isSafe: false,
        decision: 'DENIED',
        reason: `Target ${normalizedTarget} matches protected IPv6 infrastructure or loopback address`,
      }
    }
  }

  // IPv4-mapped IPv6 protection (e.g. ::ffff:127.0.0.1, ::ffff:169.254.1.1)
  const mappedMatch = ipPart.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i)
  if (mappedMatch) {
    const mappedIP = mappedMatch[1]
    for (const pattern of PROTECTED_IPV4_PATTERNS) {
      if (pattern.test(mappedIP)) {
        return {
          isSafe: false,
          decision: 'DENIED',
          reason: `Target ${normalizedTarget} is an IPv4-mapped IPv6 address matching protected IPv4 infrastructure (${mappedIP})`,
        }
      }
    }
  }

  // Localhost string protection
  if (normalizedTarget === 'localhost' || normalizedTarget.startsWith('localhost:')) {
    return {
      isSafe: false,
      decision: 'DENIED',
      reason: 'Blocking localhost is prohibited',
    }
  }

  return { isSafe: true, decision: 'ALLOWED' }
}

/**
 * Validates requester credentials and role authorization.
 *
 * @param {Object} requester - User object (from req.user)
 * @param {Object} context - { actionType, targetType, isPermanent }
 * @returns {{
 *   authorized: boolean,
 *   decision: 'ALLOWED' | 'DENIED',
 *   reason?: string
 * }}
 */
const checkRequesterAuthorization = (requester, context = {}) => {
  if (!requester || (!requester._id && !requester.id)) {
    return {
      authorized: false,
      decision: 'DENIED',
      reason: 'Authentication is required to perform containment actions',
    }
  }

  // Credential lifecycle enforcement: user cannot act if password change is pending
  if (requester.mustChangePassword === true) {
    return {
      authorized: false,
      decision: 'DENIED',
      reason: 'Password change required before performing containment actions',
    }
  }

  // Status check
  if (requester.status && requester.status !== 'active') {
    return {
      authorized: false,
      decision: 'DENIED',
      reason: 'User account is not active',
    }
  }

  const role = (requester.role || '').toLowerCase()

  // CIDR blocks and permanent containment require admin privileges
  if (context.targetType === 'cidr' || context.isPermanent) {
    if (role !== 'admin') {
      return {
        authorized: false,
        decision: 'DENIED',
        reason: 'Administrator role required for CIDR containment or permanent blocks',
      }
    }
  }

  // Standard containment allowed for admin and analyst
  if (role !== 'admin' && role !== 'analyst') {
    return {
      authorized: false,
      decision: 'DENIED',
      reason: `Role '${role}' is not authorized to execute containment actions`,
    }
  }

  return { authorized: true, decision: 'ALLOWED' }
}

/**
 * Computes and bounds containment expiration date.
 *
 * @param {number|null} durationSeconds
 * @param {boolean} isPermanent
 * @returns {{
 *   valid: boolean,
 *   durationSeconds: number | null,
 *   expiresAt: Date | null,
 *   error?: string
 * }}
 */
const calculateExpiration = (durationSeconds, isPermanent = false) => {
  if (isPermanent) {
    return { valid: true, durationSeconds: null, expiresAt: null }
  }

  let duration = durationSeconds
  if (duration === undefined || duration === null || duration === '') {
    duration = DEFAULT_CONTAINMENT_DURATION_SECONDS
  } else {
    duration = parseInt(duration, 10)
    if (isNaN(duration) || duration <= 0) {
      return {
        valid: false,
        durationSeconds: null,
        expiresAt: null,
        error: 'Duration must be a positive integer in seconds',
      }
    }
  }

  if (duration < MIN_CONTAINMENT_DURATION_SECONDS) {
    return {
      valid: false,
      durationSeconds: null,
      expiresAt: null,
      error: `Containment duration must be at least ${MIN_CONTAINMENT_DURATION_SECONDS} seconds`,
    }
  }

  if (duration > MAX_CONTAINMENT_DURATION_SECONDS) {
    return {
      valid: false,
      durationSeconds: null,
      expiresAt: null,
      error: `Containment duration cannot exceed ${MAX_CONTAINMENT_DURATION_SECONDS} seconds (30 days)`,
    }
  }

  const expiresAt = new Date(Date.now() + duration * 1000)
  return { valid: true, durationSeconds: duration, expiresAt }
}

/**
 * Master evaluation function for incoming containment requests.
 * Pure deterministic validation combining target, safety, auth, and duration checks.
 *
 * @param {Object} params
 * @param {string} params.target - Raw target string
 * @param {string} [params.actionType='block_ip'] - Action type
 * @param {number} [params.durationSeconds] - Requested TTL
 * @param {boolean} [params.isPermanent=false] - Whether block is permanent
 * @param {Object} params.requester - Authenticated user object
 * @returns {{
 *   decision: 'ALLOWED' | 'DENIED' | 'REQUIRES_CONFIRMATION',
 *   reason: string,
 *   targetInfo?: Object,
 *   expiration?: Object
 * }}
 */
const evaluatePolicy = ({ target, actionType = 'block_ip', durationSeconds, isPermanent = false, requester }) => {
  // 1. Target Validation
  const targetInfo = validateTarget(target)
  if (!targetInfo.isValid) {
    return {
      decision: 'DENIED',
      reason: targetInfo.error || 'Invalid containment target',
      targetInfo,
    }
  }

  // 2. Safety Exclusions
  const safety = checkSafetyExclusions(targetInfo)
  if (!safety.isSafe) {
    return {
      decision: safety.decision,
      reason: safety.reason,
      targetInfo,
    }
  }

  // 3. Requester Authorization
  const auth = checkRequesterAuthorization(requester, {
    actionType,
    targetType: targetInfo.targetType,
    isPermanent,
  })
  if (!auth.authorized) {
    return {
      decision: auth.decision,
      reason: auth.reason,
      targetInfo,
    }
  }

  // 4. Expiration Calculation
  const expiration = calculateExpiration(durationSeconds, isPermanent)
  if (!expiration.valid) {
    return {
      decision: 'DENIED',
      reason: expiration.error,
      targetInfo,
      expiration,
    }
  }

  return {
    decision: 'ALLOWED',
    reason: 'Policy validation succeeded',
    targetInfo,
    expiration,
  }
}

module.exports = {
  CORE_SERVICE_PORTS,
  DEFAULT_CONTAINMENT_DURATION_SECONDS,
  MIN_CONTAINMENT_DURATION_SECONDS,
  MAX_CONTAINMENT_DURATION_SECONDS,
  PROTECTED_IPV4_PATTERNS,
  PROTECTED_IPV6_PATTERNS,
  normalizeTarget,
  validateTarget,
  checkSafetyExclusions,
  checkRequesterAuthorization,
  calculateExpiration,
  evaluatePolicy,
}
