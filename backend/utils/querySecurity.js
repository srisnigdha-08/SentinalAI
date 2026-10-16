'use strict'

const net = require('net')
const mongoose = require('mongoose')

/**
 * Escapes regex metacharacters in user-supplied strings to prevent ReDoS,
 * pattern injection, and unexpected wildcard matching in MongoDB $regex queries.
 *
 * @param {any} input - Raw user input string
 * @param {number} maxLength - Maximum allowable string length (default: 100)
 * @returns {string|null} Sanitized string safe for $regex, or null if input is empty/invalid
 */
const escapeRegex = (input, maxLength = 100) => {
  if (typeof input !== 'string') return null
  const trimmed = input.trim().slice(0, maxLength)
  if (!trimmed) return null
  // Escape regex metacharacters: \ ^ $ . * + ? ( ) [ ] { } |
  return trimmed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Safely normalizes and bounds pagination parameters to prevent unbounded queries,
 * negative skips, NaN errors, and memory exhaustion.
 *
 * @param {Object} options
 * @param {any} options.page - Raw page number from query parameter
 * @param {any} options.limit - Raw limit from query parameter
 * @param {number} options.defaultLimit - Fallback limit (default: 20)
 * @param {number} options.maxLimit - Maximum permitted limit (default: 100)
 * @returns {{ page: number, limit: number, skip: number }}
 */
const parsePagination = ({ page, limit, defaultLimit = 20, maxLimit = 100 } = {}) => {
  let safeLimit = defaultLimit
  if (limit !== undefined && limit !== null && String(limit).trim() !== '') {
    const parsed = parseInt(limit, 10)
    if (!isNaN(parsed) && parsed > 0) {
      safeLimit = Math.min(parsed, maxLimit)
    }
  }

  let safePage = 1
  if (page !== undefined && page !== null && String(page).trim() !== '') {
    const parsed = parseInt(page, 10)
    if (!isNaN(parsed) && parsed > 0) {
      safePage = Math.min(parsed, 10000) // Bound max page to prevent integer overflow
    }
  }

  const skip = (safePage - 1) * safeLimit
  return { page: safePage, limit: safeLimit, skip }
}

/**
 * Validates and safely resolves sorting parameters against an explicit allowlist.
 * Prevents arbitrary field sorting, injection of MongoDB operators, and memory sort crashes.
 *
 * @param {any} sortBy - Requested sort field name
 * @param {any} sortOrder - Requested sort order ('asc' | 'desc')
 * @param {string[]} allowedFields - Explicit array of allowed sort field names
 * @param {string} defaultField - Default field if sortBy is invalid or unallowed
 * @returns {Object} Mongoose sort object (e.g. { createdAt: -1 })
 */
const parseSort = (sortBy, sortOrder, allowedFields, defaultField = 'createdAt') => {
  const field = typeof sortBy === 'string' && allowedFields.includes(sortBy.trim()) ? sortBy.trim() : defaultField

  const isAsc =
    sortOrder === 1 || sortOrder === '1' || (typeof sortOrder === 'string' && sortOrder.toLowerCase() === 'asc')
  const order = isAsc ? 1 : -1

  return { [field]: order }
}

/**
 * Validates and parses ISO date strings safely.
 * Returns null for invalid dates to prevent Mongo query errors.
 *
 * @param {any} dateStr - Date string to parse
 * @returns {Date|null}
 */
const parseDate = (dateStr) => {
  if (typeof dateStr !== 'string' || !dateStr.trim()) return null
  const d = new Date(dateStr)
  return isNaN(d.getTime()) ? null : d
}

/**
 * Validates whether an IP address is a valid IPv4 or IPv6 address.
 *
 * @param {any} ip - Input IP string
 * @returns {boolean}
 */
const isValidIP = (ip) => {
  if (typeof ip !== 'string' || !ip.trim()) return false
  return net.isIP(ip.trim()) !== 0
}

/**
 * Validates MongoDB 24-character hexadecimal ObjectId.
 *
 * @param {any} id
 * @returns {boolean}
 */
const isValidObjectId = (id) => {
  if (typeof id !== 'string' || !id.trim()) return false
  return mongoose.Types.ObjectId.isValid(id.trim()) && /^[0-9a-fA-F]{24}$/.test(id.trim())
}

module.exports = {
  escapeRegex,
  parsePagination,
  parseSort,
  parseDate,
  isValidIP,
  isValidObjectId,
}
