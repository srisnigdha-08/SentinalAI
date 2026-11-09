'use strict'

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const mongoose = require('mongoose')
const logger = require('./logger')

/**
 * Sanitizes details object by redacting sensitive keys.
 */
const sanitizeDetails = (obj) => {
  if (!obj || typeof obj !== 'object') return obj
  const sensitiveKeys = ['password', 'token', 'secret', 'authorization', 'cookie']
  const clean = Array.isArray(obj) ? [] : {}

  for (const [k, v] of Object.entries(obj)) {
    if (sensitiveKeys.some((s) => k.toLowerCase().includes(s))) {
      clean[k] = '[REDACTED]'
    } else if (v && typeof v === 'object') {
      clean[k] = sanitizeDetails(v)
    } else {
      clean[k] = v
    }
  }
  return clean
}

/**
 * Logs a structured audit event for containment operations.
 *
 * @param {Object} event
 * @param {string} event.action - e.g. 'CONTAINMENT_REQUESTED', 'POLICY_DENIED', 'RULE_APPLIED', 'RULE_ROLLED_BACK'
 * @param {string} event.containmentId
 * @param {string} [event.correlationId]
 * @param {string} event.target
 * @param {string} [event.actionType='block_ip']
 * @param {string} [event.policyDecision]
 * @param {string} [event.enforcementBackend]
 * @param {string} [event.enforcementStatus]
 * @param {string|null} [event.operatorId]
 * @param {string|null} [event.operatorEmail]
 * @param {string|null} [event.operatorRole]
 * @param {Object} [event.details]
 */
const logContainmentAudit = ({
  action,
  containmentId,
  correlationId,
  target,
  actionType = 'block_ip',
  policyDecision,
  enforcementBackend,
  enforcementStatus,
  operatorId = null,
  operatorEmail = null,
  operatorRole = null,
  details = {},
  eventKey = null,
}) => {
  const auditEntry = {
    timestamp: new Date().toISOString(),
    auditType: 'CONTAINMENT_AUDIT',
    action,
    containmentId,
    correlationId: correlationId || null,
    target,
    actionType,
    policyDecision: policyDecision || null,
    enforcementBackend: enforcementBackend || null,
    enforcementStatus: enforcementStatus || null,
    operator: {
      id: operatorId,
      email: operatorEmail,
      role: operatorRole,
    },
    details: sanitizeDetails(details),
  }

  logger.info(`[AUDIT] ${action} - target=${target} id=${containmentId} status=${enforcementStatus}`, auditEntry)
  if (containmentId) {
    auditEntry.eventId = eventKey
      ? `${containmentId}:${eventKey}`
      : ONCE_PER_CONTAINMENT.has(action)
        ? `${containmentId}:${action}`
        : crypto.randomUUID()
    // On disk before the database write is tried, so the event survives a crash at any point after this returns.
    spoolAppend(auditEntry)
    // Durable copy (F-07). Never throws and never delays the containment operation; see persistContainmentAudit.
    Object.defineProperty(auditEntry, 'persisted', { value: persistContainmentAudit(auditEntry), enumerable: false })
  }
  return auditEntry
}

// ---------------------------------------------------------------------------------------------------------------
// F-07: durable containment audit records (models/ContainmentAuditEvent.js).
//
// Events that happen at most once per containment action get a deterministic eventId, so the same event
// recorded twice (two code paths, or a retried write whose first attempt did succeed) is stored once. Repeating
// events (rollback attempts, idempotent hits, deferred recovery passes) get a random id per occurrence; callers
// that know an attempt number pass eventKey to make the retry of the same attempt idempotent too.
// ---------------------------------------------------------------------------------------------------------------
const ONCE_PER_CONTAINMENT = new Set([
  'CONTAINMENT_REQUESTED',
  'CONTAINMENT_REJECTED',
  'CONTAINMENT_ACTIVE',
  'ENFORCEMENT_FAILED',
  'CONTAINMENT_ROLLED_BACK',
  'CONTAINMENT_RECOVERED',
  'LATE_RULE_REMOVED',
])
const BACKLOG_MAX = Number(process.env.CONTAINMENT_AUDIT_BACKLOG_MAX) || 5000
const WRITE_ATTEMPTS = 3
const backlog = [] // events not yet stored because MongoDB was unavailable, oldest first
const chains = new Map() // containmentId -> tail of that action's write chain (keeps per-action order)
let dropped = 0

// ---------------------------------------------------------------------------------------------------------------
// Crash durability: a write-ahead spool, one file per database (a spool must never replay into another database).
// Guarantee: once logContainmentAudit has returned, the event survives a process crash and is stored on the next
// connection, once (eventId is unique) and in order. A crash during the append can tear only that final line.
// The file is emptied whenever nothing is outstanding. Limits: CONTAINMENT_AUDIT_SPOOL_MAX_BYTES (default 16 MiB);
// a spool that is full or unwritable is counted and logged and the event still goes to MongoDB, so a disk problem
// never blocks containment. Off under NODE_ENV=test unless CONTAINMENT_AUDIT_SPOOL_DIR is set.
// ---------------------------------------------------------------------------------------------------------------
let spoolBytes = null
let spoolFailures = 0
let spoolLoaded = false

const spoolEnabled = () => process.env.NODE_ENV !== 'test' || Boolean(process.env.CONTAINMENT_AUDIT_SPOOL_DIR)
const spoolPath = () => {
  const uri = String(process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db')
  const db = (uri.split('://')[1]?.split('/')[1]?.split('?')[0] || 'default').replace(/[^\w.-]/g, '_')
  const dir = process.env.CONTAINMENT_AUDIT_SPOOL_DIR || path.join(__dirname, '..', 'logs')
  return path.join(dir, `containment-audit-spool-${db}.jsonl`)
}
function countLoss(reason) {
  try {
    require('./metrics').inc(
      'sentinel_containment_audit_loss_total',
      'Containment audit events that lost a durability layer',
      { reason }
    )
  } catch {
    // metrics are optional here
  }
}
function spoolAppend(entry) {
  if (!spoolEnabled()) return
  try {
    const file = spoolPath()
    if (spoolBytes === null) {
      fs.mkdirSync(path.dirname(file), { recursive: true })
      spoolBytes = fs.existsSync(file) ? fs.statSync(file).size : 0
    }
    const line = JSON.stringify(entry) + '\n'
    const size = Buffer.byteLength(line)
    if (spoolBytes + size > (Number(process.env.CONTAINMENT_AUDIT_SPOOL_MAX_BYTES) || 16 * 1024 * 1024)) {
      throw new Error('spool is full')
    }
    const fd = fs.openSync(file, 'a', 0o600)
    try {
      fs.writeSync(fd, line)
      fs.fsyncSync(fd)
    } finally {
      fs.closeSync(fd)
    }
    spoolBytes += size
  } catch (err) {
    spoolFailures++
    countLoss('spool_unavailable')
    logger.error(
      `[AUDIT] Containment audit spool not written (${err.message}); event ${entry.action} is not crash-safe`
    )
  }
}
function compactSpool() {
  if (!spoolEnabled() || !spoolBytes || chains.size || backlog.length || flushing) return
  try {
    fs.truncateSync(spoolPath(), 0)
    spoolBytes = 0
  } catch (err) {
    logger.warn(`[AUDIT] Containment audit spool not compacted: ${err.message}`)
  }
}
/** Replays events left by a previous process (first call only), then flushes everything queued. */
function recoverContainmentAuditSpool() {
  if (!spoolLoaded && spoolEnabled()) {
    spoolLoaded = true
    try {
      const file = spoolPath()
      if (fs.existsSync(file)) {
        const known = new Set(backlog.map((e) => e.eventId))
        const replay = []
        let torn = 0
        for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
          if (!line.trim()) continue
          try {
            const entry = JSON.parse(line)
            if (entry.eventId && !known.has(entry.eventId)) {
              known.add(entry.eventId)
              replay.push(entry)
            }
          } catch {
            torn++
          }
        }
        if (torn) logger.warn(`[AUDIT] Containment audit spool: ${torn} incomplete line(s) skipped`)
        if (replay.length) {
          logger.warn(`[AUDIT] Containment audit spool: replaying ${replay.length} event(s) from a previous process`)
          backlog.unshift(...replay)
          ensureRetryTimer()
        }
        spoolBytes = fs.statSync(file).size
      }
    } catch (err) {
      spoolFailures++
      countLoss('spool_unreadable')
      logger.error(`[AUDIT] Containment audit spool not replayed: ${err.message}`)
    }
  }
  return flushContainmentAuditBacklog()
}

const dbReady = () => {
  return mongoose.connection.readyState === 1 && Boolean(mongoose.connection.db)
}

// Database-assigned order and time: one atomic counter increment returns the next sequence number together with
// the server clock, so ordering never depends on the backend host's clock (CONT-R1).
async function nextSequence() {
  const doc = await mongoose.connection.db
    .collection('counters')
    .findOneAndUpdate(
      { _id: 'containment_audit_events' },
      [{ $set: { seq: { $add: [{ $ifNull: ['$seq', 0] }, 1] }, at: '$$NOW' } }],
      { upsert: true, returnDocument: 'after' }
    )
  const value = doc && doc.value !== undefined && doc.seq === undefined ? doc.value : doc // driver 5/6 shapes
  return { seq: value.seq, at: value.at }
}

async function writeOnce(entry) {
  const ContainmentAuditEvent = require('../models/ContainmentAuditEvent')
  if (await ContainmentAuditEvent.exists({ eventId: entry.eventId })) return 'duplicate'
  const { seq, at } = await nextSequence()
  try {
    await ContainmentAuditEvent.create({
      eventId: entry.eventId,
      seq,
      containmentId: String(entry.containmentId),
      correlationId: entry.correlationId,
      action: entry.action,
      target: entry.target ?? null,
      actionType: entry.actionType,
      policyDecision: entry.policyDecision,
      enforcementBackend: entry.enforcementBackend,
      enforcementStatus: entry.enforcementStatus,
      operator: {
        id: entry.operator?.id != null ? String(entry.operator.id) : null,
        email: entry.operator?.email ?? null,
        role: entry.operator?.role ?? null,
      },
      details: entry.details || {},
      occurredAt: new Date(entry.timestamp),
      recordedAt: at,
    })
    return 'stored'
  } catch (err) {
    if (err?.code === 11000 && /eventId/.test(err.message)) return 'duplicate'
    throw err
  }
}

function enqueue(entry) {
  if (backlog.length >= BACKLOG_MAX) {
    const lost = backlog.shift()
    dropped++
    countLoss('backlog_full')
    logger.error(
      `[AUDIT] Containment audit backlog full (${BACKLOG_MAX}); oldest event not stored durably: ` +
        `${lost.action} ${lost.containmentId} (it remains in the application log)`
    )
  }
  backlog.push(entry)
  ensureRetryTimer()
}

// A flush that paused on a write error resumes on the next event, on reconnect, or from this timer. The timer exists
// only while events are queued (no module-level timer), never keeps the process alive, and never throws.
let retryTimer = null
function ensureRetryTimer() {
  if (retryTimer) return
  retryTimer = setInterval(() => {
    try {
      if (!backlog.length) {
        clearInterval(retryTimer)
        retryTimer = null
      } else if (dbReady()) flushContainmentAuditBacklog()
    } catch {
      // module torn down (tests) or mongoose unavailable: retried on the next tick or event
    }
  }, 30000)
  retryTimer.unref?.()
}

async function store(entry) {
  // Older events still waiting: this one goes behind them, so a newer event can never be stored (and given a
  // lower seq) before an older one; the flush is started here rather than only on a reconnect event.
  if (backlog.length) {
    enqueue(entry)
    if (dbReady()) flushContainmentAuditBacklog()
    return 'queued'
  }
  let lastErr
  for (let attempt = 1; attempt <= WRITE_ATTEMPTS; attempt++) {
    if (!dbReady()) break
    try {
      return await writeOnce(entry)
    } catch (err) {
      lastErr = err
    }
  }
  enqueue(entry)
  if (lastErr) logger.warn(`[AUDIT] Containment audit event queued after write failure: ${lastErr.message}`)
  return 'queued'
}

/** Stores one event durably, after any earlier event of the same containment action. Never rejects. */
function persistContainmentAudit(entry) {
  const key = String(entry.containmentId)
  const run = (chains.get(key) || Promise.resolve())
    .then(() => store(entry))
    .catch((err) => {
      logger.error(`[AUDIT] Containment audit persistence error: ${err.message}`)
      return 'error'
    })
  chains.set(key, run)
  run.then(() => {
    if (chains.get(key) === run) chains.delete(key)
    compactSpool()
  })
  return run
}

let flushing = null
/** Writes queued events in their original order once MongoDB is reachable again. */
function flushContainmentAuditBacklog() {
  if (flushing) return flushing
  flushing = (async () => {
    let stored = 0
    while (backlog.length && dbReady()) {
      const entry = backlog[0]
      try {
        await writeOnce(entry)
        backlog.shift()
        stored++
      } catch (err) {
        logger.warn(`[AUDIT] Containment audit backlog flush paused: ${err.message}`)
        break
      }
    }
    return stored
  })().finally(() => {
    flushing = null
    compactSpool()
  })
  return flushing
}

/** Resolves when every write started so far has finished (tests and graceful shutdown). */
async function settleContainmentAudit() {
  while (chains.size) await Promise.all([...chains.values()])
  if (flushing) await flushing
}

const containmentAuditBacklog = () => ({ queued: backlog.length, dropped, spoolFailures })

try {
  mongoose.connection.on('connected', () => recoverContainmentAuditSpool())
  mongoose.connection.on('reconnected', () => recoverContainmentAuditSpool())
  require('./metrics').gauge(
    'sentinel_containment_audit_backlog',
    'Containment audit events waiting for MongoDB (stored in order once it is reachable)',
    () => backlog.length
  )
} catch {
  // metrics or mongoose unavailable in a unit test: persistence still works when called
}

module.exports = {
  sanitizeDetails,
  logContainmentAudit,
  persistContainmentAudit,
  flushContainmentAuditBacklog,
  recoverContainmentAuditSpool,
  settleContainmentAudit,
  containmentAuditBacklog,
  ONCE_PER_CONTAINMENT,
}
