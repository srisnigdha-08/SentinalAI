'use strict'

const crypto = require('crypto')
const logger = require('./logger')

const ALLOWED_EVENT_TYPES = new Set([
  'THREAT_DETECTED',
  'THREAT_UPDATED',
  'THREAT_INTEL_UPDATED',
  'IP_BLOCKED',
  'IP_UNBLOCKED',
  'ALERT_CREATED',
  'AI_PREDICTION',
  'HONEYPOT_SESSION_OPENED',
  'HONEYPOT_COMMAND',
  'HONEYPOT_SESSION_CLOSED',
  'MALWARE_DOWNLOAD',
  'CONTAINMENT_ACTION_REQUESTED',
  'CONTAINMENT_ACTION_APPLIED',
  'CONTAINMENT_ACTION_FAILED',
  'CONTAINMENT_ACTION_ROLLED_BACK',
  'SYSTEM_HEALTH',
])

const SENSITIVE_KEYS = new Set([
  'password',
  'currentpassword',
  'newpassword',
  'token',
  'refreshtoken',
  'refreshhash',
  'secret',
  'jwt_secret',
  'jwt_refresh_secret',
  'apikey',
  'x-api-key',
  'authorization',
])

const MAX_PAYLOAD_BYTES = 32 * 1024 // 32 KB limit
const MAX_HISTORY_BUFFER = 200 // Maximum events retained in outbox ring buffer
const DEDUPLICATION_WINDOW_SIZE = 1000 // Number of recent event IDs to track for duplicate rejection

/**
 * Sanitizes payload objects to redact sensitive secrets and prevent prototype pollution.
 */
function sanitizePayload(obj, depth = 0) {
  if (depth > 5 || obj === null || obj === undefined) return obj
  if (typeof obj !== 'object') return obj

  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizePayload(item, depth + 1))
  }

  const clean = {}
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase()
    if (['__proto__', 'constructor', 'prototype'].includes(lowerKey)) continue

    if (SENSITIVE_KEYS.has(lowerKey)) {
      clean[key] = '***REDACTED***'
    } else if (typeof value === 'object' && value !== null) {
      clean[key] = sanitizePayload(value, depth + 1)
    } else {
      clean[key] = value
    }
  }
  return clean
}

/**
 * Abstract Outbox Storage Contract
 */
class OutboxStore {
  async persistEnvelope(_envelope) {
    throw new Error('persistEnvelope() must be implemented by subclass')
  }
  async markDelivered(_eventId) {
    throw new Error('markDelivered() must be implemented by subclass')
  }
  async markFailed(_eventId, _error) {
    throw new Error('markFailed() must be implemented by subclass')
  }
  async getPendingEvents() {
    throw new Error('getPendingEvents() must be implemented by subclass')
  }
  async getFailedEvents() {
    return []
  }
  async redriveFailedEvents() {
    return 0
  }
  async getOutboxStats() {
    return { total: 0, pending: 0, delivered: 0, failed: 0 }
  }
}

/**
 * In-Memory Outbox Store for testing and transient lifecycle recovery
 */
class InMemoryOutboxStore extends OutboxStore {
  constructor() {
    super()
    this.records = new Map()
  }

  async persistEnvelope(envelope) {
    this.records.set(envelope.eventId, {
      envelope,
      status: 'PENDING',
      attempts: 0,
      createdAt: new Date().toISOString(),
      lastError: null,
    })
    return true
  }

  async markDelivered(eventId) {
    const rec = this.records.get(eventId)
    if (rec) {
      rec.status = 'DELIVERED'
      rec.deliveredAt = new Date().toISOString()
    }
  }

  async markFailed(eventId, err) {
    const rec = this.records.get(eventId)
    if (rec) {
      rec.attempts++
      rec.lastError = err ? err.message || String(err) : 'Unknown error'
      rec.status = rec.attempts >= 3 ? 'FAILED' : 'PENDING'
    }
  }

  async getPendingEvents() {
    const pending = []
    for (const rec of this.records.values()) {
      if (rec.status === 'PENDING') {
        pending.push(rec.envelope)
      }
    }
    return pending
  }

  async getFailedEvents() {
    const failed = []
    for (const rec of this.records.values()) {
      if (rec.status === 'FAILED') {
        failed.push({
          envelope: rec.envelope,
          attempts: rec.attempts,
          lastError: rec.lastError,
          createdAt: rec.createdAt,
        })
      }
    }
    return failed
  }

  async redriveFailedEvents() {
    let count = 0
    for (const rec of this.records.values()) {
      if (rec.status === 'FAILED') {
        rec.status = 'PENDING'
        rec.attempts = 0
        rec.lastError = `Manual redrive at ${new Date().toISOString()}`
        count++
      }
    }
    return count
  }

  async getOutboxStats() {
    const values = Array.from(this.records.values())
    return {
      total: values.length,
      pending: values.filter((r) => r.status === 'PENDING').length,
      delivered: values.filter((r) => r.status === 'DELIVERED').length,
      failed: values.filter((r) => r.status === 'FAILED').length,
    }
  }
}

/**
 * Persistent File-Based Outbox Store surviving Node.js process crashes and restarts
 */
class FileOutboxStore extends OutboxStore {
  constructor(filePath) {
    super()
    const path = require('path')
    this.filePath = filePath || path.join(__dirname, '..', 'logs', 'event_outbox.json')
    this._ensureFile()
  }

  _ensureFile() {
    const fs = require('fs')
    const path = require('path')
    try {
      const dir = path.dirname(this.filePath)
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
      if (!fs.existsSync(this.filePath)) fs.writeFileSync(this.filePath, JSON.stringify({}), 'utf8')
    } catch (err) {
      logger.error(`[FileOutboxStore] Failed to ensure directory/file: ${err.message}`)
    }
  }

  _readAll() {
    const fs = require('fs')
    try {
      this._ensureFile()
      const data = fs.readFileSync(this.filePath, 'utf8')
      return JSON.parse(data || '{}')
    } catch (parseErr) {
      logger.warn(`[FileOutboxStore] Parse error reading ${this.filePath}: ${parseErr.message}`)
      try {
        // Preserve corrupted file for forensics rather than silently deleting it
        const corruptBackup = `${this.filePath}.corrupt.${Date.now()}`
        if (fs.existsSync(this.filePath)) {
          fs.copyFileSync(this.filePath, corruptBackup)
          logger.warn(`[FileOutboxStore] Corrupted outbox file preserved as: ${corruptBackup}`)
        }
      } catch (_) {}
      return {}
    }
  }

  _prune(data) {
    const entries = Object.entries(data)
    if (entries.length > 300) {
      const delivered = entries.filter(([_, rec]) => rec.status === 'DELIVERED')
      if (delivered.length > 100) {
        // Prune the oldest delivered entries
        const toPrune = delivered.slice(0, delivered.length - 100)
        for (const [k] of toPrune) {
          delete data[k]
        }
      }
    }
  }

  _writeAll(data) {
    const fs = require('fs')
    this._prune(data)
    const jsonStr = JSON.stringify(data, null, 2)
    const tmpPath = `${this.filePath}.tmp.${Date.now()}_${Math.random().toString(36).substring(2, 8)}`

    try {
      this._ensureFile()
      // Atomic write: write to temp file then atomic move/copy
      fs.writeFileSync(tmpPath, jsonStr, 'utf8')
      try {
        fs.renameSync(tmpPath, this.filePath)
      } catch {
        // Windows fallback if destination is open
        fs.copyFileSync(tmpPath, this.filePath)
        try {
          fs.unlinkSync(tmpPath)
        } catch (_) {}
      }
    } catch (writeErr) {
      logger.error(`[FileOutboxStore] Atomic write failed: ${writeErr.message}`)
      try {
        if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath)
      } catch (_) {}
      throw writeErr
    }
  }

  async persistEnvelope(envelope) {
    const data = this._readAll()
    data[envelope.eventId] = {
      envelope,
      status: 'PENDING',
      attempts: 0,
      createdAt: new Date().toISOString(),
      lastError: null,
    }
    this._writeAll(data)
    return true
  }

  async markDelivered(eventId) {
    const data = this._readAll()
    if (data[eventId]) {
      data[eventId].status = 'DELIVERED'
      data[eventId].deliveredAt = new Date().toISOString()
      this._writeAll(data)
    }
  }

  async markFailed(eventId, err) {
    const data = this._readAll()
    if (data[eventId]) {
      data[eventId].attempts = (data[eventId].attempts || 0) + 1
      data[eventId].lastError = err ? err.message || String(err) : 'Unknown error'
      data[eventId].status = data[eventId].attempts >= 3 ? 'FAILED' : 'PENDING'
      this._writeAll(data)
    }
  }

  async getPendingEvents() {
    const data = this._readAll()
    return Object.values(data)
      .filter((rec) => rec.status === 'PENDING')
      .map((rec) => rec.envelope)
  }

  async getFailedEvents() {
    const data = this._readAll()
    return Object.values(data)
      .filter((rec) => rec.status === 'FAILED')
      .map((rec) => ({
        envelope: rec.envelope,
        attempts: rec.attempts,
        lastError: rec.lastError,
        createdAt: rec.createdAt,
      }))
  }

  async redriveFailedEvents() {
    const data = this._readAll()
    let count = 0
    for (const rec of Object.values(data)) {
      if (rec.status === 'FAILED') {
        rec.status = 'PENDING'
        rec.attempts = 0
        rec.lastError = `Manual redrive at ${new Date().toISOString()}`
        count++
      }
    }
    if (count > 0) {
      this._writeAll(data)
    }
    return count
  }

  async getOutboxStats() {
    const data = this._readAll()
    const values = Object.values(data)
    return {
      total: values.length,
      pending: values.filter((r) => r.status === 'PENDING').length,
      delivered: values.filter((r) => r.status === 'DELIVERED').length,
      failed: values.filter((r) => r.status === 'FAILED').length,
      filePath: this.filePath,
    }
  }
}

/**
 * Standard Security Event Bus & Distribution Engine
 */
class SecurityEventBus {
  constructor(options = {}) {
    this.maxHistory = options.maxHistory || MAX_HISTORY_BUFFER
    this.dedupSize = options.dedupSize || DEDUPLICATION_WINDOW_SIZE
    this.outboxStore = options.outboxStore || null
    this.history = []
    this.seenEventIds = new Set()
    this.seenQueue = [] // FIFO queue to manage sliding deduplication window
    this.subscribers = new Map()
    this.metrics = {
      published: 0,
      duplicates: 0,
      dropped: 0,
      durablePersisted: 0,
      outboxReplayed: 0,
    }
  }

  getMetrics() {
    return {
      ...this.metrics,
      outboxDepth: this.history.length,
      subscriberTypesCount: this.subscribers.size,
      hasOutboxStore: !!this.outboxStore,
    }
  }

  /**
   * Constructs and validates a standardized security event envelope.
   */
  createEnvelope({ eventType, payload, source = 'sentinelai-backend', correlationId = null, eventId = null }) {
    if (!eventType || typeof eventType !== 'string' || !ALLOWED_EVENT_TYPES.has(eventType)) {
      throw new Error(`Invalid or unsupported eventType: ${eventType}`)
    }

    if (!payload || typeof payload !== 'object') {
      throw new Error('Event payload must be a non-null object')
    }

    const sanitized = sanitizePayload(payload)
    const jsonStr = JSON.stringify(sanitized)
    if (Buffer.byteLength(jsonStr, 'utf8') > MAX_PAYLOAD_BYTES) {
      throw new Error(`Event payload exceeds maximum permitted size (${MAX_PAYLOAD_BYTES} bytes)`)
    }

    return {
      eventId: eventId || crypto.randomUUID(),
      eventType,
      source,
      version: '1.0',
      timestamp: new Date().toISOString(),
      correlationId: correlationId || payload.id || payload._id || null,
      payload: sanitized,
    }
  }

  /**
   * Deduplication check using a bounded sliding window.
   */
  isDuplicate(eventId) {
    return this.seenEventIds.has(eventId)
  }

  _recordSeen(eventId) {
    this.seenEventIds.add(eventId)
    this.seenQueue.push(eventId)
    if (this.seenQueue.length > this.dedupSize) {
      const oldest = this.seenQueue.shift()
      this.seenEventIds.delete(oldest)
    }
  }

  /**
   * Appends an event envelope to the ring buffer for delivery replay.
   */
  _addToHistory(envelope) {
    this.history.push(envelope)
    if (this.history.length > this.maxHistory) {
      this.history.shift()
    }
  }

  /**
   * Publishes an event through the security bus to in-process subscribers and WebSocket clients.
   */
  publish(eventInput, io = null) {
    let envelope
    try {
      envelope = eventInput.eventId && eventInput.version ? eventInput : this.createEnvelope(eventInput)
    } catch (err) {
      this.metrics.dropped++
      throw err
    }

    if (this.isDuplicate(envelope.eventId)) {
      this.metrics.duplicates++
      logger.debug(`[EventBus] Duplicate event ${envelope.eventId} skipped`)
      return { success: false, eventId: envelope.eventId, status: 'duplicate_skipped' }
    }

    this._recordSeen(envelope.eventId)
    this._addToHistory(envelope)
    this.metrics.published++

    // Notify internal subscribers
    let hasHandlerErrors = false
    let lastHandlerError = null
    const handlers = this.subscribers.get(envelope.eventType) || []
    for (const fn of handlers) {
      try {
        fn(envelope)
      } catch (err) {
        hasHandlerErrors = true
        lastHandlerError = err
        logger.error(`[EventBus] Handler error for ${envelope.eventType}: ${err.message}`)
      }
    }

    // Deliver via WebSocket if IO instance provided
    if (io) {
      this._broadcastToWebSockets(envelope, io)
    }

    return {
      success: !hasHandlerErrors,
      eventId: envelope.eventId,
      eventType: envelope.eventType,
      status: hasHandlerErrors ? 'partial_delivery_error' : 'published',
      error: lastHandlerError ? lastHandlerError.message : null,
      timestamp: envelope.timestamp,
    }
  }

  /**
   * Guarantees durable state changes before describing an event as published.
   * If persistFn fails, the event is marked dropped and is NOT emitted.
   * When an outboxStore is configured, also persists envelope and tracks delivery confirmation.
   */
  async publishDurable(eventInput, persistFn, io = null) {
    const envelope = eventInput.eventId && eventInput.version ? eventInput : this.createEnvelope(eventInput)
    if (typeof persistFn !== 'function') {
      throw new Error('publishDurable requires a persistFn callback')
    }

    try {
      await persistFn(envelope)
      this.metrics.durablePersisted++
    } catch (persistErr) {
      this.metrics.dropped++
      logger.error(`[EventBus] Durable persistence failed for ${envelope.eventId}: ${persistErr.message}`)
      throw persistErr
    }

    if (this.outboxStore) {
      try {
        await this.outboxStore.persistEnvelope(envelope)
      } catch (storeErr) {
        logger.error(`[EventBus] Outbox store persistence failed for ${envelope.eventId}: ${storeErr.message}`)
      }
    }

    let publishResult
    try {
      publishResult = this.publish(envelope, io)
      if (this.outboxStore) {
        if (publishResult && publishResult.success) {
          await this.outboxStore.markDelivered(envelope.eventId)
        } else {
          const errObj =
            publishResult && publishResult.error
              ? new Error(publishResult.error)
              : new Error(publishResult ? publishResult.status : 'delivery_failed')
          await this.outboxStore.markFailed(envelope.eventId, errObj)
        }
      }
    } catch (pubErr) {
      if (this.outboxStore) {
        await this.outboxStore.markFailed(envelope.eventId, pubErr)
      }
      throw pubErr
    }

    return publishResult
  }

  /**
   * Recovers and replays pending outbox events across process restart or transient subscriber failure.
   */
  async replayPendingOutbox(io = null) {
    if (!this.outboxStore) {
      return { replayed: 0, failed: 0, pending: 0 }
    }
    const pendingEvents = await this.outboxStore.getPendingEvents()
    let replayed = 0
    let failed = 0
    for (const envelope of pendingEvents) {
      try {
        // Clear seen deduplication entry in current bus instance to allow re-emission
        this.seenEventIds.delete(envelope.eventId)
        const res = this.publish(envelope, io)
        if (res && res.success) {
          await this.outboxStore.markDelivered(envelope.eventId)
          replayed++
          this.metrics.outboxReplayed++
        } else {
          const errObj = res && res.error ? new Error(res.error) : new Error(res ? res.status : 'replay_failed')
          await this.outboxStore.markFailed(envelope.eventId, errObj)
          failed++
        }
      } catch (err) {
        await this.outboxStore.markFailed(envelope.eventId, err)
        failed++
      }
    }
    return { replayed, failed, pending: pendingEvents.length }
  }

  /**
   * Returns operational visibility metrics into outbox store contents.
   */
  async getOutboxStatus() {
    if (!this.outboxStore || typeof this.outboxStore.getOutboxStats !== 'function') {
      return { supported: false }
    }
    const stats = await this.outboxStore.getOutboxStats()
    return { supported: true, ...stats }
  }

  /**
   * Manually redrives all poisoned / failed events back to PENDING.
   */
  async redriveFailedOutbox() {
    if (!this.outboxStore || typeof this.outboxStore.redriveFailedEvents !== 'function') {
      return { redriven: 0 }
    }
    const redriven = await this.outboxStore.redriveFailedEvents()
    return { redriven }
  }

  _broadcastToWebSockets(envelope, io) {
    try {
      const { redactThreat, redactIP, redactAlert, redactAIPrediction } = require('./redact')

      const privilegedRooms = ['admin', 'analyst', 'threat_subscribers_privileged']
      io.to(privilegedRooms).emit('security_event', envelope)

      let redactedPayload = envelope.payload
      if (envelope.eventType === 'THREAT_DETECTED' || envelope.eventType === 'THREAT_UPDATED') {
        redactedPayload = redactThreat(envelope.payload, 'viewer')
      } else if (envelope.eventType === 'ALERT_CREATED') {
        redactedPayload = redactAlert(envelope.payload, 'viewer')
      } else if (envelope.eventType === 'AI_PREDICTION') {
        redactedPayload = redactAIPrediction(envelope.payload, 'viewer')
      }

      io.to('all').emit('security_event', {
        ...envelope,
        payload: redactedPayload,
      })

      // Backward-compatibility: route to specific legacy channels based on eventType
      switch (envelope.eventType) {
        case 'THREAT_DETECTED':
          io.to(privilegedRooms).emit('new_threat', envelope.payload)
          io.to(['threat_subscribers', 'all']).emit('new_threat', redactedPayload)
          if (envelope.payload.severity === 'CRITICAL') {
            io.to('admin').emit('critical_alert', { ...envelope.payload, urgency: 'IMMEDIATE' })
          }
          break
        case 'THREAT_UPDATED':
          io.to(privilegedRooms).emit('threat_updated', envelope.payload)
          io.to(['viewer', 'threat_subscribers_viewer', 'threat_subscribers', 'all']).emit('threat_updated', {
            ...envelope.payload,
            sourceIP: redactIP(envelope.payload.sourceIP),
          })
          break
        case 'ALERT_CREATED': {
          const targetRooms = envelope.payload.targetRoles || ['analyst']
          io.to(targetRooms.filter((r) => r !== 'viewer')).emit('new_alert', envelope.payload)
          io.to(['viewer', 'all']).emit('new_alert', redactedPayload)
          break
        }
        case 'AI_PREDICTION':
          io.to(privilegedRooms).emit('ai_prediction', envelope.payload)
          io.to(['viewer', 'threat_subscribers_viewer', 'threat_subscribers', 'all']).emit(
            'ai_prediction',
            redactedPayload
          )
          break
        default:
          break
      }
    } catch (wsErr) {
      logger.warn(`[EventBus] WebSocket publication warning: ${wsErr.message}`)
    }
  }

  /**
   * Subscribe to specific event types in-process.
   */
  subscribe(eventType, handler) {
    if (!this.subscribers.has(eventType)) {
      this.subscribers.set(eventType, [])
    }
    this.subscribers.get(eventType).push(handler)
    return () => {
      const list = this.subscribers.get(eventType) || []
      const idx = list.indexOf(handler)
      if (idx !== -1) list.splice(idx, 1)
    }
  }

  /**
   * Returns recent events matching optional filter or after a given timestamp.
   */
  getHistory({ since = null, eventType = null, limit = 50 } = {}) {
    let result = this.history
    if (since) {
      const sinceDate = new Date(since).getTime()
      result = result.filter((e) => new Date(e.timestamp).getTime() > sinceDate)
    }
    if (eventType) {
      result = result.filter((e) => e.eventType === eventType)
    }
    return result.slice(-Math.min(limit, this.maxHistory))
  }
}

/**
 * MongoDB-backed outbox (OUTBOX_STORE=mongo): survives restarts and works across API workers.
 */
class MongoOutboxStore extends OutboxStore {
  _model() {
    return require('../models/OutboxEvent')
  }

  _retentionMs() {
    const days = parseInt(process.env.OUTBOX_RETENTION_DAYS, 10)
    return (Number.isInteger(days) && days > 0 ? days : 7) * 86400000
  }

  async persistEnvelope(envelope) {
    await this._model().updateOne(
      { eventId: envelope.eventId },
      { $setOnInsert: { eventId: envelope.eventId, eventType: envelope.eventType, envelope, status: 'PENDING' } },
      { upsert: true }
    )
    return true
  }

  async markDelivered(eventId) {
    const now = new Date()
    await this._model().updateOne(
      { eventId },
      { $set: { status: 'DELIVERED', deliveredAt: now, expiresAt: new Date(now.getTime() + this._retentionMs()) } }
    )
  }

  async markFailed(eventId, err) {
    const Model = this._model()
    const rec = await Model.findOneAndUpdate(
      { eventId },
      { $inc: { attempts: 1 }, $set: { lastError: err ? err.message || String(err) : 'Unknown error' } },
      { new: true }
    )
    if (rec && rec.attempts >= 3) await Model.updateOne({ eventId }, { $set: { status: 'FAILED' } })
  }

  async getPendingEvents() {
    const rows = await this._model().find({ status: 'PENDING' }).sort({ createdAt: 1 }).limit(500).lean()
    return rows.map((r) => r.envelope)
  }

  async getFailedEvents() {
    const rows = await this._model().find({ status: 'FAILED' }).sort({ createdAt: 1 }).limit(500).lean()
    return rows.map((r) => ({
      envelope: r.envelope,
      attempts: r.attempts,
      lastError: r.lastError,
      createdAt: r.createdAt,
    }))
  }

  async redriveFailedEvents() {
    const res = await this._model().updateMany(
      { status: 'FAILED' },
      { $set: { status: 'PENDING', attempts: 0, lastError: `Manual redrive at ${new Date().toISOString()}` } }
    )
    return res.modifiedCount || 0
  }

  async getOutboxStats() {
    const Model = this._model()
    const [total, pending, delivered, failed] = await Promise.all([
      Model.estimatedDocumentCount(),
      Model.countDocuments({ status: 'PENDING' }),
      Model.countDocuments({ status: 'DELIVERED' }),
      Model.countDocuments({ status: 'FAILED' }),
    ])
    return { total, pending, delivered, failed }
  }
}

const storeFromEnv = (env = process.env) => {
  if (env.OUTBOX_STORE === 'mongo') return new MongoOutboxStore()
  if (env.OUTBOX_STORE === 'file') return new FileOutboxStore(env.OUTBOX_FILE || undefined)
  return null
}

/**
 * Records an event that was already delivered over Socket.IO: it enters the bus history, subscribers and
 * metrics, and (with an outbox store) a durable DELIVERED record. Never throws into the caller's path.
 */
SecurityEventBus.prototype.recordDelivered = function (eventInput) {
  try {
    const result = this.publish(eventInput)
    if (this.outboxStore && result.status === 'published') {
      const envelope = this.history[this.history.length - 1]
      Promise.resolve(this.outboxStore.persistEnvelope(envelope))
        .then(() => this.outboxStore.markDelivered(envelope.eventId))
        .catch((err) => logger.debug(`[EventBus] Outbox record failed: ${err.message}`))
    }
    return result
  } catch (err) {
    logger.debug(`[EventBus] Event not recorded: ${err.message}`)
    return { success: false, status: 'not_recorded', error: err.message }
  }
}

const defaultSecurityEventBus = new SecurityEventBus({ outboxStore: storeFromEnv() })

module.exports = {
  SecurityEventBus,
  defaultSecurityEventBus,
  ALLOWED_EVENT_TYPES,
  sanitizePayload,
  OutboxStore,
  InMemoryOutboxStore,
  FileOutboxStore,
  MongoOutboxStore,
  storeFromEnv,
}
