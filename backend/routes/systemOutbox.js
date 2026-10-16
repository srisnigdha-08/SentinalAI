'use strict'

const express = require('express')
const router = express.Router()
const { defaultSecurityEventBus } = require('../utils/securityEventBus')
const { defaultSecurityAuditLogger } = require('../utils/securityAuditLogger')
const { protect, restrictTo } = require('../middleware/auth')
const { sendSuccess, sendError } = require('../utils/apiResponse')

// All outbox management routes require authentication
router.use(protect)

/**
 * GET /api/system/outbox/status
 * Returns operational metrics on outbox event queue (Admin & Analyst).
 */
router.get('/status', restrictTo('admin', 'analyst'), async (req, res) => {
  try {
    const stats = await defaultSecurityEventBus.getOutboxStatus()
    return sendSuccess(res, stats, 'Outbox operational status retrieved')
  } catch (err) {
    return sendError(res, err.message, 500)
  }
})

/**
 * GET /api/system/outbox/failed
 * Returns quarantined / failed poison-pill events (Admin only).
 */
router.get('/failed', restrictTo('admin'), async (req, res) => {
  try {
    if (!defaultSecurityEventBus.outboxStore || typeof defaultSecurityEventBus.outboxStore.getFailedEvents !== 'function') {
      return sendSuccess(res, { failed: [] }, 'No failed events store configured')
    }
    const failed = await defaultSecurityEventBus.outboxStore.getFailedEvents()
    return sendSuccess(res, { failed }, 'Failed outbox events retrieved')
  } catch (err) {
    return sendError(res, err.message, 500)
  }
})

/**
 * POST /api/system/outbox/redrive
 * Manually redrives failed events back to PENDING (Admin only, audited).
 */
router.post('/redrive', restrictTo('admin'), async (req, res) => {
  try {
    const result = await defaultSecurityEventBus.redriveFailedOutbox()

    // Structured security audit log
    defaultSecurityAuditLogger.logEvent({
      eventType: 'OUTBOX_REDRIVE',
      action: 'MANUAL_REDRIVE',
      status: 'EXECUTED',
      actor: {
        id: req.user?._id || req.user?.id,
        role: req.user?.role,
        email: req.user?.email,
      },
      details: {
        redrivenCount: result.redriven,
      },
    })

    return sendSuccess(res, result, `Successfully redriven ${result.redriven} failed events`)
  } catch (err) {
    return sendError(res, err.message, 500)
  }
})

module.exports = router
