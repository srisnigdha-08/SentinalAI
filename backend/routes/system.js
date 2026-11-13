const express = require('express')
const router = express.Router()
const { protect } = require('../middleware/auth')
const { sendSuccess } = require('../utils/apiResponse')

// Per-route protect (not router.use): this router shares the /api/system prefix with other routes.

/**
 * @openapi
 * /system/capture:
 *   get:
 *     tags:
 *       - System
 *     summary: Network capture status (live_passive | pcap_replay | unavailable)
 *     responses:
 *       200:
 *         description: Capture status; a replay is never reported as live
 */
router.get('/capture', protect, (req, res) => {
  sendSuccess(res, require('../services/captureStatusService').getStatus())
})

/**
 * @openapi
 * /system/capabilities:
 *   get:
 *     tags:
 *       - System
 *     summary: What is implemented, enabled, simulated, shadow-only, experimental or blocked right now
 *     responses:
 *       200:
 *         description: Capability list with labels and the facts behind them
 */
router.get('/capabilities', protect, async (req, res, next) => {
  try {
    sendSuccess(res, await require('../services/capabilityService').getCapabilities())
  } catch (err) {
    next(err)
  }
})

module.exports = router
