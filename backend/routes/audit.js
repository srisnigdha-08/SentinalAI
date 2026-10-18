'use strict'

const express = require('express')
const router = express.Router()
const AuditLog = require('../models/AuditLog')
const { protect, requirePermission } = require('../middleware/auth')
const { sendPaginated, sendError } = require('../utils/apiResponse')
const { parsePagination, escapeRegex } = require('../utils/querySecurity')

router.use(protect)
router.use(requirePermission('audit:read'))

/**
 * @openapi
 * /audit:
 *   get:
 *     tags:
 *       - Audit Logs
 *     summary: Retrieve system security audit log trail (Admin only)
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema: { type: integer, default: 1 }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 20 }
 *       - in: query
 *         name: action
 *         schema: { type: string }
 *       - in: query
 *         name: status
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Paginated audit logs
 *       403:
 *         description: Insufficient permissions
 */
router.get('/', async (req, res, next) => {
  try {
    const { page = 1, limit = 20, action, status, search } = req.query
    const {
      page: safePage,
      limit: safeLimit,
      skip,
    } = parsePagination({
      page,
      limit,
      defaultLimit: 20,
      maxLimit: 100,
    })

    const filter = {}
    if (action && typeof action === 'string') {
      filter.action = action.trim()
    }
    if (status && typeof status === 'string') {
      filter.status = status.trim().toUpperCase()
    }

    const safeSearch = escapeRegex(search)
    if (safeSearch) {
      filter.$or = [
        { action: { $regex: safeSearch, $options: 'i' } },
        { 'actor.email': { $regex: safeSearch, $options: 'i' } },
        { 'target.identifier': { $regex: safeSearch, $options: 'i' } },
      ]
    }

    const total = await AuditLog.countDocuments(filter)
    const logs = await AuditLog.find(filter).sort({ createdAt: -1 }).skip(skip).limit(safeLimit).lean()

    sendPaginated(res, logs, total, safePage, safeLimit)
  } catch (err) {
    next(err)
  }
})

module.exports = router
