'use strict'

const containmentService = require('../services/containmentService')
const ContainmentAction = require('../models/ContainmentAction')
const { sendSuccess, sendError, sendPaginated } = require('../utils/apiResponse')
const { parsePagination, escapeRegex } = require('../utils/querySecurity')

/**
 * POST /api/containment/actions
 * Requests a new containment action governed by policy engine.
 */
const requestContainment = async (req, res, next) => {
  try {
    const { target, actionType, durationSeconds, isPermanent, reason, idempotencyKey, threatRef, metadata } =
      req.body || {}

    if (!target || typeof target !== 'string' || !target.trim()) {
      return sendError(res, 'Target IP or CIDR is required', 400)
    }

    const result = await containmentService.requestContainment({
      target: target.trim(),
      actionType,
      durationSeconds,
      isPermanent: isPermanent === true,
      reason,
      requester: req.user,
      idempotencyKey,
      threatRef,
      metadata,
    })

    const statusCode = result.alreadyActive || result.idempotent ? 200 : 201
    sendSuccess(res, { action: result.action }, 'Containment action processed', statusCode)
  } catch (err) {
    if (err.statusCode) {
      return sendError(res, err.message, err.statusCode, { action: err.action })
    }
    next(err)
  }
}

/**
 * POST /api/containment/actions/:id/rollback
 * Rolls back an active containment action.
 */
const rollbackContainment = async (req, res, next) => {
  try {
    const { id } = req.params
    const { reason } = req.body || {}

    const result = await containmentService.rollbackContainment({
      containmentId: id,
      operator: req.user,
      reason: reason || 'Manual operator rollback',
    })

    sendSuccess(res, { action: result.action }, 'Containment action rolled back successfully')
  } catch (err) {
    if (err.statusCode) {
      return sendError(res, err.message, err.statusCode, { action: err.action })
    }
    next(err)
  }
}

/**
 * GET /api/containment/actions
 * Lists containment actions with filtering and pagination.
 */
const getActions = async (req, res, next) => {
  try {
    const { page = 1, limit = 20, status, target, backend } = req.query
    const {
      limit: safeLimit,
      skip,
      page: safePage,
    } = parsePagination({
      page,
      limit,
      defaultLimit: 20,
      maxLimit: 100,
    })

    const filter = {}
    if (status && typeof status === 'string') {
      filter.enforcementStatus = status.trim().toUpperCase()
    }
    if (backend && typeof backend === 'string') {
      filter.enforcementBackend = backend.trim().toLowerCase()
    }
    if (target && typeof target === 'string') {
      const sanitized = escapeRegex(target.trim(), 100)
      if (sanitized) {
        filter.normalizedTarget = { $regex: sanitized, $options: 'i' }
      }
    }

    const [total, actions] = await Promise.all([
      ContainmentAction.countDocuments(filter),
      ContainmentAction.find(filter)
        .populate('requestedBy', 'name email role')
        .populate('approvedBy', 'name email role')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(safeLimit)
        .lean(),
    ])

    sendPaginated(res, actions, total, safePage, safeLimit)
  } catch (err) {
    next(err)
  }
}

/**
 * GET /api/containment/actions/:id
 * Retrieves a single containment action by containmentId or Mongo _id.
 */
const getAction = async (req, res, next) => {
  try {
    const { id } = req.params
    let action = await ContainmentAction.findOne({ containmentId: id })
      .populate('requestedBy', 'name email role')
      .populate('approvedBy', 'name email role')
      .lean()

    if (!action && id.match(/^[0-9a-fA-F]{24}$/)) {
      action = await ContainmentAction.findById(id)
        .populate('requestedBy', 'name email role')
        .populate('approvedBy', 'name email role')
        .lean()
    }

    if (!action) {
      return sendError(res, 'Containment action not found', 404)
    }

    sendSuccess(res, { action })
  } catch (err) {
    next(err)
  }
}

/**
 * GET /api/containment/status
 * Returns current status of the containment subsystem.
 */
const getStatus = async (req, res, next) => {
  try {
    const status = await containmentService.getContainmentStatus()
    sendSuccess(res, status)
  } catch (err) {
    next(err)
  }
}

module.exports = {
  requestContainment,
  rollbackContainment,
  getActions,
  getAction,
  getStatus,
}
