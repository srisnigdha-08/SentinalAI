'use strict'

const express = require('express')
const router = express.Router()
const trainingSampleService = require('../services/trainingSampleService')
const { sendSuccess, sendError, sendPaginated } = require('../utils/apiResponse')
const { protect, restrictTo } = require('../middleware/auth')
const { validateObjectId } = require('../middleware/validate')

/**
 * @openapi
 * /training-samples:
 *   get:
 *     tags:
 *       - Training Samples
 *     summary: Retrieve paginated list of training samples in quarantine pipeline
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Paginated training samples
 */
router.get('/', protect, restrictTo('admin', 'analyst'), async (req, res, next) => {
  try {
    const result = await trainingSampleService.listSamples(req.query)
    sendPaginated(res, result.data, result.total, result.page, result.limit)
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /training-samples/{id}:
 *   get:
 *     tags:
 *       - Training Samples
 *     summary: Retrieve details of a specific training sample
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Training sample details
 *       404:
 *         description: Training sample not found
 */
router.get('/:id', protect, validateObjectId, restrictTo('admin', 'analyst'), async (req, res, next) => {
  try {
    const sample = await trainingSampleService.getSampleById(req.params.id)
    if (!sample) return sendError(res, 'Training sample not found', 404)
    sendSuccess(res, { sample })
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /training-samples/ingest/{id}:
 *   post:
 *     tags:
 *       - Training Samples
 *     summary: Explicitly ingest a verified AIPrediction into QUARANTINED state
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       201:
 *         description: Training sample candidate ingested
 *       400:
 *         description: Ineligible prediction
 *       404:
 *         description: Prediction not found
 */
router.post('/ingest/:id', protect, validateObjectId, restrictTo('admin', 'analyst'), async (req, res, next) => {
  try {
    const sample = await trainingSampleService.ingestPredictionCandidate(req.params.id, req.body || {})
    sendSuccess(res, { sample }, 'Training sample candidate ingested into QUARANTINED state', 201)
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /training-samples/{id}/validate:
 *   post:
 *     tags:
 *       - Training Samples
 *     summary: Admin validation of a quarantined sample (enforces dual-control)
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Sample validated
 *       400:
 *         description: Validation failed or dual-control violation
 *       403:
 *         description: Forbidden (Admin only)
 */
router.post('/:id/validate', protect, validateObjectId, restrictTo('admin'), async (req, res, next) => {
  try {
    const metadata = {
      bypassDualControl: Boolean(req.body?.bypassDualControl),
    }
    const sample = await trainingSampleService.transitionSampleStatus(req.params.id, 'VALIDATED', req.user, metadata)
    sendSuccess(res, { sample }, 'Sample validated successfully')
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /training-samples/{id}/reject:
 *   post:
 *     tags:
 *       - Training Samples
 *     summary: Reject a quarantined or validated sample
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Sample rejected
 *       400:
 *         description: Missing reason or invalid state
 */
router.post('/:id/reject', protect, validateObjectId, restrictTo('admin', 'analyst'), async (req, res, next) => {
  try {
    const reason = req.body?.reason
    if (!reason || typeof reason !== 'string' || !reason.trim()) {
      return sendError(res, 'Rejection reason is required in request body', 400)
    }
    const sample = await trainingSampleService.transitionSampleStatus(req.params.id, 'REJECTED', req.user, {
      reason: reason.trim(),
    })
    sendSuccess(res, { sample }, 'Sample rejected')
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /training-samples/{id}/promote:
 *   post:
 *     tags:
 *       - Training Samples
 *     summary: Promote a validated sample to ELIGIBLE_FOR_TRAINING
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Sample promoted to ELIGIBLE_FOR_TRAINING
 *       400:
 *         description: Promotion failed or cooldown active
 */
router.post('/:id/promote', protect, validateObjectId, restrictTo('admin'), async (req, res, next) => {
  try {
    const sample = await trainingSampleService.transitionSampleStatus(req.params.id, 'ELIGIBLE_FOR_TRAINING', req.user)
    sendSuccess(res, { sample }, 'Sample promoted to ELIGIBLE_FOR_TRAINING')
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /training-samples/{id}/supersede:
 *   post:
 *     tags:
 *       - Training Samples
 *     summary: Manually supersede an active training sample
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Sample superseded
 *       400:
 *         description: Supersede failed
 */
router.post('/:id/supersede', protect, validateObjectId, restrictTo('admin'), async (req, res, next) => {
  try {
    const reason = req.body?.reason || 'Manually superseded by administrator'
    const sample = await trainingSampleService.transitionSampleStatus(req.params.id, 'SUPERSEDED', req.user, { reason })
    sendSuccess(res, { sample }, 'Sample superseded')
  } catch (err) {
    next(err)
  }
})

module.exports = router
