'use strict'

const express = require('express')
const router = express.Router()
const {
  requestContainment,
  rollbackContainment,
  getActions,
  getAction,
  getStatus,
} = require('../controllers/containmentController')
const { protect, restrictTo } = require('../middleware/auth')

// All containment endpoints require authentication and active session
router.use(protect)

/**
 * @openapi
 * /containment/status:
 *   get:
 *     tags:
 *       - Containment & Response
 *     summary: Retrieve current status of containment subsystem and active backend
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Subsystem status retrieved
 */
router.get('/status', restrictTo('admin', 'analyst'), getStatus)

/**
 * @openapi
 * /containment/actions:
 *   get:
 *     tags:
 *       - Containment & Response
 *     summary: List containment actions with pagination and filters
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of containment actions
 *   post:
 *     tags:
 *       - Containment & Response
 *     summary: Request a new containment action governed by policy engine
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - target
 *             properties:
 *               target:
 *                 type: string
 *               actionType:
 *                 type: string
 *                 enum: [block_ip, isolate_host, rate_limit]
 *               durationSeconds:
 *                 type: integer
 *               isPermanent:
 *                 type: boolean
 *               reason:
 *                 type: string
 *     responses:
 *       201:
 *         description: Action created and applying/active
 *       400:
 *         description: Validation error
 *       403:
 *         description: Policy rejected or unauthorized
 */
router
  .route('/actions')
  .get(restrictTo('admin', 'analyst'), getActions)
  .post(restrictTo('admin', 'analyst'), requestContainment)

/**
 * @openapi
 * /containment/actions/{id}:
 *   get:
 *     tags:
 *       - Containment & Response
 *     summary: Get details of a single containment action
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
 *         description: Containment action details
 *       404:
 *         description: Not found
 */
router.get('/actions/:id', restrictTo('admin', 'analyst'), getAction)

/**
 * @openapi
 * /containment/actions/{id}/rollback:
 *   post:
 *     tags:
 *       - Containment & Response
 *     summary: Rollback an active containment action
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
 *         description: Containment action rolled back
 *       400:
 *         description: Invalid state for rollback
 *       404:
 *         description: Action not found
 */
router.post('/actions/:id/rollback', restrictTo('admin', 'analyst'), rollbackContainment)

module.exports = router
