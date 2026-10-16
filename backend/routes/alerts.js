const express = require('express')
const router = express.Router()
const {
  getAlerts,
  getUnreadCount,
  markRead,
  markAllRead,
  createAlert,
  deleteAlert,
} = require('../controllers/alertController')
const { protect, restrictTo } = require('../middleware/auth')
const { validateObjectId } = require('../middleware/validate')

router.use(protect)

/**
 * @openapi
 * /alerts/unread-count:
 *   get:
 *     tags:
 *       - Alerts
 *     summary: Get unread alert count
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Unread alert count retrieved
 */
router.get('/unread-count', getUnreadCount)

/**
 * @openapi
 * /alerts/mark-all-read:
 *   put:
 *     tags:
 *       - Alerts
 *     summary: Mark all alerts as read
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: All alerts marked as read
 */
router.put('/mark-all-read', markAllRead)

/**
 * @openapi
 * /alerts:
 *   get:
 *     tags:
 *       - Alerts
 *     summary: Retrieve alerts with pagination
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *     responses:
 *       200:
 *         description: List of alerts
 *   post:
 *     tags:
 *       - Alerts
 *     summary: Create an alert (Admin only)
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - title
 *               - message
 *             properties:
 *               title:
 *                 type: string
 *               message:
 *                 type: string
 *               severity:
 *                 type: string
 *                 enum: [low, medium, high, critical]
 *     responses:
 *       201:
 *         description: Alert created
 */
router.route('/').get(getAlerts).post(restrictTo('admin'), createAlert)

/**
 * @openapi
 * /alerts/{id}/read:
 *   put:
 *     tags:
 *       - Alerts
 *     summary: Mark specific alert as read
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
 *         description: Alert marked as read
 */
router.put('/:id/read', validateObjectId, markRead)

/**
 * @openapi
 * /alerts/{id}:
 *   delete:
 *     tags:
 *       - Alerts
 *     summary: Delete an alert (Admin only)
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
 *         description: Alert deleted
 */
router.delete('/:id', validateObjectId, restrictTo('admin'), deleteAlert)

module.exports = router
