const express = require('express')
const router = express.Router()
const {
  getThreats,
  getAnalytics,
  getVectorTrend,
  getRecent,
  getThreat,
  createThreat,
  updateThreat,
  triageThreat,
  blockIP,
  deleteThreat,
  getSettings,
  updateSettings,
  getBlockedIPs,
  blockIPManual,
  unblockIPManual,
} = require('../controllers/threatController')

const { protect, restrictTo, requirePermission } = require('../middleware/auth')
const { validateObjectId } = require('../middleware/validate')

router.use(protect)


/**
 * @openapi
 * /threats/analytics/summary:
 *   get:
 *     tags:
 *       - Threats
 *     summary: Retrieve aggregate threat metrics and summary statistics
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Threat analytics summary retrieved
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 */
router.get('/analytics/summary', getAnalytics)

/**
 * @openapi
 * /threats/vector-trend:
 *   get:
 *     tags:
 *       - Threats
 *     summary: Retrieve attack vector trends over time
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Attack vector trend data retrieved
 */
router.get('/vector-trend', getVectorTrend)

/**
 * @openapi
 * /threats/recent:
 *   get:
 *     tags:
 *       - Threats
 *     summary: Retrieve recent threat detections
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of most recent threats
 */
router.get('/recent', getRecent)

/**
 * @openapi
 * /threats/settings:
 *   get:
 *     tags:
 *       - Settings & Blocklist
 *     summary: Get system configuration and auto-block settings
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: System settings retrieved
 *   post:
 *     tags:
 *       - Settings & Blocklist
 *     summary: Update system settings (Admin only)
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Settings updated successfully
 */
router.get('/settings', requirePermission('settings:read'), getSettings)
router.post('/settings', requirePermission('settings:write'), updateSettings)


/**
 * @openapi
 * /threats/blocked-ips:
 *   get:
 *     tags:
 *       - Settings & Blocklist
 *     summary: Get all blocked IP addresses
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Blocked IP list retrieved
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/BlockedIP'
 */
router.get('/blocked-ips', getBlockedIPs)

/**
 * @openapi
 * /threats/block-ip:
 *   post:
 *     tags:
 *       - Settings & Blocklist
 *     summary: Manually block an IP address
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - ip
 *             properties:
 *               ip:
 *                 type: string
 *                 example: 185.220.101.47
 *               reason:
 *                 type: string
 *                 example: Manual block by administrator
 *     responses:
 *       200:
 *         description: IP address blocked
 */
router.post('/block-ip', restrictTo('admin', 'analyst'), blockIPManual)

/**
 * @openapi
 * /threats/unblock-ip:
 *   post:
 *     tags:
 *       - Settings & Blocklist
 *     summary: Unblock a previously blocked IP address
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - ip
 *             properties:
 *               ip:
 *                 type: string
 *                 example: 185.220.101.47
 *     responses:
 *       200:
 *         description: IP address unblocked
 */
router.post('/unblock-ip', restrictTo('admin', 'analyst'), unblockIPManual)

/**
 * @openapi
 * /threats:
 *   get:
 *     tags:
 *       - Threats
 *     summary: Query and list threat logs with pagination and filters
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
 *       - in: query
 *         name: severity
 *         schema:
 *           type: string
 *           enum: [low, medium, high, critical]
 *     responses:
 *       200:
 *         description: Paginated threat logs retrieved
 *   post:
 *     tags:
 *       - Threats
 *     summary: Create a manual threat record
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - sourceIP
 *               - attackType
 *             properties:
 *               sourceIP:
 *                 type: string
 *               attackType:
 *                 type: string
 *               severity:
 *                 type: string
 *                 enum: [low, medium, high, critical]
 *     responses:
 *       201:
 *         description: Threat created successfully
 */
router.route('/').get(getThreats).post(restrictTo('admin', 'analyst'), createThreat)

/**
 * @openapi
 * /threats/{id}:
 *   get:
 *     tags:
 *       - Threats
 *     summary: Get single threat details by ID
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
 *         description: Threat details retrieved
 *       404:
 *         description: Threat not found
 *   put:
 *     tags:
 *       - Threats
 *     summary: Update threat details
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
 *         description: Threat updated
 *   delete:
 *     tags:
 *       - Threats
 *     summary: Delete threat record (Admin only)
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
 *         description: Threat deleted
 */
router
  .route('/:id')
  .get(validateObjectId, getThreat)
  .put(validateObjectId, restrictTo('admin', 'analyst'), updateThreat)
  .delete(validateObjectId, restrictTo('admin'), deleteThreat)

/**
 * @openapi
 * /threats/{id}/block:
 *   post:
 *     tags:
 *       - Threats
 *     summary: Block the IP associated with a specific threat ID
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
 *         description: Threat IP blocked successfully
 */
router.post('/:id/block', validateObjectId, restrictTo('admin', 'analyst'), blockIP)
router.patch('/:id/triage', validateObjectId, requirePermission('threats:triage'), triageThreat)

module.exports = router

