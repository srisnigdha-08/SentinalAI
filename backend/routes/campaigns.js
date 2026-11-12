const express = require('express')
const router = express.Router()
const Campaign = require('../models/Campaign')
const { protect } = require('../middleware/auth')
const { validateObjectId } = require('../middleware/validate')
const { sendSuccess } = require('../utils/apiResponse')
const { parsePagination } = require('../utils/querySecurity')
const { redactCampaign } = require('../utils/redact')

router.use(protect)

/**
 * @openapi
 * /campaigns:
 *   get:
 *     tags:
 *       - Campaigns
 *     summary: List all clustered threat campaigns
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of threat campaigns with populated sessions
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
 *                     $ref: '#/components/schemas/Campaign'
 */
router.get('/', async (req, res, next) => {
  try {
    const { page = 1, limit = 50 } = req.query
    const { limit: safeLimit, skip } = parsePagination({
      page,
      limit,
      defaultLimit: 50,
      maxLimit: 100,
    })
    const campaigns = await Campaign.find()
      .populate('sessions')
      .sort({ lastSeen: -1, _id: -1 })
      .skip(skip)
      .limit(safeLimit)
    const role = req.user?.role || 'viewer'
    const safeData = campaigns.map((c) => redactCampaign(c, role))
    sendSuccess(res, safeData)
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /campaigns/summary:
 *   get:
 *     tags:
 *       - Campaigns
 *     summary: Totals across every stored campaign (the Campaigns page KPI cards)
 *     description: Read-only. Computed from all campaigns, not just the page of rows the list returns.
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Campaign totals
 */
router.get('/summary', async (req, res, next) => {
  try {
    const [agg, ips] = await Promise.all([
      Campaign.aggregate([
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            maxDeceptionScore: { $max: '$maxDeceptionScore' },
            sessionTotal: { $sum: { $size: { $ifNull: ['$sessions', []] } } },
            latestLastSeen: { $max: '$lastSeen' },
          },
        },
      ]),
      Campaign.distinct('sourceIPs'),
    ])
    const s = agg[0] || {}
    const total = s.total || 0
    res.set('Cache-Control', 'no-store')
    sendSuccess(res, {
      total,
      clusteredIPs: ips.filter(Boolean).length,
      maxDeceptionScore: s.maxDeceptionScore || 0,
      sessionTotal: s.sessionTotal || 0,
      avgSessionsPerCampaign: total ? Number((s.sessionTotal / total).toFixed(1)) : 0,
      latestLastSeen: s.latestLastSeen || null,
    })
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /campaigns/{id}:
 *   get:
 *     tags:
 *       - Campaigns
 *     summary: Retrieve single threat campaign details
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
 *         description: Campaign details retrieved
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   $ref: '#/components/schemas/Campaign'
 *       404:
 *         description: Campaign not found
 */
router.get('/:id', validateObjectId, async (req, res, next) => {
  try {
    const campaign = await Campaign.findById(req.params.id).populate('sessions')
    if (!campaign) {
      return res.status(404).json({ success: false, error: 'Campaign not found' })
    }
    const role = req.user?.role || 'viewer'
    sendSuccess(res, redactCampaign(campaign, role))
  } catch (err) {
    next(err)
  }
})

module.exports = router
