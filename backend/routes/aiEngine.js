const express = require('express')
const router = express.Router()
const aiSvc = require('../services/aiEngineService')
const aiDbSvc = require('../services/aiService')
const { sendSuccess, sendError, sendPaginated } = require('../utils/apiResponse')
const { protect, restrictTo } = require('../middleware/auth')
const { validateObjectId } = require('../middleware/validate')
const { CANONICAL_CLASSES, isValidCanonicalClass } = require('../utils/canonicalClasses')
const { redactAIPrediction } = require('../utils/redact')


// Scoped internal API-key or JWT user authentication middleware
const internalOrUserAuth = (req, res, next) => {
  const apiKey = req.headers['x-api-key']
  const isInternal = Boolean(
    apiKey &&
    ((process.env.SENTINEL_KEY && apiKey === process.env.SENTINEL_KEY) ||
      (process.env.HONEYPOT_API_KEY && apiKey === process.env.HONEYPOT_API_KEY))
  )

  if (isInternal) {
    // Valid internal service call. Do NOT assign administrative privileges.
    return next()
  }

  // Otherwise, fallback to standard JWT protection and authorization checks
  protect(req, res, (err) => {
    if (err) return next(err)
    restrictTo('admin', 'analyst')(req, res, next)
  })
}

/**
 * @openapi
 * /ai/engine/health:
 *   get:
 *     tags:
 *       - AI Engine
 *     summary: Check Python AI engine health status
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: AI engine service status
 */
router.get('/engine/health', protect, async (req, res, next) => {
  try {
    sendSuccess(res, await aiSvc.getHealth())
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /ai/engine/model-info:
 *   get:
 *     tags:
 *       - AI Engine
 *     summary: Retrieve machine learning model metadata and training versions
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Model information retrieved
 *       503:
 *         description: AI engine unreachable
 */
router.get('/engine/model-info', protect, async (req, res, next) => {
  try {
    const i = await aiSvc.getModelInfo()
    if (!i) return sendError(res, 'AI engine unreachable', 503)
    sendSuccess(res, i)
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /ai/engine/stats:
 *   get:
 *     tags:
 *       - AI Engine
 *     summary: Get AI inference engine run-time statistics
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: AI engine runtime stats
 */
router.get('/engine/stats', protect, async (req, res, next) => {
  try {
    sendSuccess(res, (await aiSvc.getModelStats()) || {})
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /ai/analyze:
 *   post:
 *     tags:
 *       - AI Engine
 *     summary: Run full AI classification and threat analysis pipeline on session payload
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
 *         description: AI analysis result
 *       503:
 *         description: AI processing failed
 *       422:
 *         description: Invalid feature input; raw input is not echoed
 */
router.post('/analyze', protect, restrictTo('admin', 'analyst'), async (req, res, next) => {
  try {
    const r = await aiSvc.runFullPipeline(req.body, req.app.get('io'))
    if (!r) return sendError(res, 'AI failed', 503)
    sendSuccess(res, { result: r })
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /ai/predictions:
 *   get:
 *     tags:
 *       - AI Engine
 *     summary: Query persisted AI prediction logs with pagination
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
 *         description: Paginated AI prediction logs
 *   post:
 *     tags:
 *       - AI Engine
 *     summary: Ingest and store AI prediction record (Internal service or JWT)
 *     security:
 *       - BearerAuth: []
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - sourceIP
 *               - predictedClass
 *             properties:
 *               sourceIP:
 *                 type: string
 *               predictedClass:
 *                 type: string
 *               threatScore:
 *                 type: number
 *     responses:
 *       201:
 *         description: Prediction stored
 */
router.get('/predictions', protect, async (req, res, next) => {
  try {
    const r = await aiDbSvc.findPredictions(req.query)
    const role = req.user?.role || 'viewer'
    const safeData = r.data.map((p) => redactAIPrediction(p, role))
    sendPaginated(res, safeData, r.total, r.page, r.limit)
  } catch (err) {
    next(err)
  }
})


router.post('/predictions', internalOrUserAuth, async (req, res, next) => {
  try {
    sendSuccess(res, { prediction: await aiDbSvc.storePrediction(req.body) }, 'Stored', 201)
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /ai/stats:
 *   get:
 *     tags:
 *       - AI Engine
 *     summary: Retrieve aggregate database metrics on AI predictions
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: AI prediction statistics
 */
router.get('/stats', protect, async (req, res, next) => {
  try {
    sendSuccess(res, await aiDbSvc.getModelStats())
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /ai/predictions/{id}/verify:
 *   put:
 *     tags:
 *       - AI Engine
 *     summary: Verify or correct an AI prediction classification (Analyst/Admin)
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - actualClass
 *             properties:
 *               actualClass:
 *                 type: string
 *                 example: BRUTE_FORCE
 *     responses:
 *       200:
 *         description: Prediction verified
 *       404:
 *         description: Prediction not found
 */
router.put(
  '/predictions/:id/verify',
  protect,
  validateObjectId,
  restrictTo('admin', 'analyst'),
  async (req, res, next) => {
    try {
      const { actualClass } = req.body || {}
      if (!actualClass || typeof actualClass !== 'string' || !isValidCanonicalClass(actualClass.trim())) {
        return sendError(
          res,
          `Valid canonical actualClass required. Allowed classes: ${CANONICAL_CLASSES.join(', ')}`,
          400
        )
      }
      const p = await aiDbSvc.verifyPrediction(req.params.id, req.user._id, actualClass.trim())
      if (!p) return sendError(res, 'Prediction not found', 404)
      sendSuccess(res, { prediction: p }, 'Prediction verified')
    } catch (err) {
      next(err)
    }
  }
)

module.exports = router
