const express = require('express')
const router = express.Router()
const aiSvc = require('../services/aiEngineService')
const aiDbSvc = require('../services/aiService')
const { sendSuccess, sendError, sendPaginated } = require('../utils/apiResponse')
const { protect, restrictTo } = require('../middleware/auth')
const { validateObjectId } = require('../middleware/validate')
const { CANONICAL_CLASSES, isValidCanonicalClass } = require('../utils/canonicalClasses')
const { redactAIPrediction } = require('../utils/redact')

const { isHoneypotKey, isSentinelKey } = require('../utils/apiKeys')

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
 * /ai/engine/drift:
 *   get:
 *     tags:
 *       - AI Engine
 *     summary: Feature and class-mix drift of recent traffic versus the model's training data
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Drift report (status ok, drift or insufficient_data)
 *       503:
 *         description: AI engine unreachable
 */
/**
 * @swagger
 * /ai/engine/explain-global:
 *   get:
 *     tags:
 *       - AI Engine
 *     summary: Features that drive the model's recent verdicts (mean absolute SHAP, overall and per class)
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Global explanation over the engine's recent scored flows
 *       503:
 *         description: AI engine unreachable or no explainer
 */
router.get('/engine/explain-global', protect, restrictTo('admin', 'analyst'), async (req, res, next) => {
  try {
    const summary = await aiSvc.getGlobalExplanation()
    if (!summary) return sendError(res, 'Global explanation unavailable', 503)
    sendSuccess(res, summary)
  } catch (err) {
    next(err)
  }
})

router.get('/engine/drift', protect, restrictTo('admin', 'analyst'), async (req, res, next) => {
  try {
    const drift = await aiSvc.getDrift()
    if (!drift) return sendError(res, 'AI engine unreachable', 503)
    sendSuccess(res, drift)
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /ai/engine/reload:
 *   post:
 *     tags:
 *       - AI Engine
 *     summary: Load the models pinned in the AI engine's registry without a restart (admin)
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: New model serving
 *       409:
 *         description: New models failed to load or verify; previous model still serving
 */
router.post('/engine/reload', protect, restrictTo('admin'), async (req, res, next) => {
  const { logAudit } = require('../utils/auditLogger')
  try {
    const result = await aiSvc.reloadModel()
    await logAudit({
      action: 'MODEL_RELOADED',
      actor: req.user,
      target: { identifier: result?.current?.registry?.classifier || 'unknown', type: 'Model' },
      status: 'SUCCESS',
      details: { previous: result?.previous?.registry || null, current: result?.current?.registry || null },
      ip: req.ip,
    })
    sendSuccess(res, result, 'Model reloaded')
  } catch (err) {
    await logAudit({
      action: 'MODEL_RELOADED',
      actor: req.user,
      target: { identifier: 'registry', type: 'Model' },
      status: 'FAILED',
      details: { error: err.message },
      ip: req.ip,
    }).catch(() => {})
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
 *     summary: Store an AI prediction (AI engine callback only; SENTINEL_KEY)
 *     security:
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

// Fields the AI engine callback (inference/main.py _notify) may set. Verification, threat links
// and anything else on AIPrediction are server-owned and never accepted from the request.
const PREDICTION_CALLBACK_FIELDS = [
  'sourceIP',
  'targetIP',
  'predictedClass',
  'classProbabilities',
  'threatScore',
  'modelVersion',
  'modelType',
  'isAnomaly',
  'anomalyScore',
  'inferenceTimeMs',
  'featureVector',
  'featureSchemaVersion',
  'status',
  'action',
  'eventTime',
  'timestamp',
]

// Only the AI engine (SENTINEL_KEY) may record model output. The honeypot key and user sessions
// cannot fabricate predictions, because stored predictions can raise alerts and auto-block IPs.
const aiEngineOnly = (req, res, next) => {
  const key = req.headers['x-api-key']
  if (!key) return sendError(res, 'Missing API key', 401)
  if (isSentinelKey(key)) return next()
  if (isHoneypotKey(key)) return sendError(res, 'This key is not authorised to record AI predictions', 403)
  return sendError(res, 'Invalid API key', 401)
}

router.post('/predictions', aiEngineOnly, async (req, res, next) => {
  try {
    const body = req.body || {}
    const data = { inputSource: 'network_traffic' }
    for (const field of PREDICTION_CALLBACK_FIELDS) {
      if (body[field] !== undefined) data[field] = body[field]
    }
    sendSuccess(res, { prediction: await aiDbSvc.storePrediction(data) }, 'Stored', 201)
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
