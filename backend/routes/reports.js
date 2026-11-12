const express = require('express')
const router = express.Router()
const { protect, restrictTo } = require('../middleware/auth')
const { sendError, sendSuccess } = require('../utils/apiResponse')
const logger = require('../utils/logger')
const reportService = require('../services/reportService')

router.use(protect)

const FORMATS = {
  pdf: { type: 'application/pdf', render: reportService.renderPdf },
  csv: { type: 'text/csv; charset=utf-8', render: reportService.renderCsv },
}

/**
 * @openapi
 * /reports/security-summary:
 *   get:
 *     tags:
 *       - Reports
 *     summary: Download the security summary report (Dashboard "Export Report")
 *     description: >
 *       Figures are read from the database at request time for a whole number of Asia/Kolkata calendar days.
 *       Admin and analyst only. Read-only: nothing is created or changed except an audit-log entry.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: days
 *         schema: { type: integer, enum: [1, 7, 30, 90], default: 7 }
 *       - in: query
 *         name: format
 *         schema: { type: string, enum: [pdf, csv, json], default: pdf }
 *     responses:
 *       200:
 *         description: The report file (PDF or CSV attachment) or its JSON data
 *       400:
 *         description: Unsupported period or format
 *       403:
 *         description: Viewer role
 */
router.get('/security-summary', restrictTo('admin', 'analyst'), async (req, res, next) => {
  try {
    const days = req.query.days === undefined ? 7 : Number(req.query.days)
    if (!reportService.ALLOWED_DAYS.includes(days))
      return sendError(res, `days must be one of ${reportService.ALLOWED_DAYS.join(', ')}`, 400)
    const format = String(req.query.format || 'pdf').toLowerCase()
    if (format !== 'json' && !FORMATS[format]) return sendError(res, 'format must be pdf, csv or json', 400)

    const report = await reportService.buildSecurityReport({ days, generatedBy: req.user })
    try {
      const { logAudit } = require('../utils/auditLogger')
      await logAudit({
        action: 'REPORT_EXPORTED',
        actor: req.user,
        target: { identifier: 'security-summary', type: 'Report' },
        status: 'SUCCESS',
        details: { days, format },
        ip: req.ip,
      })
    } catch (auditErr) {
      // An export changes nothing, so a failed audit write is logged rather than blocking the download
      logger.warn(`[REPORT] audit write failed for security-summary export: ${auditErr.message}`)
    }

    res.set('Cache-Control', 'no-store')
    if (format === 'json') return sendSuccess(res, report, 'Security summary report')
    const body = FORMATS[format].render(report)
    res.set('Content-Type', FORMATS[format].type)
    res.set('Content-Disposition', `attachment; filename="${reportService.reportFileName(report, format)}"`)
    res.set('Content-Length', String(body.length))
    res.status(200).end(body)
  } catch (err) {
    next(err)
  }
})

module.exports = router
