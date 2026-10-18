const alertService = require('../services/alertService')
const { sendSuccess, sendError, sendPaginated } = require('../utils/apiResponse')
const { redactAlert } = require('../utils/redact')

const getAlerts = async (req, res, next) => {
  try {
    const role = req.user?.role || 'viewer'
    const r = await alertService.findAlerts({ ...req.query, role })
    const safeData = r.data.map((a) => redactAlert(a, role))
    sendPaginated(res, safeData, r.total, r.page, r.limit)
  } catch (err) {
    next(err)
  }
}

const getUnreadCount = async (req, res, next) => {
  try {
    sendSuccess(res, { count: await alertService.getUnreadCount(req.user.role) })
  } catch (err) {
    next(err)
  }
}
const markRead = async (req, res, next) => {
  try {
    const a = await alertService.markAsRead(req.params.id, req.user._id)
    if (!a) return sendError(res, 'Not found', 404)
    sendSuccess(res, { alert: a }, 'Marked read')
  } catch (err) {
    next(err)
  }
}
const markAllRead = async (req, res, next) => {
  try {
    sendSuccess(res, { count: await alertService.markAllAsRead(req.user.role) }, 'All read')
  } catch (err) {
    next(err)
  }
}
const createAlert = async (req, res, next) => {
  try {
    sendSuccess(res, { alert: await alertService.createAlert(req.body) }, 'Created', 201)
  } catch (err) {
    next(err)
  }
}
const deleteAlert = async (req, res, next) => {
  try {
    const a = await alertService.deleteAlert(req.params.id)
    if (!a) return sendError(res, 'Not found', 404)
    sendSuccess(res, {}, 'Deleted')
  } catch (err) {
    next(err)
  }
}
module.exports = { getAlerts, getUnreadCount, markRead, markAllRead, createAlert, deleteAlert }
