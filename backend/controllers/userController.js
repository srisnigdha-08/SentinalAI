const User = require('../models/User')
const { sendSuccess, sendError, sendPaginated } = require('../utils/apiResponse')
const logger = require('../utils/logger')
const { escapeRegex, parsePagination } = require('../utils/querySecurity')

const ALLOWED_USER_ROLES = ['admin', 'analyst', 'viewer']
const ALLOWED_USER_STATUSES = ['active', 'inactive', 'suspended']

const provisionUser = async (req, res) => {
  if (req.user?.role !== 'admin' || req.user.status !== 'active') return sendError(res, 'Access denied', 403)
  const allowed = ['name', 'email', 'password', 'role', 'department']
  if (Object.keys(req.body || {}).some((key) => !allowed.includes(key)))
    return sendError(res, 'Unsupported account fields', 422)
  const { name, email, password, role = 'viewer', department = 'SOC' } = req.body
  if (typeof role !== 'string' || !ALLOWED_USER_ROLES.includes(role)) return sendError(res, 'Invalid role', 422)
  if (typeof department !== 'string' || !department.trim() || department.trim().length > 100)
    return sendError(res, 'Valid department required', 422)
  try {
    const normalizedEmail = email.trim().toLowerCase()
    if (await User.findOne({ email: normalizedEmail })) return sendError(res, 'Email exists', 409)
    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password,
      role,
      department: department.trim(),
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })
    logger.info('Administrator provisioned an account')
    res.set('Cache-Control', 'no-store')
    sendSuccess(res, { user: user.toJSON() }, 'Account provisioned. The operator must sign in.', 201)
  } catch (error) {
    if (error.code === 11000) return sendError(res, 'Email exists', 409)
    logger.error('Account provisioning failed (' + error.name + ')')
    sendError(res, 'Account service unavailable', 503)
  }
}

const getUsers = async (req, res, next) => {
  try {
    const { page = 1, limit = 20, role, status, search } = req.query
    const {
      page: safePage,
      limit: safeLimit,
      skip,
    } = parsePagination({
      page,
      limit,
      defaultLimit: 20,
      maxLimit: 100,
    })

    const f = {}
    if (typeof role === 'string' && ALLOWED_USER_ROLES.includes(role.toLowerCase())) {
      f.role = role.toLowerCase()
    }
    if (typeof status === 'string' && ALLOWED_USER_STATUSES.includes(status.toLowerCase())) {
      f.status = status.toLowerCase()
    }

    const safeSearch = escapeRegex(search)
    if (safeSearch) {
      f.$or = [{ name: { $regex: safeSearch, $options: 'i' } }, { email: { $regex: safeSearch, $options: 'i' } }]
    }

    const total = await User.countDocuments(f)
    const users = await User.find(f).sort({ createdAt: -1 }).skip(skip).limit(safeLimit).select('-password').lean()
    sendPaginated(res, users, total, safePage, safeLimit)
  } catch (err) {
    next(err)
  }
}
const getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id).select('-password')
    if (!user) return sendError(res, 'Not found', 404)
    sendSuccess(res, { user })
  } catch (err) {
    next(err)
  }
}
const updateUser = async (req, res, next) => {
  try {
    const allowed = ['name', 'role', 'status', 'department']
    const updates = {}
    allowed.forEach((f) => {
      if (req.body[f] !== undefined) updates[f] = req.body[f]
    })
    if (
      updates.role !== undefined &&
      (typeof updates.role !== 'string' || !ALLOWED_USER_ROLES.includes(updates.role.toLowerCase()))
    ) {
      return sendError(res, 'Invalid role', 400)
    }
    if (
      updates.status !== undefined &&
      (typeof updates.status !== 'string' || !ALLOWED_USER_STATUSES.includes(updates.status.toLowerCase()))
    ) {
      return sendError(res, 'Invalid status', 400)
    }
    if (updates.role) updates.role = updates.role.toLowerCase()
    if (updates.status) updates.status = updates.status.toLowerCase()
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: updates, ...(updates.role || updates.status ? { $inc: { authVersion: 1 } } : {}) },
      { new: true, runValidators: true }
    ).select('-password')
    if (!user) return sendError(res, 'Not found', 404)
    if (updates.role || updates.status)
      await require('../services/authSessionService').revokeUserSessions(user._id, 'account-security-change')
    sendSuccess(res, { user }, 'Updated')
  } catch (err) {
    next(err)
  }
}
const deleteUser = async (req, res, next) => {
  try {
    if (req.params.id === req.user._id.toString()) return sendError(res, 'Cannot delete yourself', 400)
    const user = await User.findByIdAndDelete(req.params.id)
    if (!user) return sendError(res, 'Not found', 404)
    await require('../services/authSessionService').revokeUserSessions(user._id, 'account-deleted')
    logger.warn('User deleted: ' + user.email)
    sendSuccess(res, {}, 'Deleted')
  } catch (err) {
    next(err)
  }
}
const getUserStats = async (req, res, next) => {
  try {
    const [total, byRole, byStatus] = await Promise.all([
      User.countDocuments(),
      User.aggregate([{ $group: { _id: '$role', count: { $sum: 1 } } }]),
      User.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]),
    ])
    sendSuccess(res, { total, byRole, byStatus })
  } catch (err) {
    next(err)
  }
}
module.exports = { provisionUser, getUsers, getUser, updateUser, deleteUser, getUserStats }
