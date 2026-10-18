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
    const { runWithTransactionOrFallback } = require('../utils/transactionHelper')
    const { logAudit } = require('../utils/auditLogger')

    const userData = {
      name: name.trim(),
      email: normalizedEmail,
      password,
      role,
      department: department.trim(),
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    }

    const user = await runWithTransactionOrFallback({
      transactionFn: async (session) => {
        const [newUser] = await User.create([userData], { session })
        if (!newUser || !newUser._id) {
          throw new Error('User provisioning failed: missing persistent user id')
        }
        await logAudit({
          action: 'USER_CREATED',
          actor: req.user,
          target: { id: newUser._id.toString(), email: newUser.email, type: 'User' },
          status: 'SUCCESS',
          details: { role, department },
          ip: req.ip,
          session,
        })
        return newUser
      },
      fallbackFn: async () => {
        const newUser = await User.create(userData)
        if (!newUser || !newUser._id) {
          throw new Error('User provisioning failed: missing persistent user id')
        }
        try {
          await logAudit({
            action: 'USER_CREATED',
            actor: req.user,
            target: { id: newUser._id.toString(), email: newUser.email, type: 'User' },
            status: 'SUCCESS',
            details: { role, department },
            ip: req.ip,
          })
        } catch (auditErr) {
          await User.findByIdAndDelete(newUser._id)
          logger.error(`[AUDIT_FAILURE] Provisioned user ${newUser._id} deleted due to audit failure: ${auditErr.message}`)
          const err = new Error('Security audit logging failed; account provision rolled back')
          err.statusCode = 500
          throw err
        }
        return newUser
      },
    })
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

    const targetUser = await User.findById(req.params.id)
    if (!targetUser) return sendError(res, 'Not found', 404)

    const isSelf = req.user?._id?.toString() === req.params.id

    // Guardrail: prevent self-demotion
    if (isSelf && updates.role && updates.role !== 'admin') {
      return sendError(res, 'Administrators cannot demote their own account', 400)
    }

    // Guardrail: prevent self-deactivation
    if (isSelf && updates.status && updates.status !== 'active') {
      return sendError(res, 'Administrators cannot deactivate their own account', 400)
    }

    // Guardrail: prevent demotion or deactivation of the last active administrator
    const changingAdmin =
      (updates.role && updates.role !== 'admin') || (updates.status && updates.status !== 'active')
    if (targetUser.role === 'admin' && targetUser.status === 'active' && changingAdmin) {
      const activeAdminCount = await User.countDocuments({ role: 'admin', status: 'active' })
      if (activeAdminCount <= 1) {
        return sendError(res, 'Cannot demote or deactivate the last remaining administrator', 400)
      }
    }

    const isSecurityChange = updates.role || updates.status
    const prevRole = targetUser.role
    const prevStatus = targetUser.status
    const prevAuthVersion = targetUser.authVersion || 0

    const { runWithTransactionOrFallback } = require('../utils/transactionHelper')
    const { logAudit } = require('../utils/auditLogger')

    const user = await runWithTransactionOrFallback({
      transactionFn: async (session) => {
        const updated = await User.findByIdAndUpdate(
          req.params.id,
          {
            $set: updates,
            ...(isSecurityChange ? { $inc: { authVersion: 1, tokenVersion: 1 } } : {}),
          },
          { new: true, runValidators: true, session }
        ).select('-password')

        await logAudit({
          action: isSecurityChange ? (updates.role ? 'USER_ROLE_CHANGED' : 'USER_STATUS_CHANGED') : 'USER_UPDATED',
          actor: req.user,
          target: { id: updated._id.toString(), email: updated.email, type: 'User' },
          status: 'SUCCESS',
          details: updates,
          ip: req.ip,
          session,
        })
        return updated
      },
      fallbackFn: async () => {
        const updated = await User.findByIdAndUpdate(
          req.params.id,
          {
            $set: updates,
            ...(isSecurityChange ? { $inc: { authVersion: 1, tokenVersion: 1 } } : {}),
          },
          { new: true, runValidators: true }
        ).select('-password')

        try {
          await logAudit({
            action: isSecurityChange ? (updates.role ? 'USER_ROLE_CHANGED' : 'USER_STATUS_CHANGED') : 'USER_UPDATED',
            actor: req.user,
            target: { id: updated._id.toString(), email: updated.email, type: 'User' },
            status: 'SUCCESS',
            details: updates,
            ip: req.ip,
          })
        } catch (auditErr) {
          await User.findByIdAndUpdate(req.params.id, {
            $set: { role: prevRole, status: prevStatus, authVersion: prevAuthVersion },
          })
          logger.error(`[AUDIT_FAILURE] Reverted user ${req.params.id} mutation due to audit failure: ${auditErr.message}`)
          const err = new Error('Security audit logging failed; change not applied')
          err.statusCode = 500
          throw err
        }
        return updated
      },
    })

    if (isSecurityChange) {
      const authSessions = require('../services/authSessionService')
      await authSessions.revokeUserSessions(user._id, 'account-security-change')
      authSessions.disconnectUser(user._id)
      const socketManager = require('../websocket/socketManager')
      socketManager.disconnectUser(user._id)
    }

    sendSuccess(res, { user }, 'Updated')
  } catch (err) {
    if (err.message && err.message.includes('Security audit logging failed')) {
      return sendError(res, err.message, err.statusCode || 500)
    }
    next(err)
  }
}

const deleteUser = async (req, res, next) => {
  try {
    if (req.params.id === req.user?._id?.toString()) return sendError(res, 'Cannot delete yourself', 400)
    const targetUser = await User.findById(req.params.id)
    if (!targetUser) return sendError(res, 'Not found', 404)

    if (targetUser.role === 'admin' && targetUser.status === 'active') {
      const activeAdminCount = await User.countDocuments({ role: 'admin', status: 'active' })
      if (activeAdminCount <= 1) {
        return sendError(res, 'Cannot delete the last remaining administrator', 400)
      }
    }

    const targetId = (targetUser && targetUser._id) ? targetUser._id.toString() : String(req.params.id)
    const { logAudit } = require('../utils/auditLogger')
    try {
      await logAudit({
        action: 'USER_DELETED',
        actor: req.user,
        target: { id: targetId, email: targetUser.email || null, type: 'User' },
        status: 'SUCCESS',
        ip: req.ip,
      })
    } catch (auditErr) {
      logger.error(`[AUDIT_FAILURE] User deletion aborted for ${req.params.id} due to audit failure: ${auditErr.message}`)
      return sendError(res, 'Security audit logging failed; change not applied', 500)
    }

    const user = await User.findByIdAndDelete(req.params.id)
    const authSessions = require('../services/authSessionService')
    await authSessions.revokeUserSessions(user._id, 'account-deleted')
    authSessions.disconnectUser(user._id)
    const socketManager = require('../websocket/socketManager')
    socketManager.disconnectUser(user._id)

    logger.warn('User deleted: ' + (user?.email || targetId))
    sendSuccess(res, {}, 'Deleted')
  } catch (err) {
    next(err)
  }
}

const forceLogoutUser = async (req, res, next) => {
  try {
    const targetUser = await User.findById(req.params.id)
    if (!targetUser) return sendError(res, 'Not found', 404)

    const targetId = (targetUser && targetUser._id) ? targetUser._id.toString() : String(req.params.id)
    const { runWithTransactionOrFallback } = require('../utils/transactionHelper')
    const { logAudit } = require('../utils/auditLogger')

    const user = await runWithTransactionOrFallback({
      transactionFn: async (session) => {
        await logAudit({
          action: 'USER_FORCE_LOGOUT',
          actor: req.user,
          target: { id: targetId, email: targetUser.email || null, type: 'User' },
          status: 'SUCCESS',
          ip: req.ip,
          session,
        })
        const updated = await User.findByIdAndUpdate(
          req.params.id,
          { $inc: { authVersion: 1, tokenVersion: 1 } },
          { new: true, session }
        )
        return updated
      },
      fallbackFn: async () => {
        try {
          await logAudit({
            action: 'USER_FORCE_LOGOUT',
            actor: req.user,
            target: { id: targetId, email: targetUser.email || null, type: 'User' },
            status: 'SUCCESS',
            ip: req.ip,
          })
        } catch (auditErr) {
          logger.error(`[AUDIT_FAILURE] User force logout aborted for ${req.params.id} due to audit failure: ${auditErr.message}`)
          const err = new Error('Security audit logging failed; change not applied')
          err.statusCode = 500
          throw err
        }

        const updated = await User.findByIdAndUpdate(
          req.params.id,
          { $inc: { authVersion: 1, tokenVersion: 1 } },
          { new: true }
        )
        return updated
      },
    })

    const authSessions = require('../services/authSessionService')
    await authSessions.revokeUserSessions(user._id, 'admin-force-logout')
    authSessions.disconnectUser(user._id)
    const socketManager = require('../websocket/socketManager')
    socketManager.disconnectUser(user._id)

    sendSuccess(res, {}, 'User logged out and sessions revoked')
  } catch (err) {
    if (err.message && err.message.includes('Security audit logging failed')) {
      return sendError(res, err.message, err.statusCode || 500)
    }
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

module.exports = {
  provisionUser,
  getUsers,
  getUser,
  updateUser,
  deleteUser,
  forceLogoutUser,
  getUserStats,
}

