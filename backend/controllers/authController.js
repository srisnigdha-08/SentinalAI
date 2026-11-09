const User = require('../models/User')
const bcrypt = require('bcryptjs')
const { sendSuccess, sendError } = require('../utils/apiResponse')
const sessions = require('../services/authSessionService')
const cookies = require('../middleware/authCookies')
async function response(user, code, req, res, message) {
  const previous = cookies.refreshCookie(req)
  if (previous) {
    try {
      await sessions.logout(previous)
    } catch (error) {
      if (error.statusCode !== 401) throw error
    }
  }
  const result = await sessions.issue(user)
  cookies.setRefresh(res, result.refreshToken)
  res.set('Cache-Control', 'no-store')
  sendSuccess(res, { token: result.token, user: result.user }, message, code)
}
const register = (_req, res) =>
  sendError(res, 'Public registration is disabled. Contact an administrator for access.', 403)
// Unknown emails still pay for one bcrypt comparison (same cost 12 as stored hashes), so response time
// does not reveal which accounts exist.
let timingEqualizerHash = null
const equalizeTiming = async (password) => {
  timingEqualizerHash = timingEqualizerHash || (await bcrypt.hash('sentinel-timing-equalizer', 12))
  await bcrypt.compare(typeof password === 'string' ? password : '', timingEqualizerHash)
  return false
}
const login = async (req, res, next) => {
  try {
    const { email, password } = req.body
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password')
    const valid = user ? await user.comparePassword(password) : await equalizeTiming(password)
    if (!valid) {
      const { logAudit } = require('../utils/auditLogger')
      await logAudit({
        action: 'LOGIN_FAILED',
        actor: null,
        target: { identifier: email ? String(email).toLowerCase() : 'unknown', type: 'User' },
        status: 'DENIED',
        details: { reason: 'INVALID_CREDENTIALS' },
        ip: req.ip,
      })
      return sendError(res, 'Invalid credentials', 401)
    }
    if (user.status !== 'active') {
      const { logAudit } = require('../utils/auditLogger')
      await logAudit({
        action: 'LOGIN_FAILED',
        actor: null,
        target: { id: user._id.toString(), email: user.email, type: 'User' },
        status: 'DENIED',
        details: { reason: 'ACCOUNT_INACTIVE' },
        ip: req.ip,
      })
      return sendError(res, 'Account inactive', 403)
    }
    user.lastLogin = new Date()
    user.loginCount = (user.loginCount || 0) + 1
    await user.save({ validateBeforeSave: false })

    const userIdStr = user._id.toString()
    const { logAudit } = require('../utils/auditLogger')
    await logAudit({
      action: 'LOGIN_SUCCESS',
      actor: { id: userIdStr, email: user.email, role: user.role },
      target: { id: userIdStr, identifier: user.email, email: user.email, type: 'User' },
      status: 'SUCCESS',
      ip: req.ip,
    })

    await response(user, 200, req, res, 'Welcome back, ' + user.name)
  } catch (error) {
    next(error)
  }
}
const { getPermissions } = require('../config/permissions')
const getMe = (req, res) => {
  const user = req.user.toJSON ? req.user.toJSON() : { ...req.user }
  if (!user.permissions && user.role) {
    user.permissions = getPermissions(user.role)
  }
  return sendSuccess(res, { user })
}
const updatePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body || {}
    if (
      typeof currentPassword !== 'string' ||
      !currentPassword ||
      typeof newPassword !== 'string' ||
      newPassword.length < 8 ||
      newPassword.length > 128
    )
      return sendError(res, 'Valid current and new password required', 400)
    const user = await User.findById(req.user._id).select('+password')
    if (!user || !(await user.comparePassword(currentPassword))) return sendError(res, 'Wrong password', 401)
    const password = await bcrypt.hash(newPassword, 12)
    const updated = await User.findOneAndUpdate(
      {
        _id: user._id,
        password: user.password,
        $expr: { $eq: [{ $ifNull: ['$authVersion', 0] }, user.authVersion ?? 0] },
      },
      { $set: { password, passwordChangedAt: new Date(), mustChangePassword: false }, $inc: { authVersion: 1 } },
      { new: true, runValidators: true }
    )
    if (!updated) return sendError(res, 'Account changed; sign in again', 401)
    await sessions.revokeUserSessions(user._id, 'password-change')
    await response(updated, 200, req, res, 'Password updated')
  } catch (error) {
    next(error)
  }
}
const refreshToken = async (req, res, next) => {
  try {
    const token = cookies.refreshCookie(req)
    if (!token) return sendError(res, 'Sign in required', 401)
    const result = await sessions.rotate(token)
    cookies.setRefresh(res, result.refreshToken)
    sendSuccess(res, { token: result.token, user: result.user }, 'Refreshed')
  } catch (error) {
    next(error)
  }
}
const logout = async (req, res, next) => {
  try {
    const access = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null
    await sessions.logout(cookies.refreshCookie(req), access)
    cookies.clearCookies(res)
    sendSuccess(res, {}, 'Session revoked')
  } catch (error) {
    next(error)
  }
}
const logoutAll = async (req, res, next) => {
  try {
    await sessions.logoutAll(req.user)
    cookies.clearCookies(res)
    sendSuccess(res, {}, 'All sessions revoked')
  } catch (error) {
    next(error)
  }
}
module.exports = { register, login, getMe, updatePassword, refreshToken, logout, logoutAll }
