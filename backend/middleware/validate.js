const { sendError } = require('../utils/apiResponse')
const { isValidObjectId } = require('../utils/querySecurity')

const validateRegister = (req, res, next) => {
  const { name, email, password } = req.body || {}
  const e = []
  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    e.push('Name min 2 chars')
  } else if (name.trim().length > 50) {
    e.push('Name max 50 chars')
  }

  if (!email || typeof email !== 'string' || email.length > 100 || !/\S+@\S+\.\S+/.test(email)) {
    e.push('Valid email required')
  }

  if (!password || typeof password !== 'string' || password.length < 8) {
    e.push('Password min 8 chars')
  } else if (password.length > 128) {
    e.push('Password max 128 chars')
  }

  if (e.length) return sendError(res, 'Validation failed', 422, e)
  next()
}

const validateLogin = (req, res, next) => {
  const { email, password } = req.body || {}
  if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
    return sendError(res, 'Email and password required', 422)
  }
  if (email.length > 100 || password.length > 128) {
    return sendError(res, 'Invalid credentials length', 422)
  }
  next()
}

const validateObjectId = (req, res, next) => {
  if (!isValidObjectId(req.params.id)) return sendError(res, 'Invalid ID', 400)
  next()
}

module.exports = { validateRegister, validateLogin, validateObjectId }
