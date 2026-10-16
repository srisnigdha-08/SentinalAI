const logger = require('../utils/logger')
const { sendError } = require('../utils/apiResponse')
const errorHandler = (err, req, res, _next) => {
  let statusCode = err.statusCode || 500
  let message = err.message || 'Server Error'
  if (err.name === 'CastError') {
    message = 'Invalid ' + err.path + ': ' + err.value
    statusCode = 400
  }
  if (err.code === 11000) {
    message = Object.keys(err.keyValue)[0] + ' already exists'
    statusCode = 409
  }
  if (err.name === 'ValidationError') {
    message = Object.values(err.errors)
      .map((e) => e.message)
      .join('. ')
    statusCode = 422
  }
  if (err.name === 'JsonWebTokenError') {
    message = 'Invalid token'
    statusCode = 401
  }
  if (err.name === 'TokenExpiredError') {
    message = 'Token expired'
    statusCode = 401
  }
  if (statusCode >= 500) logger.error('[' + req.method + '] ' + req.path + ' -> ' + statusCode + ': ' + message)
  if (statusCode >= 500) message = 'Internal server error'
  sendError(res, message, statusCode)
}
const notFound = (req, res) => sendError(res, 'Route not found: ' + req.method + ' ' + req.originalUrl, 404)
module.exports = { errorHandler, notFound }
