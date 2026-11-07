const logger = require('../utils/logger')
const { sendError } = require('../utils/apiResponse')
// F-05: body-parser (express.json / urlencoded) errors carry err.type. Their messages are the parser's own
// ("Unexpected token } in JSON at position 9", "request entity too large"), which echo request fragments and
// reveal the parser, so clients get a fixed message per type and the detail goes to the server log only.
const BODY_PARSER_ERRORS = {
  'entity.parse.failed': [400, 'Malformed JSON request body'],
  'entity.too.large': [413, 'Request body too large'],
  'encoding.unsupported': [415, 'Unsupported request body encoding'],
  'charset.unsupported': [415, 'Unsupported request body encoding'],
  'entity.verify.failed': [400, 'Invalid request body'],
  'parameters.too.many': [413, 'Request body too large'],
  'request.aborted': [400, 'Invalid request body'],
  'request.size.invalid': [400, 'Invalid request body'],
}
const errorHandler = (err, req, res, _next) => {
  if (typeof err.type === 'string' && BODY_PARSER_ERRORS[err.type]) {
    const [status, publicMessage] = BODY_PARSER_ERRORS[err.type]
    logger.warn('[' + req.method + '] ' + req.path + ' -> ' + status + ' body rejected (' + err.type + ')')
    return sendError(res, publicMessage, status)
  }
  let statusCode = err.statusCode || 500
  let message = err.message || 'Server Error'
  if (err.name === 'CastError') {
    message = 'Invalid identifier for ' + err.path
    statusCode = 400
  }
  if (err.code === 11000) {
    const field = err.keyValue && Object.keys(err.keyValue)[0]
    message = field ? field + ' already exists' : 'Resource already exists'
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
