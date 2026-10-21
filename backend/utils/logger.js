const { createLogger, format, transports } = require('winston')
const path = require('path')
const fs = require('fs')
const redact = require('./redact')
const { getRequestId } = require('./requestContext')
const logDir = process.env.LOG_DIR || path.join(__dirname, '../logs')
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true })
// Console: human-readable by default; LOG_FORMAT=json emits one JSON object per line (for log shippers).
const cf =
  process.env.LOG_FORMAT === 'json'
    ? format.combine(format.timestamp(), format.errors({ stack: true }), format.json())
    : format.combine(
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        format.colorize(),
        format.printf(
          ({ timestamp, level, message, requestId }) =>
            `${timestamp} [${level}]${requestId ? ` [${requestId.slice(0, 8)}]` : ''} ${message}`
        )
      )
const ff = format.combine(
  format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  format.errors({ stack: true }),
  format.json()
)
const logger = createLogger({
  format: format((info) => {
    for (const key of Object.keys(info)) info[key] = redact(info[key], key)
    const requestId = getRequestId()
    if (requestId && !info.requestId) info.requestId = requestId
    return info
  })(),
  level: process.env.LOG_LEVEL || 'info',
  transports: [
    new transports.Console({ format: cf }),
    new transports.File({ filename: path.join(logDir, 'sentinel.log'), format: ff, maxsize: 20971520, maxFiles: 14 }),
    new transports.File({ filename: path.join(logDir, 'errors.log'), format: ff, level: 'error' }),
  ],
})
module.exports = logger
