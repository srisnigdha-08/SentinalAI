const sendSuccess = (res, data = {}, message = 'Success', statusCode = 200) =>
  res.status(statusCode).json({ success: true, message, data, timestamp: new Date().toISOString() })
const sendError = (res, message = 'Error', statusCode = 500, errors = null) => {
  const b = { success: false, error: message, code: statusCode, timestamp: new Date().toISOString() }
  if (errors) b.errors = errors
  res.status(statusCode).json(b)
}
const sendPaginated = (res, data, total, page, limit) =>
  res.status(200).json({
    success: true,
    data,
    pagination: { total, page: parseInt(page), limit: parseInt(limit), pages: Math.ceil(total / limit) },
    timestamp: new Date().toISOString(),
  })
module.exports = { sendSuccess, sendError, sendPaginated }
