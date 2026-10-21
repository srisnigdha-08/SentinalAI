'use strict'
/**
 * Per-request correlation id. Accepts a well-formed incoming X-Request-Id (from a proxy) or creates one,
 * echoes it in the response, exposes it to the logger and forwards it to the AI engine, so one request
 * can be followed across Node and FastAPI logs.
 */
const { AsyncLocalStorage } = require('async_hooks')
const crypto = require('crypto')

const storage = new AsyncLocalStorage()
const VALID_ID = /^[A-Za-z0-9._-]{8,64}$/

const middleware = (req, res, next) => {
  const incoming = req.headers['x-request-id']
  const requestId = typeof incoming === 'string' && VALID_ID.test(incoming) ? incoming : crypto.randomUUID()
  req.requestId = requestId
  res.setHeader('X-Request-Id', requestId)
  storage.run({ requestId }, next)
}

const getRequestId = () => storage.getStore()?.requestId

module.exports = { middleware, getRequestId, storage }
