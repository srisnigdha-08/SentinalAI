'use strict'
/**
 * Minimal circuit breaker for calls to the AI engine.
 *
 * closed    -> calls pass; `failureThreshold` consecutive failures open the circuit
 * open      -> calls fail fast with code CIRCUIT_OPEN for `resetTimeoutMs` (no network wait)
 * half-open -> one trial call; success closes the circuit, failure re-opens it
 *
 * Only infrastructure failures count (connection errors, timeouts, HTTP 5xx). A 4xx means the engine is
 * up and rejected the input, so it neither opens the circuit nor is retried.
 */
const isInfrastructureFailure = (err) => !err?.response || err.response.status >= 500

const RETRYABLE_CODES = new Set(['ECONNREFUSED', 'ECONNRESET', 'EPIPE', 'EAI_AGAIN'])
// Retry only fast failures; a timeout already cost the full timeout, and 502/503 are transient.
const isRetryable = (err) => RETRYABLE_CODES.has(err?.code) || [502, 503].includes(err?.response?.status)

class CircuitBreaker {
  constructor({ failureThreshold = 5, resetTimeoutMs = 30000, now = () => Date.now() } = {}) {
    this.failureThreshold = failureThreshold
    this.resetTimeoutMs = resetTimeoutMs
    this.now = now
    this.failures = 0
    this.openedAt = null
  }

  get state() {
    if (this.openedAt === null) return 'closed'
    return this.now() - this.openedAt >= this.resetTimeoutMs ? 'half-open' : 'open'
  }

  async exec(fn) {
    if (this.state === 'open') {
      const err = new Error('AI engine circuit open')
      err.code = 'CIRCUIT_OPEN'
      throw err
    }
    try {
      const result = await fn()
      this.failures = 0
      this.openedAt = null
      return result
    } catch (err) {
      if (isInfrastructureFailure(err)) {
        this.failures++
        if (this.state === 'half-open' || this.failures >= this.failureThreshold) this.openedAt = this.now()
      }
      throw err
    }
  }

  reset() {
    this.failures = 0
    this.openedAt = null
  }
}

/** Retries `fn` on transient failures with jittered exponential backoff (base 200 ms). */
const withRetry = async (
  fn,
  { retries = 2, baseMs = 200, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}
) => {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn()
    } catch (err) {
      if (attempt >= retries || !isRetryable(err)) throw err
      await sleep(baseMs * 2 ** attempt * (0.5 + Math.random()))
    }
  }
}

module.exports = { CircuitBreaker, withRetry, isInfrastructureFailure, isRetryable }
