'use strict'

/**
 * Rank 8: one place that decides where the backend writes log and audit files.
 *
 * Production behaviour is unchanged: LOG_DIR (or a sink's own variable) when set, otherwise backend/logs.
 * Test isolation is fail-closed: while Jest runs (JEST_WORKER_ID is set), a directory that resolves inside the real
 * backend/logs is replaced by a per-process temporary directory, whatever a test or the environment configured.
 * Every sink calls logDir() when it writes (not once at import), so a test can redirect it at any time.
 *
 * Sinks: utils/logger.js (sentinel.log, errors.log), utils/emergencyAudit.js (emergency_audit*.log),
 * utils/containmentAudit.js (containment-audit-spool-*.jsonl), utils/securityEventBus.js (event_outbox.json).
 */
const fs = require('fs')
const os = require('os')
const path = require('path')

const REAL_LOG_DIR = path.resolve(__dirname, '..', 'logs')
let testDir = null

const underTest = () => Boolean(process.env.JEST_WORKER_ID)

function isInsideRealLogDir(dir) {
  const resolved = path.resolve(String(dir))
  const rel = path.relative(REAL_LOG_DIR, resolved)
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))
}

function testFallbackDir() {
  if (!testDir) {
    testDir = path.join(os.tmpdir(), `sentinel-test-logs-${process.pid}`)
    fs.mkdirSync(testDir, { recursive: true })
  }
  return testDir
}

/**
 * The directory a sink writes to. `envName` is the sink's own override (e.g. EMERGENCY_AUDIT_DIR); LOG_DIR is the
 * shared fallback; backend/logs the production default.
 */
function logDir(envName = 'LOG_DIR') {
  const configured = (envName && process.env[envName]) || process.env.LOG_DIR
  const dir = configured ? path.resolve(configured) : REAL_LOG_DIR
  if (underTest() && isInsideRealLogDir(dir)) return testFallbackDir()
  return dir
}

module.exports = { REAL_LOG_DIR, logDir, isInsideRealLogDir, underTest }
