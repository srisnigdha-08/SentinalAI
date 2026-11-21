'use strict'
/**
 * Rank 8: Jest setupFiles entry (package.json "jest.setupFiles"), runs in every test file before any module loads.
 *
 * Points every file-writing sink at a temporary directory of this test run, so no suite writes to, rotates or deletes
 * files in the real backend/logs. utils/logPaths.js also refuses the real directory on its own while Jest runs; this
 * is the second layer. Suites that need their own directory (containment spool tests) still set it explicitly.
 */
const fs = require('fs')
const os = require('os')
const path = require('path')
const { isInsideRealLogDir } = require('../../utils/logPaths')

const runDir = path.join(os.tmpdir(), `sentinel-jest-logs-${process.pid}`)
fs.mkdirSync(runDir, { recursive: true })
for (const name of ['LOG_DIR', 'EMERGENCY_AUDIT_DIR', 'OUTBOX_DIR']) {
  if (!process.env[name] || isInsideRealLogDir(process.env[name])) process.env[name] = runDir
}
