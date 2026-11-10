'use strict'
/**
 * Runs a child process without blocking this one, for tests that hold a mongodb-memory-server in the same process.
 *
 * That server's log travels through a pipe only this process reads. spawnSync stops the reading, the pipe fills, mongod
 * blocks writing its log, and the child waiting on mongod never finishes (CI runs 42611611697 and 42645350654).
 * Every child is bounded. The result has the same fields as spawnSync: status, signal, stdout, stderr and error.
 */
const { spawn } = require('child_process')

const DEFAULT_TIMEOUT_MS = 45000

function runChild(command, args, { timeoutMs = DEFAULT_TIMEOUT_MS, cwd, env } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    let timedOut = false
    child.stdout.setEncoding('utf8').on('data', (d) => (stdout += d))
    child.stderr.setEncoding('utf8').on('data', (d) => (stderr += d))
    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, timeoutMs)
    child.on('error', (error) => {
      clearTimeout(timer)
      resolve({ status: null, signal: null, stdout, stderr, error })
    })
    child.on('close', (status, signal) => {
      clearTimeout(timer)
      const error = timedOut ? Object.assign(new Error(`timed out after ${timeoutMs} ms`), { code: 'ETIMEDOUT' }) : undefined
      resolve({ status, signal, stdout, stderr, error })
    })
  })
}

module.exports = { runChild }
