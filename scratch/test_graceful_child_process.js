'use strict'

const { spawn } = require('child_process')
const http = require('http')
const path = require('path')

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = ''
      res.on('data', (chunk) => (data += chunk))
      res.on('end', () => resolve({ statusCode: res.statusCode, data }))
    }).on('error', reject)
  })
}

async function runChildProcessShutdownTest() {
  console.log('=== Testing Graceful Shutdown in Isolated Child Process ===')

  // Child script content inline
  const childScript = `
const http = require('http');
const express = require('${path.join(__dirname, '..', 'backend', 'node_modules', 'express').replace(/\\/g, '/')}');
const { GracefulShutdownManager } = require('${path.join(__dirname, '..', 'backend', 'utils', 'gracefulShutdown.js').replace(/\\/g, '/')}');

const app = express();
const shutdownManager = new GracefulShutdownManager({
  drainTimeoutMs: 2000,
  emergencyTimeoutMs: 4000,
  onExit: (code) => {
    console.log('[CHILD] Exiting with code: ' + code);
    process.exit(code);
  }
});

app.use(shutdownManager.middleware());

app.get('/health', (req, res) => {
  res.json({ status: 'ok', inFlight: shutdownManager.inFlightRequests });
});

app.get('/slow', (req, res) => {
  setTimeout(() => {
    res.json({ status: 'slow_finished' });
  }, 500);
});

const server = app.listen(5055, '127.0.0.1', () => {
  shutdownManager.setServer(server);
  shutdownManager.attachSignalHandlers();
  console.log('[CHILD_READY] Server listening on port 5055');
});
`

  const child = spawn('node', ['-e', childScript], {
    stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
    windowsHide: true,
  })

  let ready = false
  child.stdout.on('data', (d) => {
    const text = d.toString()
    process.stdout.write(text)
    if (text.includes('[CHILD_READY]')) ready = true
  })
  child.stderr.on('data', (d) => process.stderr.write(d.toString()))

  // Wait for child to be ready
  const start = Date.now()
  while (!ready && Date.now() - start < 5000) {
    await sleep(100)
  }

  if (!ready) {
    child.kill()
    throw new Error('Child server did not start in time')
  }

  console.log('[TEST] Checking health endpoint on child...')
  const healthRes = await httpGet('http://127.0.0.1:5055/health')
  console.log('[TEST] Health response:', healthRes.data)

  // Start slow request, then trigger IPC shutdown
  console.log('[TEST] Initiating slow in-flight request and sending IPC shutdown message...')
  const slowReqPromise = httpGet('http://127.0.0.1:5055/slow')

  await sleep(100)
  // Send IPC shutdown message to child
  child.send('shutdown')

  const slowRes = await slowReqPromise
  console.log('[TEST] In-flight request completed successfully during drain:', slowRes.data)

  // Wait for child process exit
  const exitCode = await new Promise((resolve) => {
    child.on('exit', (code) => resolve(code))
  })

  console.log(`[TEST] Child process terminated with exit code: ${exitCode}`)
  if (exitCode === 0) {
    console.log('=== TEST RESULT: GRACEFUL SHUTDOWN IN CHILD PROCESS PASSED ===')
  } else {
    throw new Error(`Expected exit code 0, got ${exitCode}`)
  }
}

runChildProcessShutdownTest()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Child shutdown test failed:', err)
    process.exit(1)
  })
