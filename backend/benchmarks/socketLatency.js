'use strict'
/**
 * Rank 8: repeatable Socket.IO latency benchmark on an ISOLATED local server (never the running demo).
 *
 *   node benchmarks/socketLatency.js [--quick] [--out <file.json>]
 *
 * The server uses the backend's own Socket.IO version and the options from server.js (pingTimeout 60 s,
 * pingInterval 25 s), listens on an ephemeral 127.0.0.1 port, and is closed at the end. The client is the frontend's
 * socket.io-client with the frontend's defaults (HTTP long-polling, then upgrade to WebSocket). Not included: the
 * application's authentication middleware, MongoDB and the AI engine (this measures transport + serialization +
 * room fan-out). Server and clients share one Node process and one CPU budget, so figures are a conservative local
 * baseline, not a network measurement. There is no project latency SLO: results are reported as a baseline only.
 */
const http = require('http')
const os = require('os')
const fs = require('fs')
const path = require('path')
const { Server } = require('socket.io')
const { io: connect } = require(path.join(__dirname, '..', '..', 'frontend', 'node_modules', 'socket.io-client'))

const QUICK = process.argv.includes('--quick')
const outIdx = process.argv.indexOf('--out')
const OUT = outIdx > 0 ? process.argv[outIdx + 1] : null

const now = () => Number(process.hrtime.bigint()) / 1e6 // ms, monotonic, shared by server and clients
const pct = (xs, p) => {
  if (!xs.length) return null
  const s = [...xs].sort((a, b) => a - b)
  return +s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)].toFixed(3)
}
const stats = (xs) => ({
  n: xs.length,
  p50: pct(xs, 50),
  p95: pct(xs, 95),
  p99: pct(xs, 99),
  max: xs.length ? +Math.max(...xs).toFixed(3) : null,
})

// A representative ai_prediction event (same fields socketManager.emitAIPrediction sends).
const typicalEvent = () => ({
  id: '665f1c2e9b3e4a0012345678',
  sourceIP: '198.51.100.23',
  targetIP: '10.20.30.15',
  predictedClass: 'DDoS',
  classProbabilities: { BENIGN: 0.01, DDoS: 0.97, 'Port Scan': 0.01, 'SSH Brute Force': 0.01 },
  threatScore: 0.97,
  action: 'BLOCK',
  modelType: 'xgboost',
  modelVersion: 'xgb_cicids_v1',
  isAnomaly: true,
  anomalyScore: 0.62,
  inferenceTimeMs: 4.1,
  inputSource: 'network_traffic',
  captureSource: 'pcap_replay',
  createdAt: new Date().toISOString(),
  timestamp: new Date().toISOString(),
})
const sizeOf = (o) => Buffer.byteLength(JSON.stringify(o))

async function startServer() {
  const server = http.createServer()
  const io = new Server(server, { pingTimeout: 60000, pingInterval: 25000 })
  io.on('connection', (socket) => {
    socket.join(['admin', 'analyst'])
    socket.on('bench:echo', (msg, ack) => ack && ack(msg.t))
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  return { io, server, url: `http://127.0.0.1:${server.address().port}` }
}

async function connectClients(url, n, opts = {}) {
  const times = []
  const clients = await Promise.all(
    Array.from(
      { length: n },
      () =>
        new Promise((resolve, reject) => {
          const t0 = now()
          const c = connect(url, { reconnection: false, forceNew: true, ...opts })
          c.once('connect', () => {
            times.push(now() - t0)
            resolve(c)
          })
          c.once('connect_error', reject)
        })
    )
  )
  return { clients, times }
}

async function rtt(clients, perClient, payload) {
  const lat = []
  let errors = 0
  await Promise.all(
    clients.map(async (c) => {
      for (let i = 0; i < perClient; i++) {
        const t = now()
        try {
          await c.timeout(10000).emitWithAck('bench:echo', { t, payload })
          lat.push(now() - t)
        } catch {
          errors++
        }
      }
    })
  )
  return { ...stats(lat), errors }
}

async function broadcast(io, clients, events, payload, paceMs = 0) {
  const lat = []
  let received = 0
  const expected = events * clients.length
  const done = new Promise((resolve) => {
    for (const c of clients)
      c.on('ai_prediction', (e) => {
        lat.push(now() - e.sentAt)
        if (++received === expected) resolve()
      })
  })
  const t0 = now()
  for (let i = 0; i < events; i++) {
    io.to(['admin', 'analyst']).emit('ai_prediction', { ...payload, sentAt: now() })
    if (paceMs) await new Promise((r) => setTimeout(r, paceMs))
    else if (i % 50 === 49) await new Promise((r) => setImmediate(r))
  }
  await Promise.race([done, new Promise((r) => setTimeout(r, 30000))])
  const elapsed = now() - t0
  for (const c of clients) c.off('ai_prediction')
  return {
    ...stats(lat),
    expected,
    received,
    dropped: expected - received,
    throughputEventsPerSec: +((received / elapsed) * 1000).toFixed(1),
    elapsedMs: +elapsed.toFixed(1),
  }
}

async function oversizeAndDisconnect(url, io) {
  const out = {}
  // client -> server message above the server's maxHttpBufferSize (Socket.IO default 1e6 bytes)
  const {
    clients: [c],
  } = await connectClients(url, 1, { transports: ['websocket'] })
  out.oversizeClientToServer = await new Promise((resolve) => {
    const t = setTimeout(() => resolve({ outcome: 'no-disconnect-within-5s' }), 5000)
    c.once('disconnect', (reason) => {
      clearTimeout(t)
      resolve({ outcome: 'disconnected', reason, bytes: 1_500_000 })
    })
    c.emit('bench:echo', { t: now(), payload: 'x'.repeat(1_500_000) })
  })
  c.close()
  // server-side disconnect, then automatic reconnection (the frontend's settings)
  const r = connect(url, {
    forceNew: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    reconnectionAttempts: 10,
  })
  await new Promise((res) => r.once('connect', res))
  const t0 = now()
  const reason = new Promise((res) => r.once('disconnect', res))
  for (const s of await io.fetchSockets()) if (s.id === r.id) s.disconnect(true)
  out.serverDisconnect = { reason: await reason }
  // Socket.IO never auto-reconnects after 'io server disconnect': the client must call connect() itself.
  const autoReconnected = await Promise.race([
    new Promise((res) => r.once('connect', () => res(true))),
    new Promise((res) => setTimeout(() => res(false), 3000)),
  ])
  out.serverDisconnect.autoReconnectedWithin3s = autoReconnected
  if (!autoReconnected) {
    const t1 = now()
    r.connect()
    out.serverDisconnect.manualReconnectMs = await Promise.race([
      new Promise((res) => r.once('connect', () => res(+(now() - t1).toFixed(1)))),
      new Promise((res) => setTimeout(() => res(null), 5000)),
    ])
  }
  out.serverDisconnect.elapsedMs = +(now() - t0).toFixed(1)
  r.close()
  // client-side transport drop (network loss): Socket.IO reconnects automatically with the frontend's settings
  const d = connect(url, {
    forceNew: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    reconnectionAttempts: 10,
  })
  await new Promise((res) => d.once('connect', res))
  const t2 = now()
  const dropReason = new Promise((res) => d.once('disconnect', res))
  d.io.engine.close() // simulate the transport going away
  out.transportDrop = { reason: await dropReason }
  out.transportDrop.reconnectMs = await Promise.race([
    new Promise((res) => d.once('connect', () => res(+(now() - t2).toFixed(1)))),
    new Promise((res) => setTimeout(() => res(null), 10000)),
  ])
  d.close()
  return out
}

;(async () => {
  const { io, server, url } = await startServer()
  const result = {
    benchmark: 'socket.io isolated local baseline (Rank 8)',
    environment: {
      node: process.version,
      socketIoServer: require('socket.io/package.json').version,
      socketIoClient: require(
        path.join(__dirname, '..', '..', 'frontend', 'node_modules', 'socket.io-client', 'package.json')
      ).version,
      platform: `${os.type()} ${os.release()} ${os.arch()}`,
      cpu: os.cpus()[0]?.model,
      cpus: os.cpus().length,
      memoryGB: +(os.totalmem() / 2 ** 30).toFixed(1),
      serverOptions: { pingTimeout: 60000, pingInterval: 25000 },
      sameProcess: true,
      network: 'loopback 127.0.0.1',
      mode: QUICK ? 'quick' : 'full',
    },
    payloadBytes: { typical: sizeOf(typicalEvent()) },
    slo: 'none defined by the project: owner-approved target still needed',
    scenarios: {},
  }
  const typical = typicalEvent()
  const large = { ...typicalEvent(), blob: 'x'.repeat(512 * 1024) }
  result.payloadBytes.large = sizeOf(large)
  const counts = QUICK ? [1, 10] : [1, 10, 50]
  for (const transports of [undefined, ['websocket']]) {
    const label = transports ? 'websocket' : 'default(polling+upgrade)'
    for (const n of counts) {
      const { clients, times } = await connectClients(url, n, transports ? { transports } : {})
      // let polling clients finish their upgrade before measuring
      await new Promise((r) => setTimeout(r, 300))
      const key = `${label} x${n}`
      result.scenarios[key] = {
        clients: n,
        connectMs: stats(times),
        rttTypical: await rtt(clients, QUICK ? 50 : 200, typical),
        broadcastTypical: await broadcast(io, clients, QUICK ? 100 : 500, typical),
      }
      if (n === 10) result.scenarios[key].broadcastLarge512KB = await broadcast(io, clients, QUICK ? 5 : 20, large, 5)
      for (const c of clients) c.close()
    }
  }
  // sustained throughput: 10 WebSocket clients, back-to-back broadcasts
  {
    const { clients } = await connectClients(url, 10, { transports: ['websocket'] })
    result.scenarios['sustained websocket x10'] = {
      clients: 10,
      ...(await broadcast(io, clients, QUICK ? 1000 : 5000, typical)),
    }
    for (const c of clients) c.close()
  }
  result.errorBehaviour = await oversizeAndDisconnect(url, io)
  io.close()
  server.close()
  const text = JSON.stringify(result, null, 1)
  if (OUT) fs.writeFileSync(OUT, text)
  console.log(text)
  process.exit(0)
})().catch((e) => {
  console.error('benchmark failed:', e)
  process.exit(1)
})
