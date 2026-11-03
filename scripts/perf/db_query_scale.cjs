/**
 * Threat-list and dashboard-analytics query time as the ThreatLog collection grows (batch 13). Uses the backend's own
 * threatService functions against a throwaway mongod (127.0.0.1:27420, temp dbpath, deleted afterwards); no existing
 * database is touched. Synthetic threats spread over 30 days with realistic severities, statuses and attack types.
 *
 *   node scripts/perf/db_query_scale.cjs [--sizes 1000,10000,50000] [--reps 7]
 */
const { spawn, spawnSync } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')

const root = path.resolve(__dirname, '../..')
const mongoose = require(path.join(root, 'backend/node_modules/mongoose'))
const arg = (n, d) => (process.argv.indexOf('--' + n) > 0 ? process.argv[process.argv.indexOf('--' + n) + 1] : d)
const SIZES = arg('sizes', '1000,10000,50000').split(',').map(Number)
const REPS = parseInt(arg('reps', '7'), 10)
const PORT = 27420

const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)]
const timeIt = async (fn) => {
  const t = []
  for (let i = 0; i < REPS; i++) {
    const s = performance.now()
    await fn()
    t.push(performance.now() - s)
  }
  return Math.round(median(t) * 10) / 10
}

async function main() {
  const bin = [path.join(root, 'backend/node_modules/.cache/mongodb-memory-server/mongod-x64-win32-8.2.6.exe'),
    path.join(os.homedir(), '.cache/mongodb-binaries/mongod-x64-win32-8.2.6.exe')].find((p) => fs.existsSync(p))
  if (!bin) throw new Error('no throwaway mongod binary found')
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-dbscale-'))
  const mongod = spawn(bin, ['--port', String(PORT), '--bind_ip', '127.0.0.1', '--dbpath', tmp], { windowsHide: true, stdio: 'ignore' })
  try {
    for (let i = 0; ; i++) {
      try {
        await mongoose.connect(`mongodb://127.0.0.1:${PORT}/sentinelai_dbscale`, { serverSelectionTimeoutMS: 1000 })
        break
      } catch (e) {
        if (i > 30) throw e
        await new Promise((r) => setTimeout(r, 500))
      }
    }
    const ThreatLog = require(path.join(root, 'backend/models/ThreatLog'))
    await ThreatLog.syncIndexes()
    const svc = require(path.join(root, 'backend/services/threatService'))
    const types = ['DDoS', 'Port Scan', 'SSH Brute Force', 'SQL Injection', 'XSS Attempt', 'Credential Stuffing']
    const sev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    const status = ['DETECTED', 'MONITORING', 'BLOCKED', 'INVESTIGATING', 'RESOLVED']
    const rows = []
    let have = 0
    for (const size of SIZES) {
      const batch = []
      for (let i = have; i < size; i++) {
        batch.push({ severity: sev[i % 4], status: status[i % 5], attackType: types[i % 6], sourceIP: `198.51.${(i >> 8) % 256}.${i % 256}`,
          aiScore: 0.9 + (i % 10) / 100, createdAt: new Date(Date.now() - (i % (30 * 24 * 60)) * 60000), mitreTechniques: [{ id: 'T1498', name: 'Network DoS' }] })
      }
      for (let i = 0; i < batch.length; i += 5000) await ThreatLog.collection.insertMany(batch.slice(i, i + 5000), { ordered: false })
      have = size
      const plan = await ThreatLog.find({}).sort({ createdAt: -1 }).limit(20).explain('executionStats')
      const stage = JSON.stringify(plan.queryPlanner?.winningPlan || plan).match(/"stage":"(IXSCAN|COLLSCAN)"/)?.[1]
      rows.push({
        threats: size,
        listPage1Ms: await timeIt(() => svc.findThreats({ page: 1, limit: 20 })),
        listCriticalMs: await timeIt(() => svc.findThreats({ page: 1, limit: 20, severity: 'CRITICAL' })),
        listSearchMs: await timeIt(() => svc.findThreats({ page: 1, limit: 20, search: '198.51.7' })),
        dashboardAnalyticsMs: await timeIt(() => svc.getDashboardAnalytics()),
        listSortPlan: stage,
      })
      console.log(JSON.stringify(rows[rows.length - 1]))
    }
    return rows
  } finally {
    await mongoose.disconnect().catch(() => {})
    if (process.platform === 'win32') spawnSync('taskkill', ['/PID', String(mongod.pid), '/T', '/F'])
    else mongod.kill('SIGKILL')
    await new Promise((r) => (mongod.exitCode !== null ? r() : mongod.once('exit', r)))
    fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 })
  }
}

main().then(() => process.exit(0), (e) => {
  console.error(e.message)
  process.exit(1)
})
