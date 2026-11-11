'use strict'
/**
 * Deception Arena: metrics and conclusion rules (pure), the experiment API (auth, RBAC, validation, cancellation,
 * read-only reads, runner gating, idempotent trials) and an end-to-end run of the real Python runner
 * (ai-engine/demo/deception_arena.py) against this API on an in-memory MongoDB.
 */
process.env.SENTINEL_KEY = 'unit-test-sentinel-key-deception-arena-32ch'
process.env.HONEYPOT_API_KEY = 'unit-test-honeypot-key-deception-arena-32c'
process.env.NODE_ENV = 'test'

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { execFile } = require('child_process')
const execFileAsync = require('util').promisify(execFile)
const express = require('express')
const request = require('supertest')
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../utils/auditLogger', () => ({ logAudit: jest.fn().mockResolvedValue() }))
jest.mock('../middleware/auth', () => ({
  protect: (req, res, next) =>
    req.headers['x-test-role']
      ? ((req.user = { role: req.headers['x-test-role'], email: `${req.headers['x-test-role']}@t` }), next())
      : res.status(401).json({ success: false }),
  restrictTo:
    (...roles) =>
    (req, res, next) =>
      roles.includes(req.user.role) ? next() : res.status(403).json({ success: false }),
}))

const DeceptionExperiment = require('../models/DeceptionExperiment')
const HoneypotSession = require('../models/HoneypotSession')
const M = require('../utils/deceptionArenaMetrics')

const ENGINE = path.resolve(__dirname, '../../ai-engine')
const app = express()
  .use(express.json({ limit: '10kb' }))
  .use('/api/deception-arena', require('../routes/deceptionArena'))
const as = (role) => ({ 'x-test-role': role })
const KEY = { 'x-api-key': process.env.SENTINEL_KEY }

const trial = (strategy, index, over = {}) => ({
  strategy,
  index,
  persona: 'centos_7',
  durationSeconds: 60,
  commands: [
    { command: 'uname -a', intent: 'RECONNAISSANCE' },
    { command: 'id', intent: 'RECONNAISSANCE' },
  ],
  termination: 'completed',
  reward: 3,
  ...over,
})
const adaptive = (index, persona, over = {}) =>
  trial('ADAPTIVE', index, {
    persona,
    decision: {
      state: 'centos_7',
      recommendedPersona: persona,
      appliedPersona: persona,
      explored: false,
      policy: 'q_learning',
      qValues: { centos_7: 1.2, ubuntu_22: 1.4 },
    },
    ...over,
  })

describe('metrics', () => {
  test('describe: mean and median, missing values counted, zero observations give nulls', () => {
    expect(M.describe([3, 1, 2, null, 10])).toEqual({ n: 4, missing: 1, mean: 4, median: 2.5, min: 1, max: 10 })
    expect(M.describe([])).toEqual({ n: 0, missing: 0, mean: null, median: null, min: null, max: null })
    expect(M.describe([undefined, NaN])).toMatchObject({ n: 0, missing: 2, mean: null })
  })

  test('unique commands, MITRE dedup, persona switches, recommendation vs application, reward kept separate', () => {
    const exp = {
      status: 'COMPLETED',
      scenario: 'persona_sensitive_sim',
      trials: [
        trial('STATIC', 0, { commands: [{ command: 'whoami' }, { command: 'whoami' }, { command: 'id' }] }),
        adaptive(0, 'ubuntu_22', { commands: [{ command: 'whoami' }, { command: 'cat /etc/passwd' }] }),
        adaptive(1, 'ubuntu_22', {
          decision: {
            state: 'ubuntu_22',
            recommendedPersona: 'debian_11',
            appliedPersona: 'ubuntu_22',
            explored: true,
          },
          commands: [{ command: 'id' }],
        }),
        adaptive(2, 'debian_11', { durationSeconds: null, commands: [] }),
      ],
    }
    const { summary } = M.evaluate(exp)
    expect(summary.STATIC.uniqueCommandsPerTrial.mean).toBe(2)
    expect(summary.STATIC.commands.mean).toBe(3)
    expect(summary.STATIC.techniques.map((t) => t.id)).toEqual(['T1033']) // whoami and id both map to T1033 once
    expect(summary.ADAPTIVE.techniques.map((t) => t.id)).toEqual(['T1003.008', 'T1033'])
    expect(summary.ADAPTIVE.uniqueCommandsTotal).toBe(3)
    expect(summary.ADAPTIVE.personaSwitches).toBe(1)
    expect(summary.ADAPTIVE).toMatchObject({ recommendations: 3, recommendationsApplied: 2, explorations: 1 })
    expect(summary.ADAPTIVE.durationSeconds).toMatchObject({ n: 2, missing: 1 })
    expect(summary.ADAPTIVE.reward).toMatchObject({ n: 3, mean: 3 })
  })

  test('paired comparison: no interval below the minimum pairs; t-interval at/above it', () => {
    const st = Array.from({ length: 12 }, (_, i) => ({ index: i, x: 5 }))
    const ad = Array.from({ length: 12 }, (_, i) => ({ index: i, x: 5 + (i % 3) }))
    const p = M.paired(st, ad, (t) => t.x)
    expect(p.pairs).toBe(12)
    expect(p.meanDifference).toBe(1)
    expect(p.method).toBe('paired t-interval (95%)')
    expect(p.ci95[0]).toBeGreaterThan(0.4)
    expect(p.ci95[1]).toBeLessThan(1.6)
    expect(M.paired(st.slice(0, 3), ad.slice(0, 3), (t) => t.x).ci95).toBeNull()
    expect(M.paired([], [], (t) => t.x)).toMatchObject({ pairs: 0, meanDifference: null })
    expect(M.t95(9)).toBe(2.262)
    expect(M.t95(45)).toBeCloseTo(2.015, 3)
  })

  test('scripted scenario: never an engagement claim, mechanics check only', () => {
    const exp = {
      status: 'COMPLETED',
      scenario: 'scripted_recon',
      trials: [trial('STATIC', 0), adaptive(0, 'ubuntu_22')],
    }
    const c = M.evaluate(exp).conclusion
    expect(c.headline).toBe('The scripted scenario does not measure adaptive attacker engagement.')
    expect(c.findings.find((f) => f.code === 'MECHANICS').text).toMatch(/identical sessions/)
    expect(c.adaptiveBenefitEstablished).toBe(false)
  })

  test('simulated: small sample is inconclusive; a favourable mean alone is never a claim', () => {
    const trials = [0, 1, 2].flatMap((i) => [
      trial('STATIC', i),
      adaptive(i, 'ubuntu_22', { commands: Array(9).fill({ command: 'id' }) }),
    ])
    const c = M.evaluate({ status: 'COMPLETED', scenario: 'persona_sensitive_sim', trials }).conclusion
    expect(c.headline).toMatch(/^Inconclusive: 3 paired trials is too few/)
    expect(JSON.stringify(c)).not.toMatch(/better|improv|significant/i)
  })

  test('simulated, enough pairs: interval-based wording limited to the simulation', () => {
    const trials = Array.from({ length: 12 }, (_, i) => [
      trial('STATIC', i),
      adaptive(i, 'ubuntu_22', { commands: Array(3 + (i % 2)).fill({ command: 'id' }) }),
    ]).flat()
    const c = M.evaluate({ status: 'COMPLETED', scenario: 'persona_sensitive_sim', trials }).conclusion
    expect(c.headline).toMatch(/^In this simulation, the adaptive strategy captured more commands/)
    expect(c.findings.map((f) => f.code)).toEqual(
      expect.arrayContaining(['SIM_ASSUMPTIONS', 'REWARD_NOT_OUTCOME', 'LIVE_CAVEAT'])
    )
    expect(c.adaptiveBenefitEstablished).toBe(false)
  })

  test('not completed / static only', () => {
    expect(M.evaluate({ status: 'RUNNING', scenario: 'scripted_recon', trials: [] }).conclusion.headline).toMatch(
      /has not completed/
    )
    expect(
      M.evaluate({ status: 'COMPLETED', scenario: 'scripted_recon', trials: [trial('STATIC', 0)] }).conclusion.headline
    ).toMatch(/not run/)
  })

  test('scenario allowlist matches the Python runner', () => {
    const py = fs.readFileSync(path.join(ENGINE, 'demo', 'deception_arena.py'), 'utf8')
    const block = py.slice(py.indexOf('SCENARIOS = {'), py.indexOf('\ndef sha256'))
    const ids = [...block.matchAll(/^ {4}"([a-z_]+)": \{/gm)].map((m) => m[1]).sort()
    expect(ids).toEqual(Object.keys(M.SCENARIOS).sort())
    for (const id of ids) {
      const kind = block.slice(block.indexOf(`"${id}"`)).match(/"kind": "([A-Z]+)"/)[1]
      expect(kind).toBe(M.SCENARIOS[id].kind)
    }
  })
})

let mongo
beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
  await DeceptionExperiment.init()
})
afterAll(async () => {
  await mongoose.disconnect()
  await mongo.stop()
})
const VALID = {
  name: 'Arena test',
  scenario: 'scripted_recon',
  baselinePersona: 'centos_7',
  trialsPerStrategy: 2,
  seed: 7,
}
const create = async (body = VALID, role = 'analyst') =>
  request(app).post('/api/deception-arena/experiments').set(as(role)).send(body)

describe('experiment API', () => {
  beforeEach(() => {
    process.env.DECEPTION_ARENA_RUNNER_ENABLED = 'true'
  })

  test('auth and RBAC: reads need a session; create/cancel need admin or analyst', async () => {
    expect((await request(app).get('/api/deception-arena/experiments')).status).toBe(401)
    expect((await request(app).get('/api/deception-arena/experiments').set(as('viewer'))).status).toBe(200)
    expect((await create(VALID, 'viewer')).status).toBe(403)
    expect((await create(VALID, 'admin')).status).toBe(201)
  })

  test('configuration is validated and bounded; no free-form commands are accepted', async () => {
    for (const bad of [
      { ...VALID, scenario: 'rm -rf /' },
      { ...VALID, baselinePersona: 'kali' },
      { ...VALID, trialsPerStrategy: 51 },
      { ...VALID, trialsPerStrategy: '5' },
      { ...VALID, maxTrialSeconds: 99999 },
      { ...VALID, name: 'x' },
      { ...VALID, seed: { $gt: 1 } },
    ])
      expect((await create(bad)).status).toBe(422)
    const r = await create({
      ...VALID,
      commands: ['cat /etc/shadow'],
      status: 'COMPLETED',
      trials: [trial('STATIC', 0)],
    })
    expect(r.status).toBe(201)
    expect(r.body.data.experiment).toMatchObject({ status: 'CREATED', trials: [] })
    expect(r.body.data.experiment.commands).toBeUndefined()
  })

  test('malformed IDs are rejected before any query', async () => {
    expect((await request(app).get('/api/deception-arena/experiments/{"$ne":1}').set(as('viewer'))).status).toBe(400)
    expect(
      (await request(app).get(`/api/deception-arena/experiments/${crypto.randomUUID()}`).set(as('viewer'))).status
    ).toBe(404)
  })

  test('runner endpoints: key required, honeypot key refused, disabled unless explicitly enabled', async () => {
    const id = (await create()).body.data.experiment.experimentId
    const url = `/api/deception-arena/runner/${id}/claim`
    expect((await request(app).post(url)).status).toBe(401)
    expect((await request(app).post(url).set('x-api-key', process.env.HONEYPOT_API_KEY)).status).toBe(403)
    expect((await request(app).post(url).set(as('admin'))).status).toBe(401)
    process.env.DECEPTION_ARENA_RUNNER_ENABLED = 'false'
    expect((await request(app).post(url).set(KEY)).status).toBe(403)
  })

  test('lifecycle: claim once, idempotent trials, trial validation, cancel request stops the runner', async () => {
    const id = (await create()).body.data.experiment.experimentId
    const base = `/api/deception-arena/runner/${id}`
    expect((await request(app).post(`${base}/claim`).set(KEY)).body.data.config).toMatchObject({
      scenario: 'scripted_recon',
      trialsPerStrategy: 2,
    })
    expect((await request(app).post(`${base}/claim`).set(KEY)).status).toBe(409)
    const post = (t) => request(app).post(`${base}/trials`).set(KEY).send({ trial: t })
    expect((await post(trial('STATIC', 0))).body.data).toEqual({ accepted: true, cancelRequested: false })
    expect((await post(trial('STATIC', 0))).body.data.accepted).toBe(false) // duplicate delivery adds nothing
    expect((await post(trial('STATIC', 1, { persona: 'ubuntu_22' }))).status).toBe(422) // static must serve the baseline
    expect((await post(trial('STATIC', 5))).status).toBe(422)
    expect(
      (
        await post(
          adaptive(0, 'ubuntu_22', {
            decision: { state: 'centos_7', recommendedPersona: 'ubuntu_22', appliedPersona: 'debian_11' },
          })
        )
      ).status
    ).toBe(422)
    expect((await post(trial('STATIC', 1, { commands: Array(51).fill({ command: 'id' }) }))).status).toBe(422)
    expect(
      (await request(app).post(`/api/deception-arena/experiments/${id}/cancel`).set(as('analyst'))).body.data.experiment
        .cancelRequested
    ).toBe(true)
    expect((await post(adaptive(0, 'ubuntu_22'))).body.data.cancelRequested).toBe(true)
    const hashes = { before: { seedTable: 'a' }, after: { seedTable: 'a' } }
    expect(
      (
        await request(app)
          .post(`${base}/complete`)
          .set(KEY)
          .send({ provenance: { qTableHashes: hashes } })
      ).body.data.status
    ).toBe('CANCELLED')
    expect(
      (
        await request(app)
          .post(`${base}/trials`)
          .set(KEY)
          .send({ trial: trial('STATIC', 1) })
      ).body.data.accepted
    ).toBe(false)
    const doc = (await request(app).get(`/api/deception-arena/experiments/${id}`).set(as('viewer'))).body.data
      .experiment
    expect(doc.trials).toHaveLength(2)
    expect(doc.events.map((e) => e.type)).toEqual([
      'EXPERIMENT_CREATED',
      'RUN_STARTED',
      'TRIAL_COMPLETED',
      'CANCEL_REQUESTED',
      'PERSONA_RECOMMENDED',
      'TRIAL_COMPLETED',
      'RUN_CANCELLED',
    ])
  })

  test('a run that reports changed Q-table hashes is marked FAILED', async () => {
    const id = (await create()).body.data.experiment.experimentId
    const base = `/api/deception-arena/runner/${id}`
    await request(app).post(`${base}/claim`).set(KEY)
    const r = await request(app)
      .post(`${base}/complete`)
      .set(KEY)
      .send({ provenance: { qTableHashes: { before: { s: 1 }, after: { s: 2 } } } })
    expect(r.body.data.status).toBe('FAILED')
  })

  test('cancel: waiting experiments cancel at once; finished ones cannot be revived', async () => {
    const id = (await create()).body.data.experiment.experimentId
    expect(
      (await request(app).post(`/api/deception-arena/experiments/${id}/cancel`).set(as('admin'))).body.data.experiment
        .status
    ).toBe('CANCELLED')
    expect((await request(app).post(`/api/deception-arena/experiments/${id}/cancel`).set(as('admin'))).status).toBe(409)
    expect((await request(app).post(`/api/deception-arena/runner/${id}/claim`).set(KEY)).status).toBe(409)
  })

  test('reads never write, and never touch honeypot sessions', async () => {
    await HoneypotSession.create({
      sessionId: 'obs-1',
      sourceIP: '198.51.100.9',
      servedProfile: 'ubuntu_22',
      durationSeconds: 40,
      commandCount: 3,
    })
    const before = JSON.stringify(await DeceptionExperiment.find().sort({ _id: 1 }).lean())
    const sessions = await HoneypotSession.countDocuments()
    await request(app).get('/api/deception-arena/experiments').set(as('viewer'))
    const obs = (await request(app).get('/api/deception-arena/observational').set(as('viewer'))).body.data
    expect(obs.byPersona).toEqual([
      { persona: 'ubuntu_22', sessions: 1, synthetic: 0, meanDurationSeconds: 40, meanCommands: 3 },
    ])
    const list = (await request(app).get('/api/deception-arena/experiments?status=CANCELLED').set(as('viewer'))).body
      .data
    for (const e of list) await request(app).get(`/api/deception-arena/experiments/${e.experimentId}`).set(as('viewer'))
    expect(JSON.stringify(await DeceptionExperiment.find().sort({ _id: 1 }).lean())).toBe(before)
    expect(await HoneypotSession.countDocuments()).toBe(sessions)
  })

  test('scenarios endpoint discloses that live mode is unavailable', async () => {
    const d = (await request(app).get('/api/deception-arena/scenarios').set(as('viewer'))).body.data
    expect(d.liveMode.available).toBe(false)
    expect(d.scenarios.map((s) => s.id).sort()).toEqual(['persona_sensitive_sim', 'scripted_dropper', 'scripted_recon'])
  })
})

// ---- Real runner, end to end ----
// Located on disk (no child process here: see the blocking-child guard in containmentAuditSpool.test.js).
const exe = process.platform === 'win32' ? ['python.exe', 'python3.exe'] : ['python3', 'python']
const onPath = (process.env.PATH || '').split(path.delimiter).flatMap((dir) => exe.map((n) => path.join(dir, n)))
const python = [
  process.env.PYTHON,
  path.join(ENGINE, '.venv', 'Scripts', 'python.exe'),
  path.join(ENGINE, '.venv', 'bin', 'python'),
  ...onPath,
].find((p) => p && !/WindowsApps/i.test(p) && fs.existsSync(p))
const sha = (f) => (fs.existsSync(f) ? crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex') : null)
const QTABLES = [path.join(ENGINE, 'models', 'q_table.json'), path.join(ENGINE, 'runtime', 'q_table.json')]
;(python ? describe : describe.skip)('real runner (ai-engine/demo/deception_arena.py)', () => {
  let server
  let port
  beforeAll((done) => {
    process.env.DECEPTION_ARENA_RUNNER_ENABLED = 'true'
    server = app.listen(0, '127.0.0.1', () => {
      port = server.address().port
      done()
    })
  })
  afterAll((done) => {
    server.close(done)
  })

  test.each(['scripted_recon', 'persona_sensitive_sim'])(
    '%s: paired trials complete, learner decisions recorded, Q-tables untouched, results deterministic',
    async (scenario) => {
      const hashes = QTABLES.map(sha)
      const run = async () => {
        const id = (await create({ ...VALID, scenario, trialsPerStrategy: 6, seed: 11 })).body.data.experiment
          .experimentId
        await execFileAsync(
          python,
          [
            path.join(ENGINE, 'demo', 'deception_arena.py'),
            '--backend',
            `http://127.0.0.1:${port}`,
            '--experiment',
            id,
          ],
          {
            env: { ...process.env, SENTINEL_KEY: process.env.SENTINEL_KEY },
            timeout: 60000,
          }
        )
        return (await request(app).get(`/api/deception-arena/experiments/${id}`).set(as('viewer'))).body.data
      }
      const a = await run()
      const b = await run()
      expect(a.experiment.status).toBe('COMPLETED')
      expect(a.experiment.trials).toHaveLength(12)
      const st = a.experiment.trials.filter((t) => t.strategy === 'STATIC')
      const ad = a.experiment.trials.filter((t) => t.strategy === 'ADAPTIVE')
      expect(st.every((t) => t.persona === 'centos_7' && t.decision === null)).toBe(true)
      expect(ad.every((t) => t.decision && t.decision.appliedPersona === t.persona)).toBe(true)
      expect(a.experiment.provenance.qTableHashes.before).toEqual(a.experiment.provenance.qTableHashes.after)
      expect(QTABLES.map(sha)).toEqual(hashes)
      const strip = (r) => r.experiment.trials.map(({ startedAt, endedAt, ...t }) => t) // eslint-disable-line no-unused-vars
      expect(strip(b)).toEqual(strip(a))
      expect(b.results).toEqual(a.results)
      if (scenario === 'scripted_recon') {
        expect(a.results.conclusion.headline).toBe(
          'The scripted scenario does not measure adaptive attacker engagement.'
        )
        expect(a.results.comparison.commands).toMatchObject({ pairs: 6, meanDifference: 0 })
      } else {
        expect(a.results.conclusion.headline).toMatch(/^Inconclusive: 6 paired trials/)
      }
    },
    120000
  )
})
