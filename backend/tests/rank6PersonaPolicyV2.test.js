'use strict'
/**
 * Rank 6: persona policy v2 shadow evidence on the backend and its Capability Status (docs/PERSONA_POLICY_V2.md
 * section 9). The engine's policyV2 block is stored as validated shadow evidence, separate from the served persona
 * and v1's pick; nothing here can change what is served. In-memory MongoDB; logger and AI engine mocked (nothing is
 * written to backend/logs); evidence directories are temporary.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

const mockPredict = jest.fn()
const mockScore = jest.fn()
jest.mock('../services/aiEngineService', () => ({
  predictHoneypotSession: (...a) => mockPredict(...a),
  getDeceptionScore: (...a) => mockScore(...a),
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
  getAlertThreshold: jest.fn().mockResolvedValue(0.9),
  getDeceptionStats: jest.fn().mockResolvedValue({ v2Mode: 'shadow' }),
  getSessionMlStatus: jest.fn().mockResolvedValue(null),
}))
jest.mock('../services/aiService', () => ({ storePrediction: jest.fn().mockResolvedValue({}) }))
jest.mock('../services/campaignService', () => ({ clusterSession: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({
  emitHoneypotEvent: jest.fn(),
  emitNewThreat: jest.fn(),
  emitThreatUpdated: jest.fn(),
  emitNewAlert: jest.fn(),
  emitIPBlocked: jest.fn(),
}))
jest.mock('../services/containmentService', () => ({ executeAutoBlock: jest.fn().mockResolvedValue({}) }))
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const fs = require('fs')
const os = require('os')
const path = require('path')
const HoneypotSession = require('../models/HoneypotSession')
const SystemSetting = require('../models/SystemSetting')
const honeypotService = require('../services/honeypotService')
const collector = require('../../honeypot/collectors/session_collector')
const { shadowPolicyRecord, SCHEMA_VERSION } = require('../utils/shadowPolicy')
const { getCapabilities, LABELS, latestRank6Status, personaPolicyV2Items } = require('../services/capabilityService')

const V2 = (extra = {}) => ({
  mode: 'shadow',
  learned: true,
  policyVersion: 'persona-ducb-v2',
  recommendation: 'debian_11',
  status: 'OK',
  realEpisodes: 3,
  arms: { debian_11: { index: 0.7 } },
  ...extra,
})

describe('shadowPolicyRecord', () => {
  test('a servable pick is stored with its version, mode and status; nothing else', () => {
    const r = shadowPolicyRecord({ ...V2(), sourceIP: '203.0.113.5', commands: ['id'] })
    expect(r).toEqual({
      schemaVersion: SCHEMA_VERSION,
      version: 'persona-ducb-v2',
      mode: 'shadow',
      learned: true,
      recommendation: 'debian_11',
      status: 'OK',
      errorCode: null,
    })
  })

  test.each(['windows_srv', 'alpine_3', '', null, 42, { p: 1 }])(
    'unsupported or malformed pick %p is stored as INVALID_RECOMMENDATION with no persona',
    (bad) => {
      const r = shadowPolicyRecord(V2({ recommendation: bad }))
      expect(r).toMatchObject({ recommendation: null, status: 'INVALID_RECOMMENDATION' })
    }
  )

  test('a v2 failure is evidence (ERROR with the exception type), not a missing record', () => {
    expect(shadowPolicyRecord({ mode: 'shadow', error: 'TimeoutError', status: 'ERROR' })).toMatchObject({
      status: 'ERROR',
      errorCode: 'TimeoutError',
      recommendation: null,
    })
    expect(shadowPolicyRecord({ mode: 'shadow', error: '<script>' })).toMatchObject({ errorCode: 'UNKNOWN_ERROR' })
  })

  test('no block (v2 off) stores nothing', () => {
    for (const v of [undefined, null, 'x', [1]]) expect(shadowPolicyRecord(v)).toBeNull()
  })
})

describe('closure: shadow evidence never changes the served persona or v1 fields (in-memory MongoDB)', () => {
  let mongoServer
  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create()
    await mongoose.connect(mongoServer.getUri())
  }, 60000)
  afterAll(async () => {
    await mongoose.disconnect()
    if (mongoServer) await mongoServer.stop()
  })
  beforeEach(async () => {
    jest.clearAllMocks()
    for (const c of ['honeypotsessions', 'threatlogs', 'alerts', 'systemsettings'])
      await mongoose.connection.db.collection(c).deleteMany({})
    await SystemSetting.create({ key: 'deceptionActiveProfile', value: 'centos_7' })
    mockPredict.mockResolvedValue({ success: true, result: { predictedClass: 'BENIGN', threatScore: 0.4 } })
  })

  const close = async (id, policyV2) => {
    mockScore.mockResolvedValue({
      success: true,
      result: { deceptionScore: 42, nextProfile: 'ubuntu_22', learnerStats: { policy: 'q_learning' }, policyV2 },
    })
    const s = await collector.onSessionOpened({ sessionId: id, sourceIP: '198.51.100.40' })
    await honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 5 } })
    return HoneypotSession.findById(s._id).lean()
  }

  test.each([
    ['valid shadow pick', V2(), { status: 'OK', recommendation: 'debian_11' }],
    [
      'unsupported shadow pick',
      V2({ recommendation: 'windows_srv' }),
      { status: 'INVALID_RECOMMENDATION', recommendation: null },
    ],
    [
      'v2 failure',
      { mode: 'shadow', error: 'RuntimeError', status: 'ERROR' },
      { status: 'ERROR', errorCode: 'RuntimeError' },
    ],
  ])('%s', async (_name, v2, expected) => {
    const s = await close(`r6-${expected.status}`, v2)
    expect(s.shadowPolicy).toMatchObject({ schemaVersion: SCHEMA_VERSION, ...expected })
    // production fields are v1's, whatever v2 said
    expect(s.recommendedProfile).toBe('ubuntu_22')
    expect(s.deceptionPolicy).toBe('q_learning')
    expect(s.qDeceptionScore).toBe(42)
    expect(s.servedProfile).toBe('centos_7')
  })

  test('v2 off: no shadow record, v1 unaffected', async () => {
    const s = await close('r6-off', undefined)
    expect(s.shadowPolicy).toBeNull()
    expect(s.recommendedProfile).toBe('ubuntu_22')
  })
})

describe('Capability Status for persona policy v2', () => {
  const byId = (items) => Object.fromEntries(items.map((i) => [i.id, i]))
  const GATES = {
    '1_shadow_isolation': { status: 'PASS' },
    '2_persona_compatibility': { status: 'PASS' },
    '3_invalid_action_handling': { status: 'PASS' },
    '4_failure_isolation': { status: 'PASS' },
    '5_evidence_schema_and_provenance': { status: 'PASS' },
    '6_reproducible_evaluation': { status: 'PASS' },
    '7_adequate_session_evidence': { status: 'INSUFFICIENT_DATA' },
    '8_independent_evidence': { status: 'INSUFFICIENT_DATA' },
    '9_decision_stability': { status: 'FAIL' },
    '10_documented_acceptance_criteria': { status: 'NOT_MET' },
  }

  test('verified shadow pipeline, NOT READY policy', () => {
    const c = byId(
      personaPolicyV2Items('shadow', {
        overall: 'NOT_READY',
        shadow_engineering: 'PASS',
        gates: GATES,
        evidence: 'audit/x/',
      })
    )
    expect(c.persona_policy_v2_shadow.label).toBe('implemented_and_verified')
    expect(c.persona_policy_v2_shadow.summary).toMatch(/not that v2 is better/)
    expect(c.persona_policy_v2.label).toBe('shadow_only')
    expect(c.persona_policy_v2.summary).toMatch(/Readiness: NOT READY/)
    expect(c.persona_policy_v2.summary).toMatch(/never activated automatically/)
    expect(c.persona_policy_v2.facts.evidenceGates).toEqual({
      sessionEvidence: 'INSUFFICIENT_DATA',
      independentEvidence: 'INSUFFICIENT_DATA',
      decisionStability: 'FAIL',
      acceptanceCriteria: 'NOT_MET',
    })
  })

  test('missing or failed evidence is never shown as verified or ready', () => {
    const none = byId(personaPolicyV2Items('shadow', null))
    expect(none.persona_policy_v2_shadow.label).toBe('implemented_not_enabled')
    expect(none.persona_policy_v2.facts.readiness).toBe('NOT_VERIFIED')
    const failed = byId(personaPolicyV2Items('shadow', { overall: 'NOT_READY', shadow_engineering: 'FAIL', gates: {} }))
    expect(failed.persona_policy_v2_shadow.label).toBe('blocked')
  })

  const ALL_PASS = Object.fromEntries(Object.keys(GATES).map((g) => [g, { status: 'PASS' }]))

  test('even a READY evidence file only says READY; the label stays shadow_only (no promotion)', () => {
    const c = byId(personaPolicyV2Items('shadow', { overall: 'READY', shadow_engineering: 'PASS', gates: ALL_PASS }))
    expect(c.persona_policy_v2.label).toBe('shadow_only')
    expect(c.persona_policy_v2.summary).toMatch(/owner activation still required/)
    expect(c.persona_policy_v2.facts.activation).toMatchObject({ allowed: false, reason: 'NOT_REQUESTED' })
    expect(c.persona_policy_v2.facts.productionPolicy).toBe('v1_q_learning')
  })

  // Rank 6 corrections: fail-closed activation and provenance
  test('a READY overall with any non-PASS mandatory gate, or from an older run, is not READY', () => {
    const inconsistent = byId(
      personaPolicyV2Items('shadow', { overall: 'READY', shadow_engineering: 'PASS', gates: GATES })
    )
    expect(inconsistent.persona_policy_v2.facts.readiness).toBe('NOT_READY')
    const older = byId(
      personaPolicyV2Items('shadow', { overall: 'READY', shadow_engineering: 'PASS', gates: ALL_PASS, newest: false })
    )
    expect(older.persona_policy_v2.facts.readiness).toBe('NOT_READY')
  })

  test('active mode with NOT_READY evidence is shown as blocked, v1 in production, label shadow_only', () => {
    const r6 = { overall: 'NOT_READY', shadow_engineering: 'PASS', gates: GATES }
    for (const engine of [
      null,
      { requested: true, allowed: false, readiness: 'NOT_READY', reason: 'READINESS_NOT_READY' },
    ]) {
      const c = byId(personaPolicyV2Items('active', r6, engine)).persona_policy_v2
      expect(c.label).toBe('shadow_only')
      expect(c.facts.productionPolicy).toBe('v1_q_learning')
      expect(c.facts.activation).toMatchObject({ requested: true, allowed: false, reason: 'READINESS_NOT_READY' })
      expect(c.summary).toMatch(/blocked \(READINESS_NOT_READY\); v1 serves/)
      expect(c.facts.mandatoryGates['9_decision_stability']).toBe('FAIL')
    }
  })

  test('without the engine, even READY evidence never claims v2 is serving', () => {
    const c = byId(personaPolicyV2Items('active', { overall: 'READY', shadow_engineering: 'PASS', gates: ALL_PASS }))
    expect(c.persona_policy_v2.facts.activation).toMatchObject({ allowed: false, reason: 'ENGINE_UNREACHABLE' })
    expect(c.persona_policy_v2.label).toBe('shadow_only')
  })

  test('session provenance is reported as labelled vs verified; external count is never inflated', () => {
    const prov = {
      total_sessions_evaluated: 19,
      labelled_operator_in_replay: 19,
      with_recorded_and_verified_provenance: 0,
      with_untracked_or_unverifiable_provenance: 19,
      independently_verified_external: 0,
    }
    const c = byId(
      personaPolicyV2Items('shadow', {
        overall: 'NOT_READY',
        shadow_engineering: 'PASS',
        gates: GATES,
        session_provenance: prov,
      })
    ).persona_policy_v2
    expect(c.summary).toMatch(
      /labelled operator 19 \(inferred from source address\), verified provenance 0, untracked 19/
    )
    expect(c.facts.independentExternalSessions).toBe(0)
    expect(byId(personaPolicyV2Items('shadow', null)).persona_policy_v2.facts.independentExternalSessions).toBe(0)
  })

  test('the real newest evidence on this machine is NOT READY (read-only)', () => {
    const r6 = latestRank6Status()
    if (!r6) return // no evidence checked out here: covered by the missing-evidence test
    const c = byId(personaPolicyV2Items('active', r6)).persona_policy_v2
    expect(c.facts.readiness).toBe('NOT_READY')
    expect(c.facts.activation.allowed).toBe(false)
  })

  test('latestRank6Status reads the newest run with a readiness file; nothing readable -> null', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rank6-'))
    fs.mkdirSync(path.join(dir, 'run_20261114T100000Z'))
    fs.writeFileSync(
      path.join(dir, 'run_20261114T100000Z', 'readiness_status.json'),
      JSON.stringify({ overall: 'NOT_READY', gates: GATES })
    )
    fs.mkdirSync(path.join(dir, 'run_20261114T110000Z')) // no file
    expect(latestRank6Status(dir).evidence).toBe('audit/rank6_persona_policy_v2/run_20261114T100000Z/')
    expect(latestRank6Status(path.join(os.tmpdir(), 'no-such-rank6'))).toBeNull()
  })

  test('the full report keeps every earlier entry and adds the shadow entry', async () => {
    const ids = (await getCapabilities()).items.map((i) => i.id)
    for (const id of [
      'ml_evaluation_tooling',
      'ml_generalization',
      'pcap_replay',
      'live_capture',
      'firewall_adapters',
      'host_firewall',
      'mock_containment',
      'qlearning_evidence',
      'qlearning_effectiveness',
      'session_ml_pipeline',
      'session_ml',
      'session_ml_effectiveness',
      'persona_policy_v2_shadow',
      'persona_policy_v2',
      'cowrie_denylist',
    ])
      expect(ids).toContain(id)
    for (const i of (await getCapabilities()).items) expect(Object.keys(LABELS)).toContain(i.label)
  })
})
