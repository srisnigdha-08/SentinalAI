'use strict'
/**
 * Capability Status for Q-learning (docs/QLEARNING_EVIDENCE.md): evidence management, policy effectiveness and
 * persona policy v2 are three separate entries. The effectiveness facts must match the committed read-only report,
 * and nothing the engine reports can upgrade effectiveness or v2. No engine, database or network is used.
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../services/aiEngineService', () => ({ getDeceptionStats: jest.fn() }))

const fs = require('fs')
const path = require('path')
const aiEngineService = require('../services/aiEngineService')
const { getCapabilities, LABELS } = require('../services/capabilityService')
const { classifySession, EVIDENCE_SOURCES } = require('../utils/evidenceSource')

const ROOT = path.join(__dirname, '..', '..')
const byId = async () => Object.fromEntries((await getCapabilities()).items.map((i) => [i.id, i]))

describe('Q-learning capability entries', () => {
  test('evidence management is verified; effectiveness is experimental with insufficient evidence; v2 stays shadow', async () => {
    aiEngineService.getDeceptionStats.mockResolvedValue({ v2Mode: 'shadow', provenance: null })
    const c = await byId()
    expect(c.qlearning_evidence.label).toBe('implemented_and_verified')
    expect(c.qlearning_evidence.summary).toMatch(/says nothing about whether the policy works/)
    expect(c.qlearning_effectiveness.label).toBe('experimental')
    expect(c.qlearning_effectiveness.summary).toMatch(/^INSUFFICIENT INDEPENDENT EVIDENCE/)
    expect(c.persona_policy_v2.label).toBe('shadow_only')
    expect(c.persona_policy_v2.summary).toMatch(/NOT READY/)
    for (const id of ['qlearning_evidence', 'qlearning_effectiveness', 'persona_policy_v2'])
      expect(Object.keys(LABELS)).toContain(c[id].label)
  })

  test('effectiveness facts are exactly the committed read-only report', async () => {
    aiEngineService.getDeceptionStats.mockResolvedValue(null)
    const { qlearning_effectiveness: e } = await byId()
    const report = JSON.parse(fs.readFileSync(path.join(ROOT, e.facts.report), 'utf8'))
    expect(report.readOnly).toBe(true)
    expect(e.facts.totalEpisodes).toBe(report.episodes.total)
    expect(e.facts.syntheticSeedEpisodes).toBe(report.episodes.syntheticSeed)
    expect(e.facts.sessionDrivenUpdates).toBe(report.episodes.sessionDriven)
    expect(e.facts.independentExternalSessions).toBe(report.episodes.realIndependent)
    expect(e.facts.decisionsChangedByRealData).toBe(
      `${report.decisionsChangedByRealData} of ${report.decisionsEvaluated}`
    )
    expect(e.facts.personasWithoutRealSessions).toEqual(report.personasWithoutRealEvidence)
    expect(report.episodes.untracked).toBe(report.episodes.sessionDriven) // their source is not in the table
  })

  test('evidence files named on the dashboard exist', async () => {
    aiEngineService.getDeceptionStats.mockResolvedValue(null)
    const { qlearning_evidence: q } = await byId()
    for (const f of [...q.facts.evidence, q.facts.report]) expect(fs.existsSync(path.join(ROOT, f))).toBe(true)
  })

  test('live engine counts are shown but never upgrade effectiveness or v2', async () => {
    aiEngineService.getDeceptionStats.mockResolvedValue({
      v2Mode: 'shadow',
      provenance: {
        seedEpisodes: 12087,
        sessionEpisodes: 500,
        untrackedSessionEpisodes: 0,
        bySource: { operator: 0, external: 500, simulated: 0, unknown: 0 },
        duplicatesRejected: 7,
      },
    })
    const c = await byId()
    expect(c.qlearning_evidence.summary).toMatch(/external 500/)
    expect(c.qlearning_evidence.summary).toMatch(/duplicates rejected 7/)
    expect(c.qlearning_effectiveness.label).toBe('experimental')
    expect(c.persona_policy_v2.label).toBe('shadow_only')
  })

  test('an unreachable engine is reported as such; v2 is not promoted by an unknown mode', async () => {
    aiEngineService.getDeceptionStats.mockRejectedValue(new Error('ECONNREFUSED'))
    const c = await byId()
    expect(c.qlearning_evidence.summary).toMatch(/unavailable \(AI engine not reachable\)/)
    expect(c.persona_policy_v2.label).toBe('shadow_only')
    expect(c.persona_policy_v2.summary).toMatch(/Mode: unknown/)
  })
})

describe('backend session labels (the source the learner receives)', () => {
  const env = { SENTINEL_OPERATOR_SOURCES: '192.0.2.0/24' }
  test('labels are only the four known sources; nothing is labelled external without authorised collection', () => {
    expect(EVIDENCE_SOURCES).toEqual(['operator', 'external', 'simulated', 'unknown'])
    expect(classifySession({ sessionId: 'abc', sourceIP: '198.51.100.9' }, env)).toBe('unknown')
    expect(classifySession({ sessionId: 'abc', sourceIP: '192.0.2.5' }, env)).toBe('operator')
    expect(classifySession({ sessionId: 'demo-1', sourceIP: '198.51.100.9' }, env)).toBe('simulated')
    expect(classifySession({ sessionId: 'abc', sourceIP: 'not-an-ip' }, env)).toBe('unknown')
    expect(
      classifySession(
        { sessionId: 'abc', sourceIP: '198.51.100.9' },
        { ...env, HONEYPOT_EXTERNAL_COLLECTION: 'authorized' } // no published notice: still not external
      )
    ).toBe('unknown')
    expect(
      classifySession(
        { sessionId: 'abc', sourceIP: '192.0.2.5' },
        { ...env, HONEYPOT_EXTERNAL_COLLECTION: 'authorized', HONEYPOT_COLLECTION_NOTICE: 'notice-1' }
      )
    ).toBe('operator') // the operator's own traffic is never external
  })
})
