'use strict'
/**
 * Rank 5 Capability Status (docs/ML_GENERALISATION.md): evaluation tooling and generalisation evidence are separate
 * entries, read from the newest non-smoke rank5_status.json. Nothing here can make generalisation look verified.
 * Pure: temporary directories only; the logger and AI engine are mocked (nothing is written to backend/logs).
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../services/aiEngineService', () => ({
  getDeceptionStats: jest.fn().mockResolvedValue(null),
  getSessionMlStatus: jest.fn().mockResolvedValue(null),
}))

const fs = require('fs')
const os = require('os')
const path = require('path')
const { getCapabilities, LABELS, latestRank5Status, mlGeneralisationItems } = require('../services/capabilityService')

const STATUS = {
  evaluation_tooling: 'READY',
  model_integrity: 'READY',
  dataset_provenance: 'READY',
  random_split_reproduced: 'READY',
  chronological_evaluation: 'LIMITED',
  leakage_checks: 'LIMITED',
  drift_diagnostics: 'READY',
  independent_generalisation: 'NOT_VERIFIED',
  generalisation_finding: 'POOR_ON_LATER_DIFFERENT_NETWORK',
}
const HEADLINE = {
  e1_accuracy: 0.989682,
  e1_f1_macro: 0.87384,
  e3_accuracy: 0.45,
  e3_balanced_accuracy: 0.2,
  e3_f1_macro: 0.1,
  e3_attack_recall_alert_line: 0.05,
  e3_benign_fpr_alert_line: 0.01,
}

function tmpRuns(runs) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rank5-'))
  for (const [name, body] of Object.entries(runs)) {
    fs.mkdirSync(path.join(dir, name))
    if (body !== undefined)
      fs.writeFileSync(
        path.join(dir, name, 'rank5_status.json'),
        typeof body === 'string' ? body : JSON.stringify(body)
      )
  }
  return dir
}

describe('latestRank5Status', () => {
  test('picks the newest real run and ignores smoke runs, empty and unreadable ones', () => {
    const dir = tmpRuns({
      run_20261114T100000Z: { status: { ...STATUS, evaluation_tooling: 'FAILED' } },
      run_20261114T110000Z: { status: STATUS, headline: HEADLINE },
      run_20261114T120000Z_smoke: { status: STATUS, smoke_run_not_evidence: true },
      run_20261114T130000Z: undefined, // no status file
      run_20261114T140000Z: '{not json',
    })
    const r = latestRank5Status(dir)
    // the unreadable newest run makes the reader give up rather than guess from an older one
    expect(r).toBeNull()
    fs.rmSync(path.join(dir, 'run_20261114T140000Z'), { recursive: true })
    const ok = latestRank5Status(dir)
    expect(ok.status.evaluation_tooling).toBe('READY')
    expect(ok.evidence).toBe('audit/rank5_network_flow_generalisation/run_20261114T110000Z/')
  })

  test('no directory -> null', () => {
    expect(latestRank5Status(path.join(os.tmpdir(), 'does-not-exist-rank5'))).toBeNull()
  })
})

describe('mlGeneralisationItems', () => {
  const byId = (items) => Object.fromEntries(items.map((i) => [i.id, i]))

  test('ready tooling is verified; generalisation stays experimental and NOT_VERIFIED', () => {
    const c = byId(mlGeneralisationItems({ status: STATUS, headline: HEADLINE, evidence: 'audit/x/' }))
    expect(c.ml_evaluation_tooling.label).toBe('implemented_and_verified')
    expect(c.ml_evaluation_tooling.summary).toMatch(/not evidence that the model generalises/)
    expect(c.ml_generalization.label).toBe('experimental')
    expect(c.ml_generalization.facts).toMatchObject({
      deployedModel: 'xgb_cicids_v1',
      promoted: false,
      independentGeneralisation: 'NOT_VERIFIED',
      chronologicalEvaluation: 'LIMITED',
      finding: 'POOR_ON_LATER_DIFFERENT_NETWORK',
    })
    expect(c.ml_generalization.summary).toMatch(/Random split \(in-distribution, not independent\): accuracy 99\.0 %/)
    expect(c.ml_generalization.summary).toMatch(/macro F1 10\.0 %/)
  })

  test('even a status file claiming VERIFIED never changes the generalisation label', () => {
    const c = byId(
      mlGeneralisationItems({ status: { ...STATUS, independent_generalisation: 'VERIFIED' }, headline: HEADLINE })
    )
    expect(c.ml_generalization.label).toBe('experimental')
  })

  test('failed or missing evidence is never shown as ready', () => {
    const failed = byId(mlGeneralisationItems({ status: { ...STATUS, model_integrity: 'FAILED' }, headline: {} }))
    expect(failed.ml_evaluation_tooling.label).toBe('blocked')
    const none = byId(mlGeneralisationItems(null))
    expect(none.ml_evaluation_tooling.label).toBe('implemented_not_enabled')
    expect(none.ml_evaluation_tooling.summary).toMatch(/No Rank 5 evaluation run is present/)
    expect(none.ml_generalization.facts.independentGeneralisation).toBe('NOT_VERIFIED')
    expect(none.ml_generalization.facts.driftDiagnostics).toBe('INSUFFICIENT_DATA')
  })
})

describe('getCapabilities', () => {
  test('both entries are present with known labels, and earlier entries are kept', async () => {
    const r = await getCapabilities()
    const ids = r.items.map((i) => i.id)
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
      'persona_policy_v2',
    ])
      expect(ids).toContain(id)
    for (const i of r.items) expect(Object.keys(LABELS)).toContain(i.label)
    expect(r.items.find((i) => i.id === 'ml_generalization').label).toBe('experimental')
  })
})
