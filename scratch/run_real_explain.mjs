import mongoose from '../backend/node_modules/mongoose/index.js';

await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
const db = mongoose.connection.db;

console.log('=== REAL VALUES CHECK ===');
const sampleThreat = await db.collection('threatlogs').findOne({});
console.log('Threat sample:', { severity: sampleThreat?.severity, status: sampleThreat?.status, sourceIP: sampleThreat?.sourceIP });

const sampleAudit = await db.collection('auditlogs').findOne({ action: 'LOGIN_SUCCESS' });
console.log('Audit sample LOGIN_SUCCESS:', !!sampleAudit);

const sampleHP = await db.collection('honeypotsessions').findOne({});
console.log('Honeypot sample:', { honeypotNode: sampleHP?.honeypotNode, status: sampleHP?.status });

// 1. Threat List: Filter by severity & status (HIGH, MONITORING)
console.log('\n--- 1. Threat List (severity=HIGH, status=MONITORING, sort createdAt -1) ---');
const exp1 = await db.collection('threatlogs').find({ severity: 'HIGH', status: 'MONITORING' }).sort({ createdAt: -1 }).explain('executionStats');
const s1 = exp1.executionStats;
console.log(`Plan: ${exp1.queryPlanner.winningPlan.stage} | Index: ${JSON.stringify(exp1.queryPlanner.winningPlan.inputStage?.indexName || exp1.queryPlanner.winningPlan.indexName)}`);
console.log(`totalKeysExamined: ${s1.totalKeysExamined} | totalDocsExamined: ${s1.totalDocsExamined} | nReturned: ${s1.nReturned} | executionTimeMillis: ${s1.executionTimeMillis}ms`);

// 2. Threat by sourceIP
console.log('\n--- 2. Threat by sourceIP (172.18.0.1) ---');
const exp2 = await db.collection('threatlogs').find({ sourceIP: '172.18.0.1' }).sort({ createdAt: -1 }).explain('executionStats');
const s2 = exp2.executionStats;
console.log(`Plan: ${exp2.queryPlanner.winningPlan.stage} | Index: ${JSON.stringify(exp2.queryPlanner.winningPlan.inputStage?.indexName || exp2.queryPlanner.winningPlan.indexName)}`);
console.log(`totalKeysExamined: ${s2.totalKeysExamined} | totalDocsExamined: ${s2.totalDocsExamined} | nReturned: ${s2.nReturned} | executionTimeMillis: ${s2.executionTimeMillis}ms`);

// 3. Dashboard Aggregation: Severity breakdown
console.log('\n--- 3. Dashboard Aggregation (Severity $group) ---');
const exp3 = await db.collection('threatlogs').aggregate([
  { $group: { _id: '$severity', count: { $sum: 1 } } }
]).explain('executionStats');
const s3 = exp3.stages?.[0]?.$cursor?.executionStats || exp3.executionStats;
console.log(`Plan: ${JSON.stringify(exp3.stages?.[0]?.$cursor?.queryPlanner?.winningPlan?.stage || 'AGGREGATE')} | Index: ${JSON.stringify(exp3.stages?.[0]?.$cursor?.queryPlanner?.winningPlan?.inputStage?.indexName || 'NONE')}`);
console.log(`totalKeysExamined: ${s3?.totalKeysExamined ?? 0} | totalDocsExamined: ${s3?.totalDocsExamined} | nReturned: ${s3?.nReturned} | executionTimeMillis: ${s3?.executionTimeMillis}ms`);

// 4. Dashboard Aggregation: 24h Trend ($match createdAt, $group)
console.log('\n--- 4. Dashboard 24h Trend ($match createdAt, $group) ---');
const exp4 = await db.collection('threatlogs').aggregate([
  { $match: { createdAt: { $gte: new Date(Date.now() - 24 * 3600 * 1000) } } },
  { $group: { _id: '$attackType', count: { $sum: 1 } } }
]).explain('executionStats');
const s4 = exp4.stages?.[0]?.$cursor?.executionStats || exp4.executionStats;
console.log(`Plan: ${JSON.stringify(exp4.stages?.[0]?.$cursor?.queryPlanner?.winningPlan?.stage)} | Index: ${JSON.stringify(exp4.stages?.[0]?.$cursor?.queryPlanner?.winningPlan?.inputStage?.indexName)}`);
console.log(`totalKeysExamined: ${s4?.totalKeysExamined} | totalDocsExamined: ${s4?.totalDocsExamined} | nReturned: ${s4?.nReturned} | executionTimeMillis: ${s4?.executionTimeMillis}ms`);

// 5. Honeypot Session Filter (node='SSH-COWRIE-01', status='active', sort createdAt -1)
console.log('\n--- 5. Honeypot Session Filter (node=SSH-COWRIE-01, status=active, sort createdAt -1) ---');
const exp5 = await db.collection('honeypotsessions').find({ honeypotNode: 'SSH-COWRIE-01', status: 'active' }).sort({ createdAt: -1 }).explain('executionStats');
const s5 = exp5.executionStats;
console.log(`Plan: ${exp5.queryPlanner.winningPlan.stage} | Index: ${JSON.stringify(exp5.queryPlanner.winningPlan.inputStage?.indexName || exp5.queryPlanner.winningPlan.indexName)}`);
console.log(`totalKeysExamined: ${s5.totalKeysExamined} | totalDocsExamined: ${s5.totalDocsExamined} | nReturned: ${s5.nReturned} | executionTimeMillis: ${s5.executionTimeMillis}ms`);

// 6. Alerts: Unread count ({ isRead: false })
console.log('\n--- 6. Alerts: Unread count ({ isRead: false }) ---');
const exp6 = await db.collection('alerts').find({ isRead: false }).explain('executionStats');
const s6 = exp6.executionStats;
console.log(`Plan: ${exp6.queryPlanner.winningPlan.stage} | Index: ${JSON.stringify(exp6.queryPlanner.winningPlan.inputStage?.indexName || exp6.queryPlanner.winningPlan.indexName || 'NONE')}`);
console.log(`totalKeysExamined: ${s6.totalKeysExamined} | totalDocsExamined: ${s6.totalDocsExamined} | nReturned: ${s6.nReturned} | executionTimeMillis: ${s6.executionTimeMillis}ms`);

// 7. Protect: AuthSession by _id
const sessionDoc = await db.collection('authsessions').findOne({});
console.log('\n--- 7. Protect: AuthSession by ID ---');
const exp7 = await db.collection('authsessions').find({ _id: sessionDoc._id }).explain('executionStats');
const s7 = exp7.executionStats;
console.log(`Plan: ${exp7.queryPlanner.winningPlan.stage} | Index: ${JSON.stringify(exp7.queryPlanner.winningPlan.inputStage?.indexName || exp7.queryPlanner.winningPlan.indexName || '_id_')}`);
console.log(`totalKeysExamined: ${s7.totalKeysExamined} | totalDocsExamined: ${s7.totalDocsExamined} | nReturned: ${s7.nReturned} | executionTimeMillis: ${s7.executionTimeMillis}ms`);

// 8. Protect: User by _id
const userDoc = await db.collection('users').findOne({});
console.log('\n--- 8. Protect: User by ID ---');
const exp8 = await db.collection('users').find({ _id: userDoc._id }).explain('executionStats');
const s8 = exp8.executionStats;
console.log(`Plan: ${exp8.queryPlanner.winningPlan.stage} | Index: ${JSON.stringify(exp8.queryPlanner.winningPlan.inputStage?.indexName || exp8.queryPlanner.winningPlan.indexName || '_id_')}`);
console.log(`totalKeysExamined: ${s8.totalKeysExamined} | totalDocsExamined: ${s8.totalDocsExamined} | nReturned: ${s8.nReturned} | executionTimeMillis: ${s8.executionTimeMillis}ms`);

// 9. Audit Log Pagination (action='LOGIN_SUCCESS', sort createdAt -1)
console.log('\n--- 9. Audit Log Pagination (action=LOGIN_SUCCESS, sort createdAt -1) ---');
const exp9 = await db.collection('auditlogs').find({ action: 'LOGIN_SUCCESS' }).sort({ createdAt: -1 }).limit(50).explain('executionStats');
const s9 = exp9.executionStats;
console.log(`Plan: ${exp9.queryPlanner.winningPlan.stage} | Index: ${JSON.stringify(exp9.queryPlanner.winningPlan.inputStage?.inputStage?.indexName || exp9.queryPlanner.winningPlan.inputStage?.indexName || exp9.queryPlanner.winningPlan.indexName)}`);
console.log(`totalKeysExamined: ${s9.totalKeysExamined} | totalDocsExamined: ${s9.totalDocsExamined} | nReturned: ${s9.nReturned} | executionTimeMillis: ${s9.executionTimeMillis}ms`);

// 10. Containment: BlockedIP check
console.log('\n--- 10. BlockedIP check (ip=198.51.100.88) ---');
const exp10 = await db.collection('blockedips').find({ ip: '198.51.100.88' }).explain('executionStats');
const s10 = exp10.executionStats;
console.log(`Plan: ${exp10.queryPlanner.winningPlan.stage} | Index: ${JSON.stringify(exp10.queryPlanner.winningPlan.inputStage?.indexName || exp10.queryPlanner.winningPlan.indexName)}`);
console.log(`totalKeysExamined: ${s10.totalKeysExamined} | totalDocsExamined: ${s10.totalDocsExamined} | nReturned: ${s10.nReturned} | executionTimeMillis: ${s10.executionTimeMillis}ms`);

await mongoose.disconnect();
