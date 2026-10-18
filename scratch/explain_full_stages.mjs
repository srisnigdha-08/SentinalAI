import mongoose from '../backend/node_modules/mongoose/index.js';

await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
const db = mongoose.connection.db;

function getStageChain(plan) {
  const stages = [];
  let curr = plan;
  let indexName = null;
  while (curr) {
    stages.push(curr.stage);
    if (curr.indexName) indexName = curr.indexName;
    if (curr.inputStage) {
      curr = curr.inputStage;
    } else if (curr.inputStages && curr.inputStages[0]) {
      curr = curr.inputStages[0];
    } else {
      break;
    }
  }
  return { chain: stages.join(' -> '), indexName };
}

console.log('=== CHECK 10: FULL EXPLAIN STAGE CHAINS ===\n');

// 1. Threat List Filter
const exp1 = await db.collection('threatlogs').find({ severity: 'HIGH', status: 'MONITORING' }).sort({ createdAt: -1 }).explain('executionStats');
const s1 = exp1.executionStats;
const p1 = getStageChain(exp1.queryPlanner.winningPlan);
console.log('Query 1 (Threat List):');
console.log(`  Stage Chain: ${p1.chain}`);
console.log(`  Index Used:  ${p1.indexName || exp1.queryPlanner.winningPlan.inputStage?.indexName || 'None'}`);
console.log(`  totalKeysExamined: ${s1.totalKeysExamined}, totalDocsExamined: ${s1.totalDocsExamined}, nReturned: ${s1.nReturned}, time: ${s1.executionTimeMillis}ms`);

// 2. Threat by Source IP
const exp2 = await db.collection('threatlogs').find({ sourceIP: '172.18.0.1' }).sort({ createdAt: -1 }).explain('executionStats');
const s2 = exp2.executionStats;
const p2 = getStageChain(exp2.queryPlanner.winningPlan);
console.log('\nQuery 2 (Threat by sourceIP):');
console.log(`  Stage Chain: ${p2.chain}`);
console.log(`  Index Used:  ${p2.indexName}`);
console.log(`  totalKeysExamined: ${s2.totalKeysExamined}, totalDocsExamined: ${s2.totalDocsExamined}, nReturned: ${s2.nReturned}, time: ${s2.executionTimeMillis}ms`);

// 3. Dashboard Aggregation (Severity Group)
const exp3 = await db.collection('threatlogs').aggregate([
  { $group: { _id: '$severity', count: { $sum: 1 } } }
]).explain('executionStats');
const s3 = exp3.stages?.[0]?.$cursor?.executionStats || exp3.executionStats;
const p3 = getStageChain(exp3.stages?.[0]?.$cursor?.queryPlanner?.winningPlan || exp3.queryPlanner?.winningPlan);
console.log('\nQuery 3 (Dashboard Severity Group):');
console.log(`  Stage Chain: ${p3.chain}`);
console.log(`  Index Used:  ${p3.indexName || 'None'}`);
console.log(`  totalKeysExamined: ${s3?.totalKeysExamined ?? 0}, totalDocsExamined: ${s3?.totalDocsExamined}, nReturned: ${s3?.nReturned}, time: ${s3?.executionTimeMillis}ms`);

// 4. Dashboard Trend with Window containing documents (e.g. since 2026-09-01)
const exp4 = await db.collection('threatlogs').aggregate([
  { $match: { createdAt: { $gte: new Date('2026-09-01') } } },
  { $group: { _id: '$attackType', count: { $sum: 1 } } }
]).explain('executionStats');
const s4 = exp4.stages?.[0]?.$cursor?.executionStats || exp4.executionStats;
const p4 = getStageChain(exp4.stages?.[0]?.$cursor?.queryPlanner?.winningPlan || exp4.queryPlanner?.winningPlan);
console.log('\nQuery 4 (Dashboard Trend with documents since 2026-09-01):');
console.log(`  Stage Chain: ${p4.chain}`);
console.log(`  Index Used:  ${p4.indexName}`);
console.log(`  totalKeysExamined: ${s4?.totalKeysExamined}, totalDocsExamined: ${s4?.totalDocsExamined}, nReturned: ${s4?.nReturned}, time: ${s4?.executionTimeMillis}ms`);

// 5. Honeypot Session Filter
const exp5 = await db.collection('honeypotsessions').find({ honeypotNode: 'SSH-COWRIE-01', status: 'closed' }).sort({ createdAt: -1 }).explain('executionStats');
const s5 = exp5.executionStats;
const p5 = getStageChain(exp5.queryPlanner.winningPlan);
console.log('\nQuery 5 (Honeypot Session Filter, status=closed):');
console.log(`  Stage Chain: ${p5.chain}`);
console.log(`  Index Used:  ${p5.indexName}`);
console.log(`  totalKeysExamined: ${s5.totalKeysExamined}, totalDocsExamined: ${s5.totalDocsExamined}, nReturned: ${s5.nReturned}, time: ${s5.executionTimeMillis}ms`);

// 6. Alert Unread Count (real query: targetRoles + isRead: false)
const exp6 = await db.collection('alerts').find({ targetRoles: 'admin', isRead: false }).explain('executionStats');
const s6 = exp6.executionStats;
const p6 = getStageChain(exp6.queryPlanner.winningPlan);
console.log('\nQuery 6 (Alert Unread Count with targetRoles):');
console.log(`  Stage Chain: ${p6.chain}`);
console.log(`  Index Used:  ${p6.indexName || 'None'}`);
console.log(`  totalKeysExamined: ${s6.totalKeysExamined}, totalDocsExamined: ${s6.totalDocsExamined}, nReturned: ${s6.nReturned}, time: ${s6.executionTimeMillis}ms`);

// 7. Protect: AuthSession by ID
const sess = await db.collection('authsessions').findOne({});
const exp7 = await db.collection('authsessions').find({ _id: sess._id }).explain('executionStats');
const s7 = exp7.executionStats;
const p7 = getStageChain(exp7.queryPlanner.winningPlan);
console.log('\nQuery 7 (Protect AuthSession by ID):');
console.log(`  Stage Chain: ${p7.chain}`);
console.log(`  Index Used:  ${p7.indexName}`);
console.log(`  totalKeysExamined: ${s7.totalKeysExamined}, totalDocsExamined: ${s7.totalDocsExamined}, nReturned: ${s7.nReturned}, time: ${s7.executionTimeMillis}ms`);

// 8. Protect: User by ID
const u = await db.collection('users').findOne({});
const exp8 = await db.collection('users').find({ _id: u._id }).explain('executionStats');
const s8 = exp8.executionStats;
const p8 = getStageChain(exp8.queryPlanner.winningPlan);
console.log('\nQuery 8 (Protect User by ID):');
console.log(`  Stage Chain: ${p8.chain}`);
console.log(`  Index Used:  ${p8.indexName}`);
console.log(`  totalKeysExamined: ${s8.totalKeysExamined}, totalDocsExamined: ${s8.totalDocsExamined}, nReturned: ${s8.nReturned}, time: ${s8.executionTimeMillis}ms`);

// 9. Audit Log Pagination
const exp9 = await db.collection('auditlogs').find({ action: 'LOGIN_SUCCESS' }).sort({ createdAt: -1 }).limit(50).explain('executionStats');
const s9 = exp9.executionStats;
const p9 = getStageChain(exp9.queryPlanner.winningPlan);
console.log('\nQuery 9 (Audit Log Pagination):');
console.log(`  Stage Chain: ${p9.chain}`);
console.log(`  Index Used:  ${p9.indexName}`);
console.log(`  totalKeysExamined: ${s9.totalKeysExamined}, totalDocsExamined: ${s9.totalDocsExamined}, nReturned: ${s9.nReturned}, time: ${s9.executionTimeMillis}ms`);

// 10. BlockedIP check
const exp10 = await db.collection('blockedips').find({ ip: '198.51.100.88' }).explain('executionStats');
const s10 = exp10.executionStats;
const p10 = getStageChain(exp10.queryPlanner.winningPlan);
console.log('\nQuery 10 (BlockedIP check):');
console.log(`  Stage Chain: ${p10.chain}`);
console.log(`  Index Used:  ${p10.indexName}`);
console.log(`  totalKeysExamined: ${s10.totalKeysExamined}, totalDocsExamined: ${s10.totalDocsExamined}, nReturned: ${s10.nReturned}, time: ${s10.executionTimeMillis}ms`);

await mongoose.disconnect();
