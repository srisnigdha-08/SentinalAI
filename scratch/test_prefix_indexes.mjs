import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');

async function testPrefix() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  console.log('=== TESTING PREFIX CAPABILITY ===');

  // Test 1: ThreatLog severity query using hint severity_1_status_1
  const tExp = await db.collection('threatlogs').find({ severity: 'HIGH' }).hint('severity_1_status_1').explain('executionStats');
  console.log('1. ThreatLog { severity: "HIGH" } on severity_1_status_1:');
  console.log('   Stage:', tExp.queryPlanner.winningPlan.stage);
  console.log('   IndexName:', tExp.queryPlanner.winningPlan.inputStage?.indexName || tExp.queryPlanner.winningPlan.indexName);
  console.log('   KeysExamined:', tExp.executionStats.totalKeysExamined);

  // Test 2: Alert severity query using hint severity_1_isRead_1
  const aExp = await db.collection('alerts').find({ severity: 'CRITICAL' }).hint('severity_1_isRead_1').explain('executionStats');
  console.log('2. Alert { severity: "CRITICAL" } on severity_1_isRead_1:');
  console.log('   Stage:', aExp.queryPlanner.winningPlan.stage);
  console.log('   IndexName:', aExp.queryPlanner.winningPlan.inputStage?.indexName || aExp.queryPlanner.winningPlan.indexName);
  console.log('   KeysExamined:', aExp.executionStats.totalKeysExamined);

  // Test 3: AuditLog action query using hint action_1_createdAt_-1
  const auExp = await db.collection('auditlogs').find({ action: 'LOGIN_SUCCESS' }).hint('action_1_createdAt_-1').explain('executionStats');
  console.log('3. AuditLog { action: "LOGIN_SUCCESS" } on action_1_createdAt_-1:');
  console.log('   Stage:', auExp.queryPlanner.winningPlan.stage);
  console.log('   IndexName:', auExp.queryPlanner.winningPlan.inputStage?.indexName || auExp.queryPlanner.winningPlan.indexName);
  console.log('   KeysExamined:', auExp.executionStats.totalKeysExamined);

  await mongoose.disconnect();
}

testPrefix().catch(console.error);
