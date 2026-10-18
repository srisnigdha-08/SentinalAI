import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');

async function testAlertCountExplain() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  console.log('=== BEFORE: Alert countDocuments (no sort) explain ===');
  const exp = await db.collection('alerts')
    .find({ targetRoles: 'analyst', isRead: false })
    .explain('executionStats');

  console.log('Winning Plan Stage:', exp.queryPlanner.winningPlan.stage);
  console.log('Input Stage:', exp.queryPlanner.winningPlan.inputStage?.stage || 'None');
  console.log('Index Name:', exp.queryPlanner.winningPlan.inputStage?.indexName || 'None');
  console.log('Total Docs Examined:', exp.executionStats.totalDocsExamined);
  console.log('Total Keys Examined:', exp.executionStats.totalKeysExamined);
  console.log('Docs Returned:', exp.executionStats.nReturned);

  await mongoose.disconnect();
}

testAlertCountExplain().catch(console.error);
