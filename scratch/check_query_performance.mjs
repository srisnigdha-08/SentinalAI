import mongoose from '../backend/node_modules/mongoose/index.js';

async function runExplainTests() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  console.log('=== CHECK 10: QUERY PERFORMANCE (explain("executionStats")) ===\n');

  const testQueries = [
    {
      name: '1. Threat List: Filter by severity & status (severity=HIGH, status=DETECTED)',
      coll: 'threatlogs',
      fn: coll => coll.find({ severity: 'HIGH', status: 'DETECTED' }).sort({ createdAt: -1 }).explain('executionStats')
    },
    {
      name: '2. Threat List: Filter by sourceIP (sourceIP=172.18.0.1)',
      coll: 'threatlogs',
      fn: coll => coll.find({ sourceIP: '172.18.0.1' }).sort({ createdAt: -1 }).explain('executionStats')
    },
    {
      name: '3. Dashboard Aggregation: Severity breakdown ($group by severity)',
      coll: 'threatlogs',
      isDbCommand: true,
      cmd: {
        aggregate: 'threatlogs',
        pipeline: [{ $group: { _id: '$severity', count: { $sum: 1 } } }],
        cursor: {},
        explain: true
      }
    },
    {
      name: '4. Dashboard Aggregation: 24h Trend ($match createdAt, $group by Asia/Kolkata date)',
      coll: 'threatlogs',
      isDbCommand: true,
      cmd: {
        aggregate: 'threatlogs',
        pipeline: [
          { $match: { createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } },
          { $group: { _id: { $dateToString: { format: '%Y-%m-%d %H:00', date: '$createdAt', timezone: 'Asia/Kolkata' } }, count: { $sum: 1 } } },
          { $sort: { _id: 1 } }
        ],
        cursor: {},
        explain: true
      }
    },
    {
      name: '5. Honeypot Session List: Filter by node & status, sort by createdAt desc',
      coll: 'honeypotsessions',
      fn: coll => coll.find({ honeypotNode: 'SSH-COWRIE-01', status: 'active' }).sort({ createdAt: -1 }).limit(20).explain('executionStats')
    },
    {
      name: '6. Alerts: Unread count ({ isRead: false })',
      coll: 'alerts',
      fn: coll => coll.find({ isRead: false }).explain('executionStats')
    },
    {
      name: '7. protect(): AuthSession by ID (Session token lookup)',
      coll: 'authsessions',
      fn: coll => coll.find({ _id: 'ea23a31a-cb25-4be0-a879-8bfc0e81af99' }).explain('executionStats')
    },
    {
      name: '8. protect(): User by ID (User profile re-read)',
      coll: 'users',
      fn: coll => coll.find({ _id: new mongoose.Types.ObjectId('6a9fc315dd3280a95f99f529') }).explain('executionStats')
    },
    {
      name: '9. Audit Log Pagination: Action filter + sort createdAt desc',
      coll: 'auditlogs',
      fn: coll => coll.find({ action: 'LOGIN_SUCCESS' }).sort({ createdAt: -1 }).limit(50).explain('executionStats')
    },
    {
      name: '10. Containment: BlockedIP check by IP',
      coll: 'blockedips',
      fn: coll => coll.find({ ip: '198.51.100.88' }).explain('executionStats')
    }
  ];

  for (const q of testQueries) {
    const coll = db.collection(q.coll);
    console.log(`--- ${q.name} ---`);
    if (q.isDbCommand) {
      const result = await db.command(q.cmd);
      const cursorStage = result.stages ? result.stages[0]?.$cursor : null;
      if (cursorStage) {
        const execStats = cursorStage.executionStats || {};
        const inputStage = execStats.executionStages?.inputStage || execStats.executionStages || {};
        console.log(`  Plan: ${execStats.executionStages?.stage} | Index: ${inputStage.indexName || 'NONE (COLLSCAN)'}`);
        console.log(`  docsExamined: ${execStats.totalDocsExamined} | nReturned: ${execStats.nReturned} | executionTimeMillis: ${execStats.executionTimeMillis}ms`);
      } else {
        console.log('  Aggregation executed. Stages:', result.stages?.map(s => Object.keys(s)[0]));
      }
    } else {
      const result = await q.fn(coll);
      const stats = result.executionStats || {};
      const winningPlan = result.queryPlanner?.winningPlan || {};
      function findPlanDetails(plan) {
        let current = plan;
        let indexName = 'NONE (COLLSCAN)';
        let stage = current.stage;
        while (current) {
          if (current.indexName) {
            indexName = current.indexName;
            break;
          }
          if (current.inputStage) {
            current = current.inputStage;
            if (current.indexName) {
              indexName = current.indexName;
              stage = plan.stage + ' -> ' + current.stage;
              break;
            }
          } else {
            break;
          }
        }
        return { stage, indexName };
      }
      const details = findPlanDetails(winningPlan);
      console.log(`  Plan: ${details.stage} | Index: ${details.indexName}`);
      console.log(`  docsExamined: ${stats.totalDocsExamined} | nReturned: ${stats.nReturned} | executionTimeMillis: ${stats.executionTimeMillis}ms`);
    }
    console.log('');
  }

  await mongoose.disconnect();
}

runExplainTests().catch(console.error);
