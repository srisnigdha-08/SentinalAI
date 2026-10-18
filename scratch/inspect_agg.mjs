import mongoose from '../backend/node_modules/mongoose/index.js';

async function inspectAgg() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const res1 = await mongoose.connection.db.command({
    explain: {
      aggregate: 'threatlogs',
      pipeline: [{ $group: { _id: '$severity', count: { $sum: 1 } } }],
      cursor: {}
    },
    verbosity: 'executionStats'
  });
  console.log('--- Aggregation 1 (Severity Group) ---');
  console.log('Stages:', JSON.stringify(res1.stages || res1.queryPlanner, null, 2).substring(0, 800));
  if (res1.executionStats) {
    console.log('executionStats:', JSON.stringify(res1.executionStats, null, 2));
  }

  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const res2 = await mongoose.connection.db.command({
    explain: {
      aggregate: 'threatlogs',
      pipeline: [
        { $match: { createdAt: { $gte: since } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d %H:00', date: '$createdAt', timezone: 'Asia/Kolkata' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } }
      ],
      cursor: {}
    },
    verbosity: 'executionStats'
  });
  console.log('\n--- Aggregation 2 (24h Trend Match + Group) ---');
  console.log('Stages:', JSON.stringify(res2.stages || res2.queryPlanner, null, 2).substring(0, 800));
  if (res2.executionStats) {
    console.log('executionStats:', JSON.stringify(res2.executionStats, null, 2));
  }

  await mongoose.disconnect();
}
inspectAgg().catch(console.error);
