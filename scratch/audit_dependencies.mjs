import mongoose from '../backend/node_modules/mongoose/index.js';

async function run() {
  await mongoose.connect('mongodb://localhost:27017/sentinel-db');
  const db = mongoose.connection.db;

  // 1. BlockedIP real _id and document details
  const blockedIPDocs = await db.collection('blockedips').find({}).toArray();
  
  // 2. Target session IDs and threat IDs being queried
  const sessions = await db.collection('honeypotsessions').find({
    sessionId: { $regex: '^(audit-live-|sess-analyst-feed-proof)' }
  }).toArray();
  const sessionIds = sessions.map(s => s.sessionId);
  const sessionObjectIds = sessions.map(s => s._id);

  const threats = await db.collection('threatlogs').find({
    sourceIP: { $in: ['203.0.113.195', '198.51.100.77'] }
  }).toArray();
  const threatObjectIds = threats.map(t => t._id);
  const threatIdStrings = threats.map(t => t._id.toString());

  // 3. AIPredictions referencing IPs or sessions
  const aiPreds = await db.collection('aipredictions').find({
    $or: [
      { sourceIP: { $in: ['203.0.113.195', '198.51.100.77'] } },
      { sessionId: { $in: sessionIds } },
      { sessionRef: { $in: sessionObjectIds } }
    ]
  }).toArray();

  // 4. Campaigns referencing IPs or threats or sessions
  const campaigns = await db.collection('campaigns').find({
    $or: [
      { sourceIPs: { $in: ['203.0.113.195', '198.51.100.77'] } },
      { targetIPs: { $in: ['203.0.113.195', '198.51.100.77'] } },
      { relatedThreats: { $in: [...threatObjectIds, ...threatIdStrings] } },
      { relatedSessions: { $in: [...sessionObjectIds, ...sessionIds] } }
    ]
  }).toArray();

  // 5. Alerts referencing IPs or threats or messages
  const alerts = await db.collection('alerts').find({
    $or: [
      { sourceIP: { $in: ['203.0.113.195', '198.51.100.77'] } },
      { threatRef: { $in: threatObjectIds } },
      { message: { $regex: '(203\\.0\\.113\\.195|198\\.51\\.100\\.77)' } }
    ]
  }).toArray();

  console.log(JSON.stringify({
    blockedIPs: blockedIPDocs,
    sessionCount: sessions.length,
    threatCount: threats.length,
    aipredictions: {
      count: aiPreds.length,
      docs: aiPreds
    },
    campaigns: {
      count: campaigns.length,
      docs: campaigns
    },
    alerts: {
      count: alerts.length,
      docs: alerts
    }
  }, null, 2));

  await mongoose.disconnect();
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
