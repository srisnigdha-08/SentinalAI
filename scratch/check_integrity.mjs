import mongoose from '../backend/node_modules/mongoose/index.js';

async function checkReferentialIntegrity() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  console.log('=== CHECK 4: REFERENTIAL INTEGRITY & ORPHANS ===');

  // 1. alerts -> sourceRef
  const alerts = await db.collection('alerts').find({}).toArray();
  let alertOrphans = 0;
  for (const a of alerts) {
    if (a.sourceRef && a.sourceRef.refId) {
      const collMap = { ThreatLog: 'threatlogs', HoneypotSession: 'honeypotsessions', User: 'users', AIPrediction: 'aipredictions' };
      const targetColl = collMap[a.sourceRef.refModel];
      if (targetColl) {
        const found = await db.collection(targetColl).findOne({ _id: a.sourceRef.refId });
        if (!found) {
          alertOrphans++;
          console.log('  Alert orphan:', a._id, 'refModel:', a.sourceRef.refModel, 'refId:', a.sourceRef.refId);
        }
      }
    }
  }
  console.log('Alerts -> SourceRef orphans:', alertOrphans, '/', alerts.length);

  // 2. honeypotsessions.linkedThreatLog -> threatlogs
  const hpSessions = await db.collection('honeypotsessions').find({ linkedThreatLog: { $ne: null } }).toArray();
  let hpThreatOrphans = 0;
  for (const s of hpSessions) {
    const found = await db.collection('threatlogs').findOne({ _id: s.linkedThreatLog });
    if (!found) {
      hpThreatOrphans++;
      console.log('  HoneypotSession orphan linkedThreatLog:', s._id, 'target:', s.linkedThreatLog);
    }
  }
  console.log('HoneypotSession -> ThreatLog orphans:', hpThreatOrphans, '/', hpSessions.length);

  // 3. authsessions -> users
  const sessions = await db.collection('authsessions').find({}).toArray();
  let sessionOrphans = 0;
  for (const s of sessions) {
    const found = await db.collection('users').findOne({ _id: s.user });
    if (!found) {
      sessionOrphans++;
      console.log('  AuthSession orphan user:', s._id, 'user:', s.user);
    }
  }
  console.log('AuthSessions -> User orphans:', sessionOrphans, '/', sessions.length);

  // 4. campaigns.sessions -> honeypotsessions
  const campaigns = await db.collection('campaigns').find({}).toArray();
  let campaignSessionOrphans = 0;
  let totalCampaignSessionRefs = 0;
  for (const c of campaigns) {
    for (const sid of (c.sessions || [])) {
      totalCampaignSessionRefs++;
      const found = await db.collection('honeypotsessions').findOne({ _id: sid });
      if (!found) {
        campaignSessionOrphans++;
        console.log('  Campaign', c.campaignId, 'orphan session ref:', sid);
      }
    }
  }
  console.log('Campaigns -> HoneypotSessions orphans:', campaignSessionOrphans, '/', totalCampaignSessionRefs);

  // 5. aipredictions.generatedThreat -> threatlogs
  const predictions = await db.collection('aipredictions').find({ generatedThreat: { $ne: null } }).toArray();
  let predThreatOrphans = 0;
  for (const p of predictions) {
    const found = await db.collection('threatlogs').findOne({ _id: p.generatedThreat });
    if (!found) {
      predThreatOrphans++;
      console.log('  AIPrediction orphan generatedThreat:', p._id, 'target:', p.generatedThreat);
    }
  }
  console.log('AIPredictions -> ThreatLogs orphans:', predThreatOrphans, '/', predictions.length);

  // 6. threatlogs.containmentId -> blockedips
  const threatsWithContainment = await db.collection('threatlogs').find({ containmentId: { $ne: null } }).toArray();
  let threatContainmentOrphans = 0;
  for (const t of threatsWithContainment) {
    const found = await db.collection('blockedips').findOne({ _id: t.containmentId });
    if (!found) {
      threatContainmentOrphans++;
      console.log('  ThreatLog orphan containmentId:', t._id, 'target:', t.containmentId);
    }
  }
  console.log('ThreatLogs -> BlockedIPs orphans:', threatContainmentOrphans, '/', threatsWithContainment.length);

  // 7. threatlogs.predictionId -> aipredictions
  const threatsWithPred = await db.collection('threatlogs').find({ predictionId: { $ne: null } }).toArray();
  let threatPredOrphans = 0;
  for (const t of threatsWithPred) {
    const found = await db.collection('aipredictions').findOne({ _id: t.predictionId });
    if (!found) {
      threatPredOrphans++;
      console.log('  ThreatLog orphan predictionId:', t._id, 'target:', t.predictionId);
    }
  }
  console.log('ThreatLogs -> AIPredictions orphans:', threatPredOrphans, '/', threatsWithPred.length);

  // 8. auditlogs actor.id / target.id
  const audits = await db.collection('auditlogs').find({}).toArray();
  let auditActorUserOrphans = 0;
  let auditTargetOrphans = 0;
  for (const a of audits) {
    if (a.actor && a.actor.id) {
      try {
        const found = await db.collection('users').findOne({ _id: new mongoose.Types.ObjectId(a.actor.id) });
        if (!found) auditActorUserOrphans++;
      } catch {
        auditActorUserOrphans++;
      }
    }
    if (a.target && a.target.id) {
      let targetColl = null;
      if (a.target.type === 'User') targetColl = 'users';
      else if (a.target.type === 'Threat' || a.target.type === 'ThreatLog') targetColl = 'threatlogs';
      else if (a.target.type === 'ContainmentAction') targetColl = 'containmentactions';
      if (targetColl) {
        try {
          const found = await db.collection(targetColl).findOne({ _id: new mongoose.Types.ObjectId(a.target.id) });
          if (!found) auditTargetOrphans++;
        } catch {
          auditTargetOrphans++;
        }
      }
    }
  }
  console.log('AuditLogs -> Actor User orphans:', auditActorUserOrphans, '/', audits.length);
  console.log('AuditLogs -> Target orphans:', auditTargetOrphans, '/', audits.length);

  await mongoose.disconnect();
}
checkReferentialIntegrity().catch(console.error);
