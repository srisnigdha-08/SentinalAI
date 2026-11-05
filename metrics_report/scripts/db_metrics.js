// Read-only aggregation of every local SentinelAI MongoDB database (metrics audit 2026-10-22).
// Run: mongosh --quiet mongodb://localhost:27017 metrics_report/scripts/db_metrics.js > metrics_report/raw/db_metrics.json
// Nothing is written. Every database is reported separately: they come from different test/demo runs.
const out = { generated_at: new Date().toISOString(), databases: {} };
const skip = ["admin", "config", "local"];
const pct = (a) => { if (!a.length) return null; const s = [...a].sort((x, y) => x - y);
  const q = (p) => s[Math.min(s.length - 1, Math.floor(p * (s.length - 1) + 0.5))];
  return { n: s.length, mean: +(s.reduce((x, y) => x + y, 0) / s.length).toFixed(2), p50: q(0.5), p95: q(0.95), max: s[s.length - 1], min: s[0] }; };
const count = (arr) => arr.reduce((m, k) => { const key = String(k); m[key] = (m[key] || 0) + 1; return m; }, {});

for (const { name } of db.adminCommand({ listDatabases: 1 }).databases) {
  if (skip.includes(name)) continue;
  const d = db.getSiblingDB(name);
  const r = { collections: {} };
  for (const c of d.getCollectionNames()) r.collections[c] = d.getCollection(c).countDocuments();

  const hs = d.honeypotsessions.find({}, { rawEvents: 0 }).toArray();
  if (hs.length) {
    const creds = hs.flatMap((s) => s.credentials || []);
    const ioc = hs.reduce((m, s) => { const i = s.iocExtracted || {}; m.ips += (i.ips || []).length; m.urls += (i.urls || []).length; m.hashes += (i.hashes || []).length; return m; }, { ips: 0, urls: 0, hashes: 0 });
    const ingest = hs.filter((s) => s.closureAnalysisStartedAt && s.closureAnalysisCompletedAt)
      .map((s) => new Date(s.closureAnalysisCompletedAt) - new Date(s.closureAnalysisStartedAt));
    r.honeypot = {
      sessions: hs.length,
      unique_source_ips: new Set(hs.map((s) => s.sourceIP)).size,
      source_ips: count(hs.map((s) => s.sourceIP)),
      client_versions: count(hs.map((s) => s.clientVersion)),
      login_attempts: creds.length,
      login_success: creds.filter((c) => c.success === true).length,
      login_failed: creds.filter((c) => c.success === false).length,
      commands_total: hs.reduce((a, s) => a + (s.commands || []).length, 0),
      commands_per_session: pct(hs.map((s) => (s.commands || []).length)),
      duration_seconds: pct(hs.map((s) => s.durationSeconds || 0)),
      duration_seconds_nonzero: pct(hs.map((s) => s.durationSeconds || 0).filter((x) => x > 0)),
      iocs: ioc,
      downloads: hs.reduce((a, s) => a + (s.downloadCount || 0), 0),
      classification: count(hs.map((s) => s.aiClassification)),
      classification_method: count(hs.map((s) => s.aiClassificationMethod)),
      status: count(hs.map((s) => s.status)),
      closure_state: count(hs.map((s) => s.closureAnalysisState)),
      ai_pending: hs.filter((s) => s.aiAnalysisPending).length,
      deception_pending: hs.filter((s) => s.deceptionScoringPending).length,
      served_profile: count(hs.map((s) => s.servedProfile)),
      recommended_profile: count(hs.map((s) => s.recommendedProfile)),
      engagement_level: count(hs.map((s) => s.engagementLevel)),
      mitre_techniques: count(hs.flatMap((s) => (s.mitreTechniques || []).map((t) => (t && t.id) || t))),
      sessions_with_mitre: hs.filter((s) => (s.mitreTechniques || []).length).length,
      closure_analysis_ms: pct(ingest),
      q_deception_score: pct(hs.filter((s) => s.qDeceptionScore != null).map((s) => s.qDeceptionScore)),
      duration_by_served_profile: Object.fromEntries(Object.entries(count(hs.map((s) => s.servedProfile)))
        .map(([p]) => [p, pct(hs.filter((s) => String(s.servedProfile) === p).map((s) => s.durationSeconds || 0))])),
      first: hs.map((s) => s.startTime).sort()[0], last: hs.map((s) => s.startTime).sort().slice(-1)[0],
    };
  }

  const ca = d.containmentactions.find().toArray();
  if (ca.length) {
    r.containment = {
      actions: ca.length,
      policy_decision: count(ca.map((c) => c.policyDecision)),
      enforcement_backend: count(ca.map((c) => c.enforcementBackend)),
      enforcement_status: count(ca.map((c) => c.enforcementStatus)),
      requested_by: count(ca.map((c) => c.requestedByName)),
      rolled_back: ca.filter((c) => c.rolledBackAt).length,
      failure_reasons: count(ca.filter((c) => c.failureReason).map((c) => c.failureReason)),
      request_to_applied_ms: pct(ca.filter((c) => c.appliedAt && c.requestedAt).map((c) => new Date(c.appliedAt) - new Date(c.requestedAt))),
      adapter_exec_ms: pct(ca.map((c) => (c.enforcementDetails || {}).executionDurationMs).filter((x) => x != null)),
      targets: ca.map((c) => c.target),
    };
  }
  const tl = d.threatlogs.find().toArray();
  if (tl.length) {
    const auto = tl.filter((t) => t.autonomousAction && t.autonomousAction.taken);
    r.threats = {
      threat_logs: tl.length,
      severity: count(tl.map((t) => t.severity)),
      attack_type: count(tl.map((t) => t.attackType)),
      status: count(tl.map((t) => t.status)),
      autonomous_actions: auto.length,
      threat_to_autoblock_ms: pct(auto.filter((t) => t.autonomousAction.actionTime && t.createdAt)
        .map((t) => new Date(t.autonomousAction.actionTime) - new Date(t.createdAt))),
      mitre: count(tl.flatMap((t) => (t.mitreTechniques || []).map((m) => (m && m.id) || m))),
      unique_sources: new Set(tl.map((t) => t.sourceIP)).size,
    };
  }
  const ap = d.aipredictions.find().toArray();
  if (ap.length) {
    const keys = Object.keys(ap[0]);
    r.predictions = { n: ap.length, sample_keys: keys,
      by_class: count(ap.map((p) => p.prediction || p.predictedClass || p.classification || p.attackType)),
      model_type: count(ap.map((p) => p.modelType)),
      processing_ms: pct(ap.map((p) => p.processingTimeMs ?? p.inferenceTimeMs ?? p.latencyMs).filter((x) => typeof x === "number")) };
  }
  const bl = d.blockedips.countDocuments();
  if (bl) r.blocked_ips = bl;
  const al = d.alerts.find().toArray();
  if (al.length) r.alerts = { n: al.length, severity: count(al.map((a) => a.severity)), type: count(al.map((a) => a.type || a.alertType)) };
  const au = d.auditlogs ? d.auditlogs.aggregate([{ $group: { _id: "$action", n: { $sum: 1 } } }]).toArray() : [];
  if (au.length) r.audit_actions = Object.fromEntries(au.map((x) => [x._id, x.n]));
  out.databases[name] = r;
}
print(JSON.stringify(out, null, 1));
