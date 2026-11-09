// Read-only: end-to-end "flow sent -> ThreatLog/Alert stored" latency for the benchmark replay, and direct
// MongoDB query timings, against the isolated bench database only.
// Run: mongosh --quiet mongodb://127.0.0.1:27017/sentinel-metrics-bench-20261023 metrics_report/scripts/e2e_and_db_latency.js
const rows = JSON.parse(fs.readFileSync('metrics_report/raw/backend_replay_rows.json', 'utf8'))
const pct = (a) => { if (!a.length) return null; const s = [...a].sort((x, y) => x - y)
  const q = (p) => s[Math.min(s.length - 1, Math.round(p * (s.length - 1)))]
  return { n: s.length, mean: +(s.reduce((x, y) => x + y, 0) / s.length).toFixed(1), p50: q(0.5), p95: q(0.95), p99: q(0.99), max: s[s.length - 1] } }
const first = new Date(rows[0].sent)
const threats = db.threatlogs.find({ createdAt: { $gte: first }, sourceIP: /^198\.51\.100\./ }).toArray()
const alerts = db.alerts.find({ createdAt: { $gte: first } }).toArray()
const preds = db.aipredictions.find({ createdAt: { $gte: first }, sourceIP: /^198\.51\.100\./ }).toArray()
const byIp = {}; rows.forEach((r) => { (byIp[r.sourceIP] = byIp[r.sourceIP] || []).push(r) })
const lat = (docs) => docs.map((d) => { const c = (byIp[d.sourceIP] || []).filter((r) => new Date(r.sent) <= d.createdAt)
  .sort((a, b) => new Date(b.sent) - new Date(a.sent))[0]; return c ? d.createdAt - new Date(c.sent) : null }).filter((x) => x != null)
const time = (fn, n) => { const t = []; for (let i = 0; i < n; i++) { const t0 = Date.now(); fn(); t.push(Date.now() - t0) } return pct(t) }
const out = {
  replayed: rows.length, threats_created: threats.length, alerts_created: alerts.length, predictions_stored: preds.length,
  threat_severity: threats.reduce((m, t) => (m[t.severity] = (m[t.severity] || 0) + 1, m), {}),
  threat_attack_types: threats.reduce((m, t) => (m[t.attackType] = (m[t.attackType] || 0) + 1, m), {}),
  threats_with_mitre: threats.filter((t) => (t.mitreTechniques || []).length).length,
  sent_to_prediction_stored_ms: pct(lat(preds)),
  sent_to_threatlog_stored_ms: pct(lat(threats)),
  mongo_query_ms: {
    threatlogs_recent_20: time(() => db.threatlogs.find().sort({ createdAt: -1 }).limit(20).toArray(), 200),
    threatlogs_count_by_severity: time(() => db.threatlogs.aggregate([{ $group: { _id: '$severity', n: { $sum: 1 } } }]).toArray(), 200),
    aipredictions_recent_50: time(() => db.aipredictions.find().sort({ createdAt: -1 }).limit(50).toArray(), 200),
    honeypotsessions_recent_20: time(() => db.honeypotsessions.find().sort({ startTime: -1 }).limit(20).toArray(), 200),
  },
  collection_counts: Object.fromEntries(db.getCollectionNames().map((c) => [c, db.getCollection(c).countDocuments()])),
  note: 'mongo_query_ms is measured from mongosh on the same host (includes client round trip); bench DB is small',
}
print(JSON.stringify(out, null, 1))
