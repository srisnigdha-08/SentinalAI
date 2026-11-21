// READ-ONLY label audit for the honeypot-session classifier (docs/SESSION_ML.md). Run: node scripts/session_ml_data_audit.js
// Only SentinelAI databases (name starts with "sentinel"). listDatabases, listCollections, countDocuments, aggregate, find(limit 1).
// No insert / update / delete / index / drop call exists in this file. No IP address or credential is printed.
const { MongoClient } = require(require('path').join(__dirname, '..', 'backend', 'node_modules', 'mongodb'))

;(async () => {
  const c = new MongoClient(process.env.SESSION_AUDIT_MONGO_URI || 'mongodb://127.0.0.1:27017', { serverSelectionTimeoutMS: 4000 })
  await c.connect()
  const dbs = (await c.db().admin().listDatabases({ nameOnly: true })).databases.map((d) => d.name)
  const out = { databases: dbs.filter((n) => /^sentinel/i.test(n)) }
  for (const name of out.databases) {
    const db = c.db(name)
    const cols = (await db.listCollections({}, { nameOnly: true }).toArray()).map((x) => x.name)
    if (!cols.includes('honeypotsessions')) continue
    const s = db.collection('honeypotsessions')
    const g = async (field) =>
      Object.fromEntries(
        (await s.aggregate([{ $group: { _id: `$${field}`, n: { $sum: 1 } } }]).toArray()).map((r) => [String(r._id), r.n])
      )
    const span = await s.aggregate([{ $group: { _id: null, min: { $min: '$startTime' }, max: { $max: '$startTime' } } }]).toArray()
    const distinctIPs = (await s.aggregate([{ $group: { _id: '$sourceIP' } }, { $count: 'n' }]).toArray())[0]?.n || 0
    const sessionsPerIP = await s
      .aggregate([{ $group: { _id: '$sourceIP', n: { $sum: 1 } } }, { $group: { _id: '$n', ips: { $sum: 1 } } }, { $sort: { _id: 1 } }])
      .toArray()
    const cmdStats = (
      await s
        .aggregate([
          {
            $project: {
              n: { $size: { $ifNull: ['$commands', []] } },
              ok: { $anyElementTrue: [{ $map: { input: { $ifNull: ['$credentials', []] }, in: '$$this.success' } }] },
            },
          },
          {
            $group: {
              _id: null,
              total: { $sum: 1 },
              withCommands: { $sum: { $cond: [{ $gt: ['$n', 0] }, 1, 0] } },
              commands: { $sum: '$n' },
              loginOk: { $sum: { $cond: ['$ok', 1, 0] } },
            },
          },
        ])
        .toArray()
    )[0]
    // Near-duplicates: identical command sequences
    const dupSeq = await s
      .aggregate([
        { $project: { seq: { $map: { input: { $ifNull: ['$commands', []] }, in: '$$this.command' } } } },
        { $group: { _id: '$seq', n: { $sum: 1 } } },
        { $match: { n: { $gt: 1 } } },
        { $group: { _id: null, groups: { $sum: 1 }, sessions: { $sum: '$n' } } },
      ])
      .toArray()
    const simulated = await s.countDocuments({ sessionId: /^(demo|arena|sim)-/i })
    const sample = (await s.find({}, { projection: { _id: 0 } }).limit(1).toArray())[0] || {}
    out[name] = {
      total: await s.countDocuments({}),
      status: await g('status'),
      evidenceSource: await g('evidenceSource'),
      aiClassification: await g('aiClassification'),
      aiClassificationMethod: await g('aiClassificationMethod'),
      servedProfile: await g('servedProfile'),
      evidenceLabelMethod: await g('evidenceLabel.method'),
      distinctSourceIPs: distinctIPs,
      sessionsPerSourceIP: sessionsPerIP.map((r) => `${r.ips} IP(s) with ${r._id} session(s)`),
      identicalCommandSequences: dupSeq[0] || { groups: 0, sessions: 0 },
      startTimeSpan: span[0] ? { min: span[0].min, max: span[0].max } : null,
      simulatedIdPrefix: simulated,
      commandStats: cmdStats,
      fieldsPresent: Object.keys(sample).sort(),
      labelLikeCollections: {},
    }
    for (const col of cols.filter((x) => /label|train|sample|verif/i.test(x)))
      out[name].labelLikeCollections[col] = await db.collection(col).countDocuments({})
  }
  console.log(JSON.stringify(out, null, 1))
  await c.close()
})().catch((e) => {
  console.error('AUDIT ERROR', e.message)
  process.exit(1)
})
