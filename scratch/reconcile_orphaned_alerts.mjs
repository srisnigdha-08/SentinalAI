/**
 * scratch/reconcile_orphaned_alerts.mjs
 *
 * READ-ONLY Reconcile Report: Orphaned Alert Detection
 *
 * Purpose:
 * Scans the alerts collection for references (sourceRef) pointing to deleted
 * upstream entities (ThreatLog, HoneypotSession, User, AIPrediction).
 *
 * SAFETY INVARIANTS:
 * - STRICTLY READ-ONLY: performs .find() and .findOne() queries only.
 * - ZERO mutations: no deletes, no updates, no inserts, no index alterations.
 * - Safe to run at any time against production, staging, or local development DBs.
 */

import { MongoClient, ObjectId } from '../backend/node_modules/mongodb/lib/index.js'

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db'

const MODEL_TO_COLLECTION = {
  ThreatLog: 'threatlogs',
  HoneypotSession: 'honeypotsessions',
  User: 'users',
  AIPrediction: 'aipredictions',
}

async function reconcileAlerts() {
  const client = new MongoClient(MONGO_URI)
  const startTime = new Date()

  try {
    await client.connect()
    const db = client.db()
    const dbName = db.databaseName

    console.log('='.repeat(70))
    console.log(' SENTINEL-AI READ-ONLY ORPHANED ALERTS RECONCILIATION REPORT')
    console.log('='.repeat(70))
    console.log(`Timestamp : ${startTime.toISOString()}`)
    console.log(`Database  : ${dbName} (${MONGO_URI.replace(/\/\/[^:]+:[^@]+@/, '//***:***@')})`)
    console.log(`Mode      : READ-ONLY (Zero writes/deletes will be executed)\n`)

    const alertCollection = db.collection('alerts')
    const totalAlerts = await alertCollection.countDocuments({})
    const allAlerts = await alertCollection.find({}).sort({ createdAt: -1 }).toArray()

    const orphanedAlerts = []
    const validAlerts = []
    const unreferencedAlerts = []

    for (const alert of allAlerts) {
      if (!alert.sourceRef || !alert.sourceRef.refModel || !alert.sourceRef.refId) {
        unreferencedAlerts.push(alert)
        continue
      }

      const { refModel, refId } = alert.sourceRef
      const targetCollectionName = MODEL_TO_COLLECTION[refModel]

      if (!targetCollectionName) {
        orphanedAlerts.push({
          alert,
          reason: `Unknown refModel: "${refModel}"`,
          refModel,
          refId,
        })
        continue
      }

      const targetCol = db.collection(targetCollectionName)
      let queryId = refId
      if (typeof refId === 'string' && ObjectId.isValid(refId)) {
        queryId = new ObjectId(refId)
      }

      const referencedDoc = await targetCol.findOne({ _id: queryId }, { projection: { _id: 1 } })

      if (!referencedDoc) {
        orphanedAlerts.push({
          alert,
          reason: `Referenced ${refModel} [${refId}] does not exist in "${targetCollectionName}"`,
          refModel,
          refId,
        })
      } else {
        validAlerts.push({
          alert,
          refModel,
          refId,
        })
      }
    }

    console.log('--- SUMMARY METRICS ---')
    console.log(`Total Alerts in Database      : ${totalAlerts}`)
    console.log(`Valid Referenced Alerts       : ${validAlerts.length}`)
    console.log(`Standalone (No sourceRef)     : ${unreferencedAlerts.length}`)
    console.log(`Orphaned Alerts Detected      : ${orphanedAlerts.length}\n`)

    if (orphanedAlerts.length === 0) {
      console.log('✓ No orphaned alerts found. Referential integrity is intact.\n')
    } else {
      console.log('--- DETAILED ORPHANED ALERTS INVENTORY ---')
      orphanedAlerts.forEach((item, idx) => {
        const a = item.alert
        const now = Date.now()
        let expiryInfo = 'No expiresAt set'
        if (a.expiresAt) {
          const exp = new Date(a.expiresAt)
          const msLeft = exp.getTime() - now
          const daysLeft = (msLeft / (1000 * 60 * 60 * 24)).toFixed(1)
          expiryInfo = `${exp.toISOString()} (${daysLeft > 0 ? `${daysLeft} days remaining` : 'EXPIRED - awaiting TTL sweep'})`
        }

        console.log(`[${idx + 1}] Alert ID   : ${a._id}`)
        console.log(`    Title      : ${a.title}`)
        console.log(`    Severity   : ${a.severity}`)
        console.log(`    Type       : ${a.type}`)
        console.log(`    Created At : ${a.createdAt ? new Date(a.createdAt).toISOString() : 'N/A'}`)
        console.log(`    Expires At : ${expiryInfo}`)
        console.log(`    SourceRef  : { refModel: '${item.refModel}', refId: ObjectId('${item.refId}') }`)
        console.log(`    Issue      : ${item.reason}`)
        console.log('')
      })
    }

    console.log('='.repeat(70))
    console.log('SAFETY AUDIT: 0 writes executed | 0 deletions | 0 schema mutations')
    console.log('='.repeat(70))
  } catch (err) {
    console.error('Error during reconciliation audit:', err)
    process.exitCode = 1
  } finally {
    await client.close()
  }
}

reconcileAlerts()
