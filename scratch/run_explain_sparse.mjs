import { MongoClient } from '../backend/node_modules/mongodb/lib/index.js'

async function run() {
  const client = new MongoClient('mongodb://localhost:27017/sentinel-db')
  try {
    await client.connect()
    const db = client.db()

    const totalCount = await db.collection('authsessions').countDocuments()
    const nullCount = await db.collection('authsessions').countDocuments({ revokedAt: null })
    const dateCount = await db.collection('authsessions').countDocuments({ revokedAt: { $type: 'date' } })
    const missingCount = await db.collection('authsessions').countDocuments({ revokedAt: { $exists: false } })

    console.log('=== AUTHSESSIONS INVENTORY ===')
    console.log(`Total documents:               ${totalCount}`)
    console.log(`revokedAt is null:             ${nullCount}`)
    console.log(`revokedAt is BSON Date:        ${dateCount}`)
    console.log(`revokedAt is missing:          ${missingCount}`)

    const explainResult = await db.collection('authsessions')
      .find({ revokedAt: { $eq: null, $exists: true } })
      .hint('revokedAt_1')
      .explain('executionStats')

    console.log('\n=== RAW EXPLAIN EXECUTION STATS ===')
    console.log(JSON.stringify(explainResult.executionStats, null, 2))

    console.log('\n=== WINNING PLAN ===')
    console.log(JSON.stringify(explainResult.queryPlanner.winningPlan, null, 2))
  } finally {
    await client.close()
  }
}

run().catch(console.error)
