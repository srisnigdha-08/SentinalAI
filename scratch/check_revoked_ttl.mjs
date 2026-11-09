import { MongoClient } from '../backend/node_modules/mongodb/lib/index.js'

async function run() {
  const c = new MongoClient('mongodb://localhost:27017/sentinel-db')
  await c.connect()
  const db = c.db()
  const total = await db.collection('authsessions').countDocuments()
  const active = await db.collection('authsessions').countDocuments({ revokedAt: null })
  const revoked = await db.collection('authsessions').countDocuments({ revokedAt: { $type: 'date' } })
  const oldestRevoked = await db.collection('authsessions').find({ revokedAt: { $type: 'date' } }).sort({ revokedAt: 1 }).limit(1).toArray()
  const newestRevoked = await db.collection('authsessions').find({ revokedAt: { $type: 'date' } }).sort({ revokedAt: -1 }).limit(1).toArray()

  console.log('=== REVOKED SESSIONS TTL CLEANUP REPORT ===')
  console.log(`Total sessions:                     ${total}`)
  console.log(`Active sessions (revokedAt: null):   ${active}`)
  console.log(`Revoked sessions (revokedAt: Date):  ${revoked}`)
  if (oldestRevoked.length > 0) {
    console.log(`Oldest revokedAt:                   ${oldestRevoked[0].revokedAt.toISOString()}`)
    const expireOldest = new Date(oldestRevoked[0].revokedAt.getTime() + 172800 * 1000)
    console.log(`  -> Will expire automatically at:   ${expireOldest.toISOString()}`)
  }
  if (newestRevoked.length > 0) {
    console.log(`Newest revokedAt:                   ${newestRevoked[0].revokedAt.toISOString()}`)
    const expireNewest = new Date(newestRevoked[0].revokedAt.getTime() + 172800 * 1000)
    console.log(`  -> Will expire automatically at:   ${expireNewest.toISOString()}`)
  }
  await c.close()
}

run().catch(console.error)
