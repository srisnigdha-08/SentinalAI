import { MongoClient, ObjectId } from '../backend/node_modules/mongodb/lib/index.js'

async function run() {
  const uri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/sentinel-db'
  const client = new MongoClient(uri)

  try {
    await client.connect()
    const db = client.db()
    const usersCol = db.collection('users')

    console.log('=== BEFORE DELETION ===')
    const beforeTarget = await usersCol.findOne({ _id: new ObjectId('6ad481835d17085d4036a633') }, { projection: { password: 0 } })
    console.log('Target document found:', JSON.stringify(beforeTarget, null, 2))
    const countBefore = await usersCol.countDocuments()
    console.log(`Total users before deletion: ${countBefore}`)

    if (!beforeTarget) {
      console.log('Target document not found. Nothing to delete.')
      return
    }

    console.log('\n=== EXECUTING DELETION ===')
    const deleteResult = await usersCol.deleteOne({ _id: new ObjectId('6ad481835d17085d4036a633') })
    console.log(`Delete acknowledgment: acknowledged=${deleteResult.acknowledged}, deletedCount=${deleteResult.deletedCount}`)

    console.log('\n=== AFTER DELETION ===')
    const countAfter = await usersCol.countDocuments()
    console.log(`Total users after deletion: ${countAfter}`)

    const remainingUsers = await usersCol.find({}, { projection: { email: 1, role: 1, status: 1, department: 1 } }).toArray()
    console.log('\nRemaining Users in sentinel-db:')
    remainingUsers.forEach(u => {
      console.log(`  - [${u._id}] ${u.email.padEnd(22)} (role: ${u.role}, status: ${u.status}, dept: ${u.department || 'N/A'})`)
    })

    // Check if any authsessions remain for this user id
    const orphanSessions = await db.collection('authsessions').countDocuments({ user: '6ad481835d17085d4036a633' })
    console.log(`\nRemaining authsessions for deleted user: ${orphanSessions}`)
  } finally {
    await client.close()
  }
}

run().catch(console.error)
