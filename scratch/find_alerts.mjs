import { MongoClient } from '../backend/node_modules/mongodb/lib/index.js'

async function run() {
  const client = new MongoClient('mongodb://localhost:27017')
  await client.connect()
  const db = client.db('sentinel-db')
  const alerts = await db.collection('alerts').find({
    $or: [
      { 'details.ip': '198.51.100.77' },
      { 'details.sourceIP': '198.51.100.77' },
      { title: /198\.51\.100\.77/ },
      { description: /198\.51\.100\.77/ },
      { message: /198\.51\.100\.77/ },
      { sourceIP: '198.51.100.77' },
    ]
  }).toArray()
  console.log('Found', alerts.length, 'alerts:')
  console.log(JSON.stringify(alerts, null, 2))
  await client.close()
}

run().catch(console.error)
