import { createRequire } from 'module'
import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import { fileURLToPath } from 'url'

const require = createRequire(import.meta.url)
const { MongoClient } = require('../backend/node_modules/mongodb')

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const uri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/sentinel-db'
const client = new MongoClient(uri)

async function run() {
  try {
    await client.connect()
    const db = client.db()
    const collections = await db.listCollections().toArray()
    // Sort collections alphabetically for stable output
    collections.sort((a, b) => a.name.localeCompare(b.name))

    const rawIndexes = {}
    let totalIndexes = 0
    const perCollectionCounts = {}

    for (const col of collections) {
      const colName = col.name
      const indexes = await db.collection(colName).indexes()
      rawIndexes[colName] = indexes
      perCollectionCounts[colName] = indexes.length
      totalIndexes += indexes.length
    }

    const evidenceDir = path.join(__dirname, 'evidence')
    if (!fs.existsSync(evidenceDir)) {
      fs.mkdirSync(evidenceDir, { recursive: true })
    }

    const targetFile = path.join(evidenceDir, 'sentinel_db_indexes_raw.json')
    const jsonContent = JSON.stringify(rawIndexes, null, 2)
    fs.writeFileSync(targetFile, jsonContent, 'utf8')

    const fileBuffer = fs.readFileSync(targetFile)
    const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex')

    console.log('=== SENTINEL-DB LIVE INDEX DUMP ===')
    console.log(`File Path: ${targetFile}`)
    console.log(`File Size: ${fileBuffer.length} bytes`)
    console.log(`SHA-256:   ${sha256}`)
    console.log(`Total Collections: ${collections.length}`)
    console.log(`Total Indexes:     ${totalIndexes}`)
    console.log('\n--- PER-COLLECTION COUNTS ---')
    for (const [col, count] of Object.entries(perCollectionCounts)) {
      console.log(`  ${col.padEnd(20)}: ${count} indexes`)
    }

    console.log('\n--- VERBATIM RAW INDEX DETAILS (NAMES + KEYS + OPTIONS) ---')
    for (const [col, idxList] of Object.entries(rawIndexes)) {
      console.log(`\nCollection: [${col}] (${idxList.length} indexes)`)
      for (const idx of idxList) {
        const { v, ...rest } = idx
        console.log(`  - name: "${rest.name}"`)
        console.log(`    key:  ${JSON.stringify(rest.key)}`)
        const options = { ...rest }
        delete options.name
        delete options.key
        if (Object.keys(options).length > 0) {
          console.log(`    options: ${JSON.stringify(options)}`)
        }
      }
    }
  } finally {
    await client.close()
  }
}

run().catch((err) => {
  console.error('Error dumping indexes:', err)
  process.exit(1)
})
