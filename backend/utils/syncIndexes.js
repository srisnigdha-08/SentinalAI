'use strict'
/**
 * Keeps the database's indexes equal to the Mongoose schemas. Mongoose builds missing indexes at start-up but never
 * drops indexes a schema no longer declares, so databases drift (e.g. a leftover single-field index that duplicates
 * the prefix of a compound one, which costs every write).
 *
 *   npm run db:indexes                                  dry run: lists what would be dropped and created
 *   npm run db:indexes -- --apply --confirm=<database>  applies it (the database name must be repeated)
 *
 * Only collections that belong to a model are touched; `_id_` is never dropped; documents are never modified.
 * Creating a unique index fails if existing documents violate it: that is reported and nothing else is changed for
 * that model. Run the dry run first, and take a backup before applying (scripts/demo/backup-local-db.cjs).
 */
const fs = require('fs')
const path = require('path')
const mongoose = require('mongoose')

// autoIndex AND autoCreate off: loading the models must not build indexes or create a model's missing collection.
// (autoCreate defaults to true in Mongoose 8; an early version of this script created empty collections on a dry run.)
const CONNECT_OPTIONS = { serverSelectionTimeoutMS: 5000, autoIndex: false, autoCreate: false }

function loadModels(dir = path.join(__dirname, '..', 'models')) {
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.js'))) require(path.join(dir, file))
  return mongoose
    .modelNames()
    .sort()
    .map((name) => mongoose.model(name))
}

const describeSpec = (spec) => {
  const [fields, options = {}] = Array.isArray(spec) ? spec : [spec.key || spec, spec]
  const keys = Object.entries(fields)
    .map(([k, v]) => `${k}:${v}`)
    .join('+')
  const flags = ['unique', 'sparse'].filter((f) => options[f])
  if (options.expireAfterSeconds !== undefined) flags.push(`ttl=${options.expireAfterSeconds}`)
  if (options.partialFilterExpression) flags.push('partial')
  return flags.length ? `${keys} (${flags.join(', ')})` : keys
}

/** Per model: { model, collection, toDrop: [index names], toCreate: [descriptions] }. Reads only. */
async function diffAll(models) {
  const out = []
  for (const Model of models) {
    const collection = Model.collection.collectionName
    const exists = (await Model.db.db.listCollections({ name: collection }, { nameOnly: true }).toArray()).length > 0
    if (!exists) {
      out.push({ model: Model.modelName, collection, missingCollection: true, toDrop: [], toCreate: [] })
      continue
    }
    const { toDrop, toCreate } = await Model.diffIndexes({ indexOptionsToCreate: true })
    out.push({
      model: Model.modelName,
      collection,
      toDrop: toDrop.filter((n) => n !== '_id_'),
      toCreate: toCreate.map(describeSpec),
    })
  }
  return out
}

/** Applies the diff model by model; returns { model, dropped, error } entries. */
async function applyAll(models) {
  const results = []
  for (const Model of models) {
    try {
      const dropped = await Model.syncIndexes()
      results.push({ model: Model.modelName, dropped: dropped.filter((n) => n !== '_id_') })
    } catch (err) {
      results.push({ model: Model.modelName, dropped: [], error: `${err.name}: ${err.codeName || err.message}` })
    }
  }
  return results
}

async function main(argv = process.argv.slice(2)) {
  require('dotenv').config({ path: process.env.DOTENV_CONFIG_PATH || path.join(__dirname, '..', '.env') })
  const uri = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db'
  const { databaseName } = require('./destructiveGuard')
  const db = databaseName(uri)
  const apply = argv.includes('--apply')
  if (apply) {
    const confirmed = (argv.find((a) => a.startsWith('--confirm=')) || '').slice('--confirm='.length)
    if (!db || confirmed !== db) {
      console.error(
        `[BLOCKED] --apply changes the indexes of database ${db || '(unparsed)'}. Re-run with --confirm=${db || '<database>'}`
      )
      return 1
    }
  }
  await mongoose.connect(uri, CONNECT_OPTIONS)
  try {
    const models = loadModels()
    const diff = await diffAll(models)
    let pending = 0
    console.log(`Database: ${db}${apply ? '' : '  (dry run: nothing is changed)'}`)
    for (const d of diff) {
      if (d.missingCollection) continue
      if (!d.toDrop.length && !d.toCreate.length) continue
      pending += d.toDrop.length + d.toCreate.length
      console.log(`\n${d.model} (${d.collection})`)
      for (const n of d.toDrop) console.log(`  drop    ${n}`)
      for (const c of d.toCreate) console.log(`  create  ${c}`)
    }
    if (!pending) {
      console.log('\nIndexes match the schemas.')
      return 0
    }
    if (!apply) {
      console.log(`\n${pending} change(s). Apply with: npm run db:indexes -- --apply --confirm=${db}`)
      return 0
    }
    const results = await applyAll(models)
    const failed = results.filter((r) => r.error)
    for (const r of results) if (r.dropped.length) console.log(`dropped from ${r.model}: ${r.dropped.join(', ')}`)
    for (const r of failed) console.error(`FAILED ${r.model}: ${r.error}`)
    console.log(failed.length ? `\n${failed.length} model(s) failed; see above.` : '\nIndexes synchronised.')
    return failed.length ? 1 : 0
  } finally {
    await mongoose.disconnect()
  }
}

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error('ERROR: ' + err.name)
      process.exit(1)
    }
  )
}

module.exports = { CONNECT_OPTIONS, loadModels, diffAll, applyAll, describeSpec, main }
