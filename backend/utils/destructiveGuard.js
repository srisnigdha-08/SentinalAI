'use strict'

/**
 * Guard for scripts that delete collections. The operator must name the target database:
 *   npm run seed -- --confirm=sentinel-db
 * so a stray `npm run seed` can never wipe the demo/production database.
 */
const databaseName = (uri) => {
  try {
    const name = new URL(uri).pathname.replace(/^\//, '')
    return decodeURIComponent(name) || null
  } catch {
    return null
  }
}

const requireDatabaseConfirmation = (uri, scriptName, collections, argv = process.argv) => {
  const dbName = databaseName(uri)
  const confirmArg = argv.find((a) => a.startsWith('--confirm='))
  const confirmed = confirmArg ? confirmArg.slice('--confirm='.length) : null
  if (!dbName || confirmed !== dbName) {
    console.error(`\n[BLOCKED] ${scriptName} permanently deletes all documents in: ${collections.join(', ')}`)
    console.error(`Target database: ${dbName || '(could not parse MONGO_URI)'}`)
    console.error(`To proceed, re-run with:  npm run ${scriptName} -- --confirm=${dbName || '<database-name>'}\n`)
    process.exit(1)
  }
  return dbName
}

module.exports = { databaseName, requireDatabaseConfirmation }
