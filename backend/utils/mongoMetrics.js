'use strict'
/**
 * M9: MongoDB visibility on GET /metrics, from the driver's own monitoring events (config/db.js connects with
 * monitorCommands: true and calls instrument() once).
 *
 *   sentinel_mongo_commands_total{command}                  operations by type (find, insert, aggregate, ...)
 *   sentinel_mongo_command_duration_seconds_sum{command}    total time per type (divide by the count for a mean)
 *   sentinel_mongo_command_failures_total{command}          failed operations (driver or server error)
 *   sentinel_mongo_slow_commands_total{command}             operations slower than MONGO_SLOW_MS (default 500)
 *   sentinel_mongo_pool_connections_open / _in_use / _waiting   connection-pool gauges
 *   sentinel_mongo_pool_checkout_failures_total             no connection became available in time
 *
 * Slow operations are also logged with their type, collection and duration only: never the filter, update or any
 * document value, which can hold IP addresses, credentials or attacker data. Driver heartbeats (hello, ping, ...)
 * are not counted, so the series describe the application's own work.
 */
const metrics = require('./metrics')
const logger = require('./logger')

const COUNTED = new Set([
  'find',
  'getMore',
  'insert',
  'update',
  'delete',
  'findAndModify',
  'aggregate',
  'count',
  'distinct',
  'createIndexes',
  'dropIndexes',
  'listIndexes',
  'listCollections',
  'create',
  'drop',
  'commitTransaction',
  'abortTransaction',
])
const MAX_IN_FLIGHT = 10000

const slowMs = () => {
  const n = parseInt(process.env.MONGO_SLOW_MS, 10)
  return Number.isInteger(n) && n > 0 ? n : 500
}

const instrumented = new WeakSet()
const pool = { open: 0, inUse: 0, waiting: 0 }

function instrument(client) {
  if (!client || instrumented.has(client)) return false
  instrumented.add(client)
  const inFlight = new Map() // requestId -> collection, for the slow-operation log only

  client.on('commandStarted', (e) => {
    if (!COUNTED.has(e.commandName)) return
    const target = e.command?.[e.commandName]
    if (inFlight.size < MAX_IN_FLIGHT) inFlight.set(e.requestId, typeof target === 'string' ? target : '')
  })
  client.on('commandSucceeded', (e) => {
    if (!COUNTED.has(e.commandName)) return
    const labels = { command: e.commandName }
    const collection = inFlight.get(e.requestId) || ''
    inFlight.delete(e.requestId)
    metrics.inc('sentinel_mongo_commands_total', 'MongoDB operations by command', labels)
    metrics.inc(
      'sentinel_mongo_command_duration_seconds_sum',
      'Total MongoDB operation time by command',
      labels,
      e.duration / 1000
    )
    if (e.duration >= slowMs()) {
      metrics.inc('sentinel_mongo_slow_commands_total', 'MongoDB operations slower than MONGO_SLOW_MS', labels)
      logger.warn(
        `[MongoDB] slow ${e.commandName}${collection ? ' on ' + collection : ''}: ${Math.round(e.duration)} ms`
      )
    }
  })
  client.on('commandFailed', (e) => {
    if (!COUNTED.has(e.commandName)) return
    inFlight.delete(e.requestId)
    metrics.inc('sentinel_mongo_command_failures_total', 'Failed MongoDB operations by command', {
      command: e.commandName,
    })
  })

  client.on('connectionCreated', () => pool.open++)
  client.on('connectionClosed', () => (pool.open = Math.max(0, pool.open - 1)))
  client.on('connectionCheckOutStarted', () => pool.waiting++)
  client.on('connectionCheckedOut', () => {
    pool.waiting = Math.max(0, pool.waiting - 1)
    pool.inUse++
  })
  client.on('connectionCheckOutFailed', () => {
    pool.waiting = Math.max(0, pool.waiting - 1)
    metrics.inc('sentinel_mongo_pool_checkout_failures_total', 'MongoDB connection checkouts that failed or timed out')
  })
  client.on('connectionCheckedIn', () => (pool.inUse = Math.max(0, pool.inUse - 1)))

  metrics.gauge('sentinel_mongo_pool_connections_open', 'Open MongoDB pool connections', () => pool.open)
  metrics.gauge('sentinel_mongo_pool_connections_in_use', 'MongoDB pool connections checked out', () => pool.inUse)
  metrics.gauge(
    'sentinel_mongo_pool_connections_waiting',
    'Operations waiting for a pool connection',
    () => pool.waiting
  )
  return true
}

const _reset = () => {
  pool.open = 0
  pool.inUse = 0
  pool.waiting = 0
}

module.exports = { instrument, COUNTED, _reset }
