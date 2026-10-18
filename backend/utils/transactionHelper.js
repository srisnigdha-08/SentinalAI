'use strict'

/**
 * utils/transactionHelper.js
 *
 * Task 9: Dynamic ACID Transaction & Replica Set Helper
 *
 * Provides conditional multi-document transaction execution:
 * - ACTIVE ONLY IF:
 *   1. process.env.MONGO_USE_TRANSACTIONS === 'true' (disabled by default)
 *   2. The connected MongoDB server topology supports transactions (ReplicaSet or Sharded cluster)
 * - FALLBACK:
 *   Executes the existing standalone compensating-rollback code path seamlessly
 *   when running on standalone MongoDB or when the flag is off.
 */

const mongoose = require('mongoose')
const logger = require('./logger')

function isTransactionsEnabled() {
  return process.env.MONGO_USE_TRANSACTIONS === 'true'
}

function serverSupportsTransactions() {
  try {
    const topology = mongoose.connection?.client?.topology
    if (!topology) return false
    const type = topology.description?.type
    return type === 'ReplicaSetWithPrimary' || type === 'Sharded'
  } catch {
    return false
  }
}

function shouldUseTransactions() {
  return isTransactionsEnabled() && serverSupportsTransactions()
}

/**
 * Executes a transaction if enabled and supported; otherwise calls the fallback function.
 *
 * @template T
 * @param {Object} options
 * @param {(session: import('mongoose').ClientSession) => Promise<T>} options.transactionFn - Transaction block
 * @param {() => Promise<T>} options.fallbackFn - Fallback compensating-rollback block
 * @returns {Promise<T>}
 */
async function runWithTransactionOrFallback({ transactionFn, fallbackFn }) {
  if (shouldUseTransactions()) {
    const session = await mongoose.startSession()
    try {
      let result
      await session.withTransaction(async () => {
        result = await transactionFn(session)
      })
      return result
    } catch (err) {
      logger.debug(`[Transaction] Aborted transaction: ${err.message}`)
      throw err
    } finally {
      await session.endSession()
    }
  }

  return fallbackFn()
}

module.exports = {
  isTransactionsEnabled,
  serverSupportsTransactions,
  shouldUseTransactions,
  runWithTransactionOrFallback,
}
