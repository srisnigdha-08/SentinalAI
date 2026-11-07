'use strict'
/**
 * F-08: transactionHelper branches not reached by the database suites: a topology probe that throws, an absent
 * client, and the abort path (session ended, error rethrown). The real replica-set path is covered end-to-end in
 * multiDocumentFaults.test.js.
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
const mongoose = require('mongoose')
const helper = require('../utils/transactionHelper')

const ORIGINAL = process.env.MONGO_USE_TRANSACTIONS
const conn = mongoose.connection
const savedClient = Object.getOwnPropertyDescriptor(conn, 'client')
// connection.client is a plain property: replace it for one test, restore it afterwards
const setClient = (descriptor) => Object.defineProperty(conn, 'client', { configurable: true, ...descriptor })
afterEach(() => {
  jest.restoreAllMocks()
  if (savedClient) Object.defineProperty(conn, 'client', savedClient)
  else delete conn.client
  if (ORIGINAL === undefined) delete process.env.MONGO_USE_TRANSACTIONS
  else process.env.MONGO_USE_TRANSACTIONS = ORIGINAL
})

test('no client / no topology: transactions not supported', () => {
  setClient({ value: undefined })
  expect(helper.serverSupportsTransactions()).toBe(false)
})

test('a topology probe that throws is treated as "not supported", never as supported', () => {
  setClient({
    get() {
      throw new Error('client torn down')
    },
  })
  expect(helper.serverSupportsTransactions()).toBe(false)
})

test.each([
  ['ReplicaSetWithPrimary', true],
  ['Sharded', true],
  ['ReplicaSetNoPrimary', false],
  ['Single', false],
])('topology %s -> supported %s', (type, expected) => {
  setClient({ value: { topology: { description: { type } } } })
  expect(helper.serverSupportsTransactions()).toBe(expected)
})

test('transaction path: an error inside the transaction is rethrown and the session is always ended', async () => {
  process.env.MONGO_USE_TRANSACTIONS = 'true'
  setClient({ value: { topology: { description: { type: 'Sharded' } } } })
  const session = {
    withTransaction: jest.fn(async (fn) => fn()),
    endSession: jest.fn().mockResolvedValue(undefined),
  }
  jest.spyOn(mongoose, 'startSession').mockResolvedValue(session)
  const fallbackFn = jest.fn()
  await expect(
    helper.runWithTransactionOrFallback({
      transactionFn: async () => {
        throw new Error('audit write failed')
      },
      fallbackFn,
    })
  ).rejects.toThrow('audit write failed')
  expect(session.endSession).toHaveBeenCalledTimes(1)
  expect(fallbackFn).not.toHaveBeenCalled() // a failed transaction never falls through to the compensating path
})

test('transaction path: the result of transactionFn is returned', async () => {
  process.env.MONGO_USE_TRANSACTIONS = 'true'
  setClient({ value: { topology: { description: { type: 'Sharded' } } } })
  const session = { withTransaction: jest.fn(async (fn) => fn()), endSession: jest.fn().mockResolvedValue() }
  jest.spyOn(mongoose, 'startSession').mockResolvedValue(session)
  await expect(
    helper.runWithTransactionOrFallback({
      transactionFn: async (s) => (s === session ? 'ok' : 'wrong'),
      fallbackFn: jest.fn(),
    })
  ).resolves.toBe('ok')
})
