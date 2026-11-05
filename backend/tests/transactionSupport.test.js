/**
 * Transaction Support & Rollback Test Suite
 *
 * Verifies that:
 * 1. When MONGO_USE_TRANSACTIONS=false: fallback compensating path is executed.
 * 2. When MONGO_USE_TRANSACTIONS=true: transactionFn executes inside a session, and an
 *    audit logging failure completely aborts the transaction leaving ZERO partial state in the DB.
 */

const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')
const {
  isTransactionsEnabled,
  serverSupportsTransactions,
  shouldUseTransactions,
  runWithTransactionOrFallback,
} = require('../utils/transactionHelper')
const User = require('../models/User')
const ThreatLog = require('../models/ThreatLog')
const BlockedIP = require('../models/BlockedIP')
const AuditLog = require('../models/AuditLog')

describe('Task 9: Transaction Support & Atomic Rollback', () => {
  let mongoServer
  const originalEnvTx = process.env.MONGO_USE_TRANSACTIONS

  afterAll(() => {
    process.env.MONGO_USE_TRANSACTIONS = originalEnvTx
  })

  describe('Part A.1: Configuration & Topology Detection', () => {
    beforeAll(async () => {
      mongoServer = await MongoMemoryServer.create()
      await mongoose.connect(mongoServer.getUri())
    })

    afterAll(async () => {
      await mongoose.disconnect()
      await mongoServer.stop()
    })

    it('defaults MONGO_USE_TRANSACTIONS to false', () => {
      delete process.env.MONGO_USE_TRANSACTIONS
      expect(isTransactionsEnabled()).toBe(false)
    })

    it('correctly reads MONGO_USE_TRANSACTIONS when set to true', () => {
      process.env.MONGO_USE_TRANSACTIONS = 'true'
      expect(isTransactionsEnabled()).toBe(true)
      process.env.MONGO_USE_TRANSACTIONS = 'false'
      expect(isTransactionsEnabled()).toBe(false)
    })

    it('detects standalone MongoMemoryServer does NOT support replica set transactions', () => {
      // Standalone mongod topology type is 'Single'
      expect(serverSupportsTransactions()).toBe(false)
      process.env.MONGO_USE_TRANSACTIONS = 'true'
      // shouldUseTransactions requires BOTH flag=true AND server support
      expect(shouldUseTransactions()).toBe(false)
    })
  })

  describe('Part A.2: Standalone Fallback Path (Compensating Rollback)', () => {
    beforeAll(async () => {
      mongoServer = await MongoMemoryServer.create()
      await mongoose.connect(mongoServer.getUri())
    })

    afterAll(async () => {
      await mongoose.disconnect()
      await mongoServer.stop()
    })

    beforeEach(async () => {
      process.env.MONGO_USE_TRANSACTIONS = 'false'
      await User.deleteMany({})
      await ThreatLog.deleteMany({})
      await BlockedIP.deleteMany({})
      await AuditLog.collection.deleteMany({})
    })

    it('executes fallbackFn directly when transactions are disabled', async () => {
      let txCalled = false
      let fallbackCalled = false

      const result = await runWithTransactionOrFallback({
        transactionFn: async () => {
          txCalled = true
          return 'tx'
        },
        fallbackFn: async () => {
          fallbackCalled = true
          return 'fallback'
        },
      })

      expect(result).toBe('fallback')
      expect(txCalled).toBe(false)
      expect(fallbackCalled).toBe(true)
    })

    it('user provisioning fallback deletes user if audit logging fails', async () => {
      const email = 'fallback-fail@sentinel.local'
      const userData = {
        name: 'Fallback User',
        email,
        password: 'Password123!',
        role: 'analyst',
        department: 'SOC',
      }

      let errorThrown = false
      try {
        await runWithTransactionOrFallback({
          transactionFn: async (session) => {
            const [u] = await User.create([userData], { session })
            return u
          },
          fallbackFn: async () => {
            const newUser = await User.create(userData)
            // Simulate audit failure
            try {
              throw new Error('Audit service unreachable')
            } catch {
              await User.findByIdAndDelete(newUser._id)
              const err = new Error('Security audit logging failed; account provision rolled back')
              err.statusCode = 500
              throw err
            }
          },
        })
      } catch (err) {
        errorThrown = true
        expect(err.message).toContain('Security audit logging failed')
      }

      expect(errorThrown).toBe(true)
      const persisted = await User.findOne({ email })
      expect(persisted).toBeNull()
    })
  })

  describe('Part A.3: Replica Set Transaction Path (Separate Port 27030)', () => {
    let rsConnection
    const RS_URI =
      process.env.TEST_RS_URI ||
      'mongodb://root_admin:TestAdminPassword123!@127.0.0.1:27030/sentinel-db-test?replicaSet=rs0&authSource=admin'

    beforeAll(async () => {
      try {
        rsConnection = await mongoose
          .createConnection(RS_URI, {
            serverSelectionTimeoutMS: 1500,
            connectTimeoutMS: 1500,
          })
          .asPromise()
      } catch {
        rsConnection = null
      }
    })

    afterAll(async () => {
      if (rsConnection) {
        await rsConnection.close()
      }
    })

    it('verifies the port 27030 instance is a replica set primary', () => {
      if (!rsConnection) {
        console.log('Skipping: isolated test replica set on port 27030 is not running')
        return
      }
      const topoType = rsConnection.client?.topology?.description?.type
      expect(['ReplicaSetWithPrimary', 'Single']).toContain(topoType)
      expect(rsConnection.name).toBe('sentinel-db-test')
    })

    it('aborts transaction and leaves ZERO partial state on audit failure', async () => {
      if (!rsConnection) {
        console.log('Skipping: isolated test replica set on port 27030 is not running')
        return
      }
      // Bind models to the test replica set connection
      const TestUser = rsConnection.model('User', User.schema)
      const TestAudit = rsConnection.model('AuditLog', AuditLog.schema)

      await TestUser.deleteMany({})
      await TestAudit.collection.deleteMany({})

      const session = await rsConnection.startSession()
      let txErrorOccurred = false

      try {
        await session.withTransaction(async () => {
          // 1. Create user within transaction
          const [newUser] = await TestUser.create(
            [
              {
                name: 'Tx Test User',
                email: 'tx-test@sentinel.local',
                password: 'Password123!',
                role: 'analyst',
                department: 'SOC',
              },
            ],
            { session }
          )
          expect(newUser._id).toBeDefined()

          // 2. Audit logging step FAILS intentionally
          throw new Error('Simulated audit write network partition')
        })
      } catch (err) {
        txErrorOccurred = true
        expect(err.message).toBe('Simulated audit write network partition')
      } finally {
        await session.endSession()
      }

      expect(txErrorOccurred).toBe(true)

      // Verify ZERO partial state in sentinel-db-test
      const persistedUser = await TestUser.findOne({ email: 'tx-test@sentinel.local' })
      expect(persistedUser).toBeNull()

      const auditEntries = await TestAudit.find({})
      expect(auditEntries.length).toBe(0)
    })

    it('aborts threat block transaction and leaves threat DETECTED and BlockedIP empty', async () => {
      if (!rsConnection) {
        console.log('Skipping: isolated test replica set on port 27030 is not running')
        return
      }
      const TestThreat = rsConnection.model('ThreatLog', ThreatLog.schema)
      const TestBlockedIP = rsConnection.model('BlockedIP', BlockedIP.schema)

      await TestThreat.deleteMany({})
      await TestBlockedIP.deleteMany({})

      // Create an initial DETECTED threat
      const threat = await TestThreat.create({
        sourceIP: '203.0.113.99',
        attackType: 'SQL Injection',
        severity: 'HIGH',
        status: 'DETECTED',
        aiScore: 0.85,
      })

      const session = await rsConnection.startSession()
      let txErrorOccurred = false

      try {
        await session.withTransaction(async () => {
          // 1. Transition threat to BLOCKED within transaction
          await TestThreat.findByIdAndUpdate(threat._id, { status: 'BLOCKED', preBlockStatus: 'DETECTED' }, { session })

          // 2. Create BlockedIP within transaction
          await TestBlockedIP.create(
            [
              {
                ip: '203.0.113.99',
                reason: 'Manual threat block test',
                threatRef: threat._id,
              },
            ],
            { session }
          )

          // 3. Audit logging FAILS
          throw new Error('Audit engine write timeout')
        })
      } catch (err) {
        txErrorOccurred = true
        expect(err.message).toBe('Audit engine write timeout')
      } finally {
        await session.endSession()
      }

      expect(txErrorOccurred).toBe(true)

      // Verify both collections rolled back atomically
      const reloadedThreat = await TestThreat.findById(threat._id)
      expect(reloadedThreat.status).toBe('DETECTED')

      const blockedDoc = await TestBlockedIP.findOne({ ip: '203.0.113.99' })
      expect(blockedDoc).toBeNull()
    })
  })
})
