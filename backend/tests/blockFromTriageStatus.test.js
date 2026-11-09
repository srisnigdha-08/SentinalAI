'use strict'
/**
 * A threat an analyst marked INVESTIGATING (or CONTAINED) can be blocked, and unblocking restores that status.
 * Before the fix, preBlockStatus rejected both values, so the Block button failed with a validation error on
 * exactly the threats an analyst was working on (found by the Firefox/WebKit E2E runs, dashboard.spec.js).
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const ThreatLog = require('../models/ThreatLog')
const BlockedIP = require('../models/BlockedIP')
const containment = require('../services/containmentService')

let mongo
beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
})
afterAll(async () => {
  await mongoose.disconnect()
  await mongo.stop()
})
afterEach(async () => {
  await ThreatLog.deleteMany({})
  await BlockedIP.deleteMany({})
})

test.each(['INVESTIGATING', 'CONTAINED'])('blocking a %s threat succeeds and unblock restores it', async (status) => {
  const threat = await ThreatLog.create({
    severity: 'HIGH',
    sourceIP: '198.51.100.71',
    attackType: 'SQL Injection',
    aiScore: 0.82,
    status,
  })
  const analyst = new mongoose.Types.ObjectId()

  const blocked = await containment.blockThreat(threat._id, analyst)
  expect(blocked.status).toBe('BLOCKED')
  expect(blocked.preBlockStatus).toBe(status)
  expect(await BlockedIP.exists({ ip: '198.51.100.71' })).toBeTruthy()

  await containment.unblockIPManual({ ip: '198.51.100.71' })
  const restored = await ThreatLog.findById(threat._id)
  expect(restored.status).toBe(status)
  expect(restored.preBlockStatus).toBeNull()
})

test('preBlockStatus accepts every status a block may start from', () => {
  const blockable = ThreatLog.schema
    .path('status')
    .enumValues.filter((s) => !['BLOCKED', 'RESOLVED', 'FALSE_POSITIVE'].includes(s))
  for (const s of blockable) {
    const doc = new ThreatLog({
      severity: 'LOW',
      sourceIP: '198.51.100.72',
      attackType: 'Port Scan',
      preBlockStatus: s,
    })
    expect(doc.validateSync()?.errors?.preBlockStatus).toBeUndefined()
  }
})
