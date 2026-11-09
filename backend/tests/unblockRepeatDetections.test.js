'use strict'
/**
 * CONT-001 (found in the batch 15 demo rehearsal): when an address had been detected more than once, an auto-block
 * tagged every open threat for it with the ContainmentAction id, but Settings → Unblock IP restored only threats
 * tagged with the BlockedIP id (plus its single threatRef). The other detections stayed BLOCKED although the address
 * was no longer contained. Threats from an older, already finished containment must still be left alone (TEST 14).
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const ThreatLog = require('../models/ThreatLog')
const BlockedIP = require('../models/BlockedIP')
const ContainmentAction = require('../models/ContainmentAction')
const containment = require('../services/containmentService')

const IP = '198.51.100.73'
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
  await Promise.all([ThreatLog.deleteMany({}), BlockedIP.deleteMany({}), ContainmentAction.deleteMany({})])
})

const threat = (status, extra = {}) =>
  ThreatLog.create({ severity: 'CRITICAL', sourceIP: IP, attackType: 'DDoS', aiScore: 0.99, status, ...extra })

test('unblocking an auto-blocked address restores every detection the active containment blocked', async () => {
  const earlier = await threat('MONITORING') // first detection, before auto-block was enabled
  const trigger = await threat('DETECTED') // the detection that triggers the auto-block

  const res = await containment.executeAutoBlock({ threat: trigger, threatScore: 0.99 })
  expect(res.success).toBe(true)
  expect((await ThreatLog.findById(earlier._id)).status).toBe('BLOCKED')
  expect((await ThreatLog.findById(trigger._id)).status).toBe('BLOCKED')

  // What Settings → Unblock IP does (threatController.unblockIPManual)
  await containment.unblockIPManual({ ip: IP })
  await containment.releaseManualBlock({ ip: IP, operator: null })

  const e = await ThreatLog.findById(earlier._id)
  const t = await ThreatLog.findById(trigger._id)
  expect([e.status, t.status]).toEqual(['MONITORING', 'DETECTED'])
  expect([e.containmentId, t.containmentId]).toEqual([null, null])
  expect(e.autonomousAction.taken).toBe(false)
  expect(await BlockedIP.exists({ ip: IP })).toBeNull()
  expect(await ContainmentAction.countDocuments({ normalizedTarget: IP, enforcementStatus: 'ACTIVE' })).toBe(0)
})

test('a threat blocked by an older, finished containment is still left alone (historical protection)', async () => {
  const oldAction = new mongoose.Types.ObjectId() // a containment that no longer exists or is long rolled back
  const historical = await threat('BLOCKED', { preBlockStatus: 'MONITORING', containmentId: oldAction })
  const trigger = await threat('DETECTED')

  await containment.executeAutoBlock({ threat: trigger, threatScore: 0.99 })
  await containment.unblockIPManual({ ip: IP })
  await containment.releaseManualBlock({ ip: IP, operator: null })

  const h = await ThreatLog.findById(historical._id)
  expect(h.status).toBe('BLOCKED')
  expect(String(h.containmentId)).toBe(String(oldAction))
  expect((await ThreatLog.findById(trigger._id)).status).toBe('DETECTED')
})
