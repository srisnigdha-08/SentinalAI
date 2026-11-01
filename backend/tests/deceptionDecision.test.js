'use strict'
/**
 * RL-001: one persisted rotation decision per served persona. Before, every recommendation request (each rotator
 * call, each Honeypot Analytics view) drew a fresh epsilon-greedy choice, so the persona applied was one of several
 * unrecorded draws.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const DeceptionDecision = require('../models/DeceptionDecision')
const svc = require('../services/deceptionDecisionService')

let mongo
beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
  await DeceptionDecision.init() // unique indexes in place before the concurrency test
})
afterAll(async () => {
  await mongoose.disconnect()
  await mongo.stop()
})
afterEach(() => DeceptionDecision.deleteMany({}))

// A learner whose every draw differs, so a re-draw would be visible
const drawing = () => {
  const order = ['debian_11', 'raspberry_pi', 'aws_ec2', 'ubuntu_22']
  let n = 0
  const fn = jest.fn(async () => ({
    nextProfile: order[n++ % order.length],
    explored: true,
    policy: 'q_learning',
    learnerStats: { provenance: { seedEpisodes: 4 } },
  }))
  return fn
}

test('repeated requests get the same decision; the learner is asked once', async () => {
  const recommend = drawing()
  const a = await svc.currentDecision('centos_7', { recommend })
  const b = await svc.currentDecision('centos_7', { recommend })
  const c = await svc.currentDecision('centos_7', { recommend })
  expect(recommend).toHaveBeenCalledTimes(1)
  expect(b.decision.decisionId).toBe(a.decision.decisionId)
  expect(c.decision.action).toBe(a.decision.action)
  expect([a.reused, b.reused]).toEqual([false, true])
  expect(a.decision.provenance).toEqual({ seedEpisodes: 4 })
})

test('concurrent first requests converge on one persisted decision', async () => {
  const recommend = drawing()
  const results = await Promise.all(Array.from({ length: 6 }, () => svc.currentDecision('centos_7', { recommend })))
  const ids = new Set(results.map((r) => r.decision.decisionId))
  expect(ids.size).toBe(1)
  expect(await DeceptionDecision.countDocuments({ status: 'PENDING' })).toBe(1)
})

test('applying is compare-and-set: wrong profile, wrong state or a second apply are refused', async () => {
  const { decision } = await svc.currentDecision('centos_7', { recommend: drawing() })
  await expect(svc.applyDecision(decision.decisionId, 'windows_srv', 'centos_7', 'rotator')).rejects.toMatchObject({
    statusCode: 409,
  })
  await expect(svc.applyDecision(decision.decisionId, decision.action, 'ubuntu_22', 'rotator')).rejects.toMatchObject({
    statusCode: 409,
  })
  const applied = await svc.applyDecision(decision.decisionId, decision.action, 'centos_7', 'rotator')
  expect(applied).toMatchObject({ status: 'APPLIED', appliedProfile: decision.action, appliedBy: 'rotator' })
  expect(applied.pendingLock).toBeUndefined()
  await expect(svc.applyDecision(decision.decisionId, decision.action, 'centos_7', 'rotator')).rejects.toMatchObject({
    statusCode: 409,
  })
})

test('after apply, the next request draws a new decision for the new state', async () => {
  const recommend = drawing()
  const first = (await svc.currentDecision('centos_7', { recommend })).decision
  await svc.applyDecision(first.decisionId, first.action, 'centos_7', 'rotator')
  const next = (await svc.currentDecision(first.action, { recommend })).decision
  expect(next.decisionId).not.toBe(first.decisionId)
  expect(next.state).toBe(first.action)
  expect(recommend).toHaveBeenCalledTimes(2)
})

test('a pending decision for another persona, or an expired one, is superseded and never applied', async () => {
  const recommend = drawing()
  const old = (await svc.currentDecision('centos_7', { recommend })).decision
  const fresh = (await svc.currentDecision('ubuntu_22', { recommend })).decision // someone recorded ubuntu_22
  expect((await DeceptionDecision.findOne({ decisionId: old.decisionId }).lean()).status).toBe('SUPERSEDED')
  await expect(svc.applyDecision(old.decisionId, old.action, 'centos_7', 'rotator')).rejects.toMatchObject({
    statusCode: 409,
  })
  // createdAt is immutable through Mongoose; age the decision on the raw collection
  await DeceptionDecision.collection.updateOne(
    { decisionId: fresh.decisionId },
    { $set: { createdAt: new Date(Date.now() - 3 * 3600 * 1000) } }
  )
  const renewed = (await svc.currentDecision('ubuntu_22', { recommend })).decision
  expect(renewed.decisionId).not.toBe(fresh.decisionId)
  expect((await DeceptionDecision.findOne({ decisionId: fresh.decisionId }).lean()).status).toBe('SUPERSEDED')
})

test('a failed application is recorded and frees the slot for a new draw', async () => {
  const recommend = drawing()
  const d = (await svc.currentDecision('centos_7', { recommend })).decision
  const failed = await svc.failDecision(d.decisionId, 'restart failed')
  expect(failed).toMatchObject({ status: 'FAILED', failureReason: 'restart failed' })
  await expect(svc.failDecision(d.decisionId, 'again')).rejects.toMatchObject({ statusCode: 409 })
  const next = (await svc.currentDecision('centos_7', { recommend })).decision
  expect(next.decisionId).not.toBe(d.decisionId)
})

test('engine unreachable: no decision is invented', async () => {
  expect(await svc.currentDecision('centos_7', { recommend: async () => null })).toBeNull()
  expect(await DeceptionDecision.countDocuments({})).toBe(0)
})
