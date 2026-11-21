'use strict'
// M3 (compound indexes) and L8 (keyset pagination) for the threat list, on a disposable in-memory MongoDB.
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')
const ThreatLog = require('../models/ThreatLog')
const { findThreats } = require('../services/threatService')

let server
const base = new Date('2026-11-01T00:00:00Z').getTime()

beforeAll(async () => {
  server = await MongoMemoryServer.create()
  await mongoose.connect(server.getUri())
  await ThreatLog.syncIndexes()
  const docs = []
  for (let i = 0; i < 45; i++) {
    docs.push({
      severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'][i % 4],
      status: i % 9 === 0 ? 'BLOCKED' : 'MONITORING',
      attackType: i % 2 ? 'DDoS' : 'Port Scan',
      sourceIP: `203.0.113.${i % 50}`,
      aiScore: 0.9,
      // Groups of three share one timestamp, so the _id tie-breaker decides their order.
      createdAt: new Date(base + Math.floor(i / 3) * 60000),
    })
  }
  await ThreatLog.collection.insertMany(docs) // raw insert keeps the shared timestamps
})

afterAll(async () => {
  await mongoose.disconnect()
  await server.stop()
})

const walk = async (query) => {
  const ids = []
  let cursor
  for (let guard = 0; guard < 20; guard++) {
    const r = await findThreats({ ...query, limit: 10, ...(cursor ? { after: cursor } : {}) })
    ids.push(...r.data.map((d) => String(d._id)))
    if (!r.nextCursor) break
    cursor = r.nextCursor
  }
  return ids
}

const byPages = async (query) => {
  const ids = []
  for (let page = 1; page <= 10; page++) {
    const r = await findThreats({ ...query, limit: 10, page })
    if (!r.data.length) break
    ids.push(...r.data.map((d) => String(d._id)))
  }
  return ids
}

test('cursor pages return every row once, in the same order as page numbers, across equal timestamps', async () => {
  const viaCursor = await walk({})
  expect(viaCursor).toHaveLength(45)
  expect(new Set(viaCursor).size).toBe(45)
  expect(viaCursor).toEqual(await byPages({}))
})

test('the cursor combines with filters and search, and total stays the filtered total', async () => {
  const blocked = await walk({ status: 'BLOCKED' })
  expect(blocked).toHaveLength(5)
  const first = await findThreats({ type: 'DDoS', search: '203.0.113', limit: 10 })
  expect(first.total).toBe(22)
  const second = await findThreats({ type: 'DDoS', search: '203.0.113', limit: 10, after: first.nextCursor })
  expect(second.total).toBe(22)
  expect(second.data.map((d) => String(d._id))).not.toContain(String(first.data[0]._id))
})

test('the last page has no nextCursor; other sort orders have none either', async () => {
  const last = await findThreats({ status: 'BLOCKED', limit: 10 })
  expect(last.nextCursor).toBeNull()
  expect((await findThreats({ sortBy: 'aiScore', limit: 10 })).nextCursor).toBeNull()
})

test('malformed or misused cursors are refused with 400', async () => {
  const bad = [
    'not base64!',
    Buffer.from('{"t":"yesterday","id":"x"}').toString('base64url'),
    Buffer.from('{"t":"2026-11-01T00:00:00Z","id":{"$ne":null}}').toString('base64url'),
    'a'.repeat(300),
    ['x', 'y'],
  ]
  for (const after of bad) await expect(findThreats({ after })).rejects.toMatchObject({ statusCode: 400 })
  const ok = (await findThreats({ limit: 10 })).nextCursor
  await expect(findThreats({ sortBy: 'aiScore', after: ok })).rejects.toMatchObject({ statusCode: 400 })
})

describe('query plans use the compound indexes without an in-memory sort', () => {
  const plan = async (filter) => {
    const e = await ThreatLog.find(filter).sort({ createdAt: -1, _id: -1 }).limit(10).explain('queryPlanner')
    const stages = []
    const walkPlan = (s) => {
      if (!s) return
      stages.push(s.stage + (s.indexName ? `(${s.indexName})` : ''))
      walkPlan(s.inputStage)
      ;(s.inputStages || []).forEach(walkPlan)
    }
    const winning = e.queryPlanner.winningPlan
    walkPlan(winning.queryPlan || winning)
    return stages
  }
  test.each([
    [{}, 'createdAt_-1__id_-1'],
    [{ status: 'BLOCKED' }, 'status_1_createdAt_-1__id_-1'],
    [{ severity: 'HIGH' }, 'severity_1_createdAt_-1__id_-1'],
    [{ attackType: 'DDoS' }, 'attackType_1_createdAt_-1__id_-1'],
  ])('%j', async (filter, index) => {
    const stages = await plan(filter)
    expect(stages).toContain(`IXSCAN(${index})`)
    expect(stages).not.toContain('SORT')
    expect(stages).not.toContain('COLLSCAN')
  })
})
