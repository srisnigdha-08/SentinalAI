import test from 'node:test'
import assert from 'node:assert/strict'
import { feedThreatsToRecover } from '../src/utils/liveFeedSync.js'

const t = (id, iso) => ({ _id: id, createdAt: iso, sourceIP: '198.51.100.1', attackType: 'DDoS' })

test('only threats newer than the newest seen and not yet shown are recovered, newest first', () => {
  const recent = [t('c', '2026-11-03T10:00:03Z'), t('b', '2026-11-03T10:00:02Z'), t('a', '2026-11-03T10:00:01Z'), t('d', '2026-11-03T10:00:04Z')]
  const newestSeen = Date.parse('2026-11-03T10:00:01Z')
  assert.deepEqual(feedThreatsToRecover(recent, new Set(['a']), newestSeen).map((x) => x._id), ['d', 'c', 'b'])
})

test('a threat already delivered live is never added again (no duplicates)', () => {
  const recent = [t('x', '2026-11-03T10:00:05Z'), t('y', '2026-11-03T10:00:06Z')]
  assert.deepEqual(feedThreatsToRecover(recent, new Set(['x', 'y']), null), [])
})

test('older threats never reappear at the top of the feed', () => {
  const recent = [t('old', '2026-11-03T09:00:00Z')]
  assert.deepEqual(feedThreatsToRecover(recent, new Set(), Date.parse('2026-11-03T10:00:00Z')), [])
})

test('an empty feed takes whatever the bounded list returns; malformed input is ignored', () => {
  assert.equal(feedThreatsToRecover([t('a', '2026-11-03T10:00:00Z')], new Set(), null).length, 1)
  assert.deepEqual(feedThreatsToRecover(undefined, new Set(), null), [])
  assert.deepEqual(feedThreatsToRecover([{ createdAt: '2026-11-03T10:00:00Z' }, t('z', 'not a date')], new Set(), null), [])
})

test('rows are kept newest first; a recovered older row goes below newer live rows', async () => {
  const { insertByTime } = await import('../src/utils/liveFeedSync.js')
  const feed = [{ id: 'live', at: 3000 }, { id: 'old', at: 1000 }]
  assert.deepEqual(insertByTime(feed, [{ id: 'missed', at: 2000 }], 30).map((r) => r.id), ['live', 'missed', 'old'])
  assert.deepEqual(insertByTime(feed, [{ id: 'new', at: 4000 }], 2).map((r) => r.id), ['new', 'live']) // bounded
  assert.deepEqual(insertByTime([{ id: 'a', at: 5 }], [{ id: 'b', at: 5 }], 30).map((r) => r.id), ['b', 'a']) // tie: newest added first
})

test('a missed threat created in the same millisecond as the newest seen one is still recovered', () => {
  const at = '2026-11-03T10:00:00.000Z'
  assert.deepEqual(feedThreatsToRecover([t('same', at)], new Set(['seen']), Date.parse(at)).map((x) => x._id), ['same'])
})
