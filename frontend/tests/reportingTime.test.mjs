import test from 'node:test'
import assert from 'node:assert/strict'
import { timeText, dateText } from '../src/utils/reportingTime.js'
test('browser formatting is explicit IST even when local timezone differs', () => {
  const old = process.env.TZ
  const results = ['UTC', 'Asia/Kolkata', 'America/New_York'].map(zone => {
    process.env.TZ = zone
    return [dateText('2026-12-31T18:30:00Z'), timeText('2026-12-31T18:30:00Z')]
  })
  if (old === undefined) delete process.env.TZ; else process.env.TZ = old
  assert.deepEqual(results[0], results[1]); assert.deepEqual(results[1], results[2])
  assert.equal(results[0][1], '00:00:00')
  assert.match(results[0][0], /2027/)
})
