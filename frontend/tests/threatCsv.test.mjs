import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { csvCell, threatsCsv, fetchAllThreats, threatCsvFilename, THREAT_CSV_COLUMNS, EXPORT_MAX_ROWS } from '../src/utils/threatCsv.js'

test('cells are CSV-escaped', () => {
  assert.equal(csvCell('plain'), 'plain')
  assert.equal(csvCell('a,b'), '"a,b"')
  assert.equal(csvCell('say "hi"'), '"say ""hi"""')
  assert.equal(csvCell('two\nlines'), '"two\nlines"')
  assert.equal(csvCell(' padded '), '" padded "')
  assert.equal(csvCell(null), '')
  assert.equal(csvCell(undefined), '')
  assert.equal(csvCell(42), '42')
  assert.equal(csvCell(NaN), '')
})

test('text a spreadsheet would execute as a formula is neutralised', () => {
  for (const evil of ['=HYPERLINK("http://x")', '+1+1', '-2+3', '@SUM(A1)', '\tcmd'])
    assert.ok(csvCell(evil).replace(/^"/, '').startsWith("'"), evil)
  assert.equal(csvCell(-5), '-5') // real numbers stay numeric
})

test('a threat row maps to the documented columns', () => {
  const csv = threatsCsv([{
    _id: 't1', createdAt: '2026-11-20T10:39:14.000Z', severity: 'LOW', sourceIP: '172.29.32.17',
    attackType: 'SSH Brute Force', targetService: 'SSH-COWRIE-01', aiScore: 0.4, status: 'BLOCKED',
    notes: '[HONEYPOT_RULES_RECLASSIFIED] x',
    mitreTechniques: [{ id: 'T1110', name: 'Brute Force' }],
    threatIntel: { abuseConfidenceScore: 80, totalReports: 3, isp: 'Example, Inc' },
  }])
  assert.ok(csv.startsWith('\uFEFF'))
  const [header, row, end] = csv.slice(1).split('\r\n')
  assert.equal(header.split(',').length, THREAT_CSV_COLUMNS.length)
  assert.equal(end, '')
  assert.match(row, /^2026-11-20T10:39:14\.000Z,"20\/11\/2026, 16:09:14",LOW,172\.29\.32\.17,SSH Brute Force,/)
  assert.match(row, /Rule-reclassified after session-open heuristic,SSH-COWRIE-01,40,BLOCKED,T1110 - Brute Force \(Credential Access\),"abuse 80%, 3 reports, Example, Inc",t1$/)
})

test('missing or malformed fields export as empty cells, never as invented values', () => {
  const [, row] = threatsCsv([{ createdAt: 'not a date' }, null]).slice(1).split('\r\n')
  assert.equal(row, ','.repeat(THREAT_CSV_COLUMNS.length - 1))
})

test('every page is fetched with the active filters until the reported total', async () => {
  const calls = []
  const all = Array.from({ length: 230 }, (_, i) => ({ _id: `t${i}` }))
  const listPage = async (p) => {
    calls.push(p)
    const start = (p.page - 1) * p.limit
    return { data: { data: all.slice(start, start + p.limit), pagination: { total: all.length } } }
  }
  const r = await fetchAllThreats(listPage, { severity: 'HIGH', search: '10.0' })
  assert.equal(r.rows.length, 230)
  assert.equal(r.truncated, false)
  assert.deepEqual(calls.map((c) => c.page), [1, 2, 3])
  for (const c of calls) {
    assert.equal(c.severity, 'HIGH')
    assert.equal(c.search, '10.0')
    assert.equal(c.limit, 100)
  }
})

test('large exports stop at the row cap and say so', async () => {
  let n = 0
  const listPage = async (p) => { n++; return { data: { data: Array.from({ length: p.limit }, () => ({})), pagination: { total: 99999 } } } }
  const r = await fetchAllThreats(listPage, {})
  assert.equal(r.rows.length, EXPORT_MAX_ROWS)
  assert.equal(r.truncated, true)
  assert.equal(r.total, 99999)
  assert.equal(n, EXPORT_MAX_ROWS / 100)
})

test('a failed page rejects instead of producing a partial file', async () => {
  const listPage = async (p) => { if (p.page === 2) throw new Error('boom'); return { data: { data: Array(100).fill({}), pagination: { total: 300 } } } }
  await assert.rejects(fetchAllThreats(listPage, {}), /boom/)
})

test('file names carry the IST date and sanitised filters', () => {
  const now = new Date('2026-11-20T20:00:00Z') // 21 Nov in IST
  assert.equal(threatCsvFilename({}, now), 'sentinelai-threats-2026-11-21.csv')
  assert.equal(threatCsvFilename({ severity: 'HIGH', type: 'SSH Brute/Force' }, now), 'sentinelai-threats-2026-11-21-high-ssh-brute-force.csv')
})

test('the Threat Logs button is wired to the export, not left disabled', () => {
  const page = readFileSync(new URL('../src/pages/ThreatLogs.jsx', import.meta.url), 'utf8')
  assert.match(page, /onClick={exportCsv}/)
  assert.doesNotMatch(page, /CSV export is not available yet/)
})
