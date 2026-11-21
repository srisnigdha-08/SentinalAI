// Threat Logs "Export CSV": builds the file in the browser from GET /api/threats (no export endpoint exists).
// Rows are exactly what the API returns for the current filters, so server-side role redaction (viewer IP masking)
// carries into the file. Cells are escaped for CSV and neutralised against spreadsheet formula injection.
import { threatEvidenceLabel } from './threatEvidence.js'
import { tacticText } from './mitreTactics.js'
import { REPORT_TIME_ZONE } from './reportingTime.js'

export const EXPORT_PAGE_SIZE = 100 // the API's maximum page size
export const EXPORT_MAX_ROWS = 5000 // 50 requests at most, far below the API rate limit

const FORMULA_START = /^[=+\-@\t\r]/

/** One CSV cell: quotes doubled, field quoted when needed, and text that a spreadsheet would run as a formula
 *  prefixed with an apostrophe. Numbers are left as numbers. */
export function csvCell(value) {
  if (value === null || value === undefined) return ''
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : ''
  let s = String(value)
  if (FORMULA_START.test(s)) s = `'${s}`
  return /[",\r\n]/.test(s) || s !== s.trim() ? `"${s.replace(/"/g, '""')}"` : s
}

const istText = (v) => {
  const d = new Date(v)
  if (Number.isNaN(d.getTime())) return ''
  return d.toLocaleString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12: false })
}

const isoText = (v) => {
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? '' : d.toISOString()
}

const mitreText = (t) => (Array.isArray(t.mitreTechniques) ? t.mitreTechniques : [])
  .map((m) => [m?.id, m?.name].filter(Boolean).join(' - ') + (m ? ` (${tacticText(m)})` : ''))
  .filter(Boolean)
  .join('; ')

const intelText = (i) => {
  if (!i) return ''
  if (i.status && i.status !== 'ok' && i.status !== 'OK') return String(i.status)
  const parts = []
  if (i.abuseConfidenceScore !== undefined && i.abuseConfidenceScore !== null) parts.push(`abuse ${i.abuseConfidenceScore}%`)
  if (i.totalReports !== undefined && i.totalReports !== null) parts.push(`${i.totalReports} reports`)
  if (i.isp) parts.push(i.isp)
  return parts.join(', ') || (i.status ? String(i.status) : '')
}

export const THREAT_CSV_COLUMNS = Object.freeze([
  ['Detected (UTC ISO 8601)', (t) => isoText(t.createdAt)],
  ['Detected (IST)', (t) => istText(t.createdAt)],
  ['Severity', (t) => t.severity],
  ['Source IP', (t) => t.sourceIP],
  ['Attack Type', (t) => t.attackType],
  ['Evidence Note', (t) => threatEvidenceLabel(t) || ''],
  ['Target', (t) => t.targetService],
  ['Threat Score (%)', (t) => (typeof t.aiScore === 'number' ? Math.round(t.aiScore * 100) : '')],
  ['Status', (t) => t.status],
  ['MITRE ATT&CK', mitreText],
  ['Threat Intel', (t) => intelText(t.threatIntel)],
  ['Threat ID', (t) => t._id || t.id],
])

/** CSV text (with a UTF-8 BOM so Excel reads non-ASCII correctly) for a list of threat records. */
export function threatsCsv(threats) {
  const lines = [THREAT_CSV_COLUMNS.map(([h]) => csvCell(h)).join(',')]
  for (const t of threats || []) {
    if (!t || typeof t !== 'object') continue
    lines.push(THREAT_CSV_COLUMNS.map(([, get]) => csvCell(get(t))).join(','))
  }
  return '\uFEFF' + lines.join('\r\n') + '\r\n'
}

/**
 * Fetches every page for `filters` through `listPage(params)` (threatAPI.list) up to EXPORT_MAX_ROWS.
 * Returns { rows, total, truncated }. Stops early on an empty or short page; a failed request rejects.
 */
export async function fetchAllThreats(listPage, filters = {}, { pageSize = EXPORT_PAGE_SIZE, maxRows = EXPORT_MAX_ROWS } = {}) {
  const rows = []
  let total = null
  for (let page = 1; rows.length < maxRows; page++) {
    const res = await listPage({ ...filters, page, limit: pageSize, sortBy: 'createdAt', sortOrder: 'desc' })
    const data = Array.isArray(res?.data?.data) ? res.data.data : []
    const reported = Number(res?.data?.pagination?.total)
    if (Number.isFinite(reported)) total = reported
    rows.push(...data)
    if (data.length < pageSize || (total !== null && rows.length >= total)) break
  }
  const kept = rows.slice(0, maxRows)
  const known = total ?? rows.length
  return { rows: kept, total: known, truncated: known > kept.length }
}

/** File name such as sentinelai-threats-2026-11-20-high.csv (IST date; filter values are sanitised). */
export function threatCsvFilename(filters = {}, now = new Date()) {
  const day = now.toLocaleDateString('en-CA', { timeZone: REPORT_TIME_ZONE })
  const tag = [filters.severity, filters.type].filter(Boolean).join('-').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
  return `sentinelai-threats-${day}${tag ? `-${tag.slice(0, 40)}` : ''}.csv`
}
