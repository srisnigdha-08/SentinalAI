'use strict'
/**
 * Security summary report behind the Dashboard "Export Report" button. Every figure is read from the database
 * (or the live AI-engine readiness probe) at export time; nothing is estimated. The reporting window is a
 * whole number of Asia/Kolkata calendar days (utils/reportingTime), stated in the report itself.
 * The report carries no credentials, tokens, keys, captured passwords or configuration values.
 */
const reportTime = require('../utils/reportingTime')
const { PdfDocument } = require('../utils/pdfWriter')

const ALLOWED_DAYS = [1, 7, 30, 90]
const RECENT_EVENT_LIMIT = 25
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const isSyntheticSession = (sessionId) => /^demo-/i.test(String(sessionId || ''))

const countMap = (rows) => Object.fromEntries(rows.filter((r) => r._id != null).map((r) => [String(r._id), r.count]))

async function buildSecurityReport({ days = 7, now = new Date(), generatedBy = null } = {}) {
  if (!ALLOWED_DAYS.includes(days)) {
    const err = new Error(`Reporting period must be one of ${ALLOWED_DAYS.join(', ')} days`)
    err.statusCode = 400
    throw err
  }
  const ThreatLog = require('../models/ThreatLog')
  const BlockedIP = require('../models/BlockedIP')
  const ContainmentAction = require('../models/ContainmentAction')
  const HoneypotSession = require('../models/HoneypotSession')
  const Campaign = require('../models/Campaign')
  const honeypotService = require('./honeypotService')
  const aiEngineService = require('./aiEngineService')

  const period = reportTime.metadata(days, now)
  const inWindow = reportTime.filter(days, now)

  const [
    detectionsInPeriod,
    detectionsAllTime,
    bySeverity,
    byType,
    byStatus,
    blockedInPeriod,
    blockedAllTime,
    blockedIPsActive,
    containmentByStatus,
    sessionsInPeriod,
    sessionIPs,
    sessionLogins,
    sessionIdsInPeriod,
    activeSessionsNow,
    campaignsTotal,
    campaignsInPeriod,
    recent,
    nodes,
    aiHealth,
  ] = await Promise.all([
    ThreatLog.countDocuments({ createdAt: inWindow }),
    ThreatLog.countDocuments(),
    ThreatLog.aggregate([{ $match: { createdAt: inWindow } }, { $group: { _id: '$severity', count: { $sum: 1 } } }]),
    ThreatLog.aggregate([
      { $match: { createdAt: inWindow } },
      { $group: { _id: '$attackType', count: { $sum: 1 } } },
      { $sort: { count: -1, _id: 1 } },
    ]),
    ThreatLog.aggregate([{ $match: { createdAt: inWindow } }, { $group: { _id: '$status', count: { $sum: 1 } } }]),
    ThreatLog.countDocuments({ createdAt: inWindow, status: 'BLOCKED' }),
    ThreatLog.countDocuments({ status: 'BLOCKED' }),
    BlockedIP.countDocuments(),
    ContainmentAction.aggregate([
      { $match: { createdAt: inWindow } },
      { $group: { _id: '$enforcementStatus', count: { $sum: 1 } } },
      { $sort: { count: -1, _id: 1 } },
    ]),
    HoneypotSession.countDocuments({ createdAt: inWindow }),
    HoneypotSession.distinct('sourceIP', { createdAt: inWindow }),
    HoneypotSession.countDocuments({ createdAt: inWindow, 'credentials.success': true }),
    HoneypotSession.find({ createdAt: inWindow }, { sessionId: 1, _id: 0 }).lean(),
    HoneypotSession.countDocuments({ status: 'active' }),
    Campaign.countDocuments(),
    Campaign.countDocuments({ lastSeen: inWindow }),
    ThreatLog.find({ createdAt: inWindow })
      .sort({ createdAt: -1 })
      .limit(RECENT_EVENT_LIMIT)
      .select('createdAt attackType severity status sourceIP aiScore')
      .lean(),
    honeypotService.getNodeStatus(now).catch(() => null),
    aiEngineService.getHealth().catch(() => ({ status: 'unreachable' })),
  ])

  const sevCounts = countMap(bySeverity)
  const syntheticSessions = sessionIdsInPeriod.filter((s) => isSyntheticSession(s.sessionId)).length

  return {
    title: 'SentinelAI Security Summary Report',
    generatedAt: now.toISOString(),
    generatedBy: generatedBy ? { name: generatedBy.name || null, role: generatedBy.role || null } : null,
    period,
    system: {
      mode: 'REAL_MODE',
      aiEngine: aiHealth?.status === 'ok' ? 'connected' : 'unreachable',
      honeypotNodes: Array.isArray(nodes)
        ? nodes.map((n) => ({
            name: n.name,
            protocol: n.protocol,
            port: n.port,
            status: n.status,
            sessionsToday: n.sessionsToday,
            activeSessions: n.activeSessions,
          }))
        : null,
    },
    detections: {
      inPeriod: detectionsInPeriod,
      allTime: detectionsAllTime,
      bySeverity: SEVERITIES.map((s) => ({ severity: s, count: sevCounts[s] || 0 })),
      byType: byType.filter((r) => r._id != null).map((r) => ({ type: String(r._id), count: r.count })),
      byStatus: byStatus.filter((r) => r._id != null).map((r) => ({ status: String(r._id), count: r.count })),
    },
    containment: {
      blockedThreatsInPeriod: blockedInPeriod,
      blockedThreatsAllTime: blockedAllTime,
      blockRateInPeriod: detectionsInPeriod > 0 ? Number(((blockedInPeriod / detectionsInPeriod) * 100).toFixed(1)) : 0,
      deniedIPsCurrent: blockedIPsActive,
      actionsByStatus: containmentByStatus
        .filter((r) => r._id != null)
        .map((r) => ({ status: String(r._id), count: r.count })),
    },
    honeypot: {
      sessionsInPeriod,
      syntheticSessionsInPeriod: syntheticSessions,
      uniqueSourceIPsInPeriod: sessionIPs.length,
      successfulLoginSessionsInPeriod: sessionLogins,
      activeSessionsNow,
      campaignsTotal,
      campaignsActiveInPeriod: campaignsInPeriod,
    },
    recentEvents: recent.map((t) => ({
      time: t.createdAt ? new Date(t.createdAt).toISOString() : null,
      attackType: t.attackType || null,
      severity: t.severity || null,
      status: t.status || null,
      sourceIP: t.sourceIP || null,
      aiScore: typeof t.aiScore === 'number' ? Number(t.aiScore.toFixed(3)) : null,
    })),
    recentEventLimit: RECENT_EVENT_LIMIT,
  }
}

const fmtTime = (iso) =>
  iso ? new Date(iso).toLocaleString('en-IN', { timeZone: reportTime.TIME_ZONE, hour12: false }) + ' IST' : 'n/a'

function reportFileName(report, ext) {
  const stamp = report.generatedAt.replace(/[:.]/g, '-').replace('T', '_').slice(0, 19)
  return `sentinelai-security-report-${report.period.days}d-${stamp}.${ext}`
}

function renderPdf(report) {
  const doc = new PdfDocument({ title: report.title })
  doc.text(report.title, { font: 'bold', size: 18, color: [0.0, 0.3, 0.5], gap: 6 })
  doc.text(`Generated: ${fmtTime(report.generatedAt)}`, { size: 9.5 })
  doc.text(
    `Reporting period: last ${report.period.days} calendar day(s), ${fmtTime(report.period.rangeStart)} to ` +
      `${fmtTime(report.period.rangeEnd)} (${report.period.timeZone}). All-time figures are labelled as such.`,
    { size: 9.5 }
  )
  if (report.generatedBy?.role)
    doc.text(`Exported by: ${report.generatedBy.name || 'operator'} (${report.generatedBy.role})`, { size: 9.5 })

  doc.heading('System overview')
  doc.text(`Data mode: ${report.system.mode} (figures read from the SentinelAI database at export time)`)
  doc.text(`AI engine (readiness probe at export): ${report.system.aiEngine.toUpperCase()}`)
  if (report.system.honeypotNodes) {
    const active = report.system.honeypotNodes.filter((n) => n.status === 'active').length
    doc.text(`Honeypot nodes active: ${active} / ${report.system.honeypotNodes.length}`)
    doc.space(2)
    doc.table(
      [
        { label: 'NODE', width: 16 },
        { label: 'PROTO', width: 6 },
        { label: 'PORT', width: 6 },
        { label: 'STATUS', width: 10 },
        { label: 'SESSIONS TODAY', width: 15 },
        { label: 'ACTIVE NOW', width: 10 },
      ],
      report.system.honeypotNodes.map((n) => [n.name, n.protocol, n.port, n.status, n.sessionsToday, n.activeSessions])
    )
  } else doc.text('Honeypot node status: unavailable at export time')

  doc.heading('Detections')
  doc.text(`Detections in period: ${report.detections.inPeriod} (all time: ${report.detections.allTime})`)
  doc.space(2)
  doc.table(
    [
      { label: 'SEVERITY', width: 12 },
      { label: 'COUNT', width: 8 },
    ],
    report.detections.bySeverity.map((s) => [s.severity, s.count])
  )
  doc.space(4)
  doc.table(
    [
      { label: 'THREAT TYPE', width: 28 },
      { label: 'COUNT', width: 8 },
    ],
    report.detections.byType.map((t) => [t.type, t.count])
  )
  doc.space(4)
  doc.table(
    [
      { label: 'TRIAGE STATUS', width: 16 },
      { label: 'COUNT', width: 8 },
    ],
    report.detections.byStatus.map((s) => [s.status, s.count])
  )

  doc.heading('Containment')
  const c = report.containment
  doc.text(`Threats blocked in period: ${c.blockedThreatsInPeriod} (${c.blockRateInPeriod}% of detections in period)`)
  doc.text(`Threats blocked all time: ${c.blockedThreatsAllTime}`)
  doc.text(`IP addresses currently on the deny list: ${c.deniedIPsCurrent}`)
  doc.space(2)
  doc.table(
    [
      { label: 'CONTAINMENT ACTION STATUS', width: 26 },
      { label: 'COUNT', width: 8 },
    ],
    c.actionsByStatus.map((s) => [s.status, s.count])
  )

  doc.heading('Honeypot sessions')
  const h = report.honeypot
  doc.text(
    `Sessions in period: ${h.sessionsInPeriod} (of which synthetic demo sessions: ${h.syntheticSessionsInPeriod})`
  )
  doc.text(`Unique source IPs in period: ${h.uniqueSourceIPsInPeriod}`)
  doc.text(`Sessions with a successful login in period: ${h.successfulLoginSessionsInPeriod}`)
  doc.text(`Sessions active now: ${h.activeSessionsNow}`)
  doc.text(`Attacker campaigns: ${h.campaignsActiveInPeriod} seen in period, ${h.campaignsTotal} in total`)

  doc.heading(`Recent security events (latest ${report.recentEventLimit} in period)`)
  doc.table(
    [
      { label: 'TIME (IST)', width: 20 },
      { label: 'TYPE', width: 20 },
      { label: 'SEVERITY', width: 9 },
      { label: 'STATUS', width: 14 },
      { label: 'SOURCE IP', width: 15 },
      { label: 'AI', width: 5 },
    ],
    report.recentEvents.map((e) => [
      e.time ? fmtTime(e.time).replace(' IST', '') : 'n/a',
      e.attackType,
      e.severity,
      e.status,
      e.sourceIP,
      e.aiScore ?? '',
    ])
  )
  return doc.toBuffer({ footer: `SentinelAI security summary - generated ${fmtTime(report.generatedAt)}` })
}

// RFC 4180 quoting; cells that a spreadsheet would evaluate as formulas are prefixed with a quote.
function csvCell(value) {
  let s = value == null ? '' : String(value)
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

function renderCsv(report) {
  const rows = [['section', 'metric', 'value']]
  const add = (section, metric, value) => rows.push([section, metric, value])
  add('report', 'title', report.title)
  add('report', 'generated_at', report.generatedAt)
  add('report', 'period_days', report.period.days)
  add('report', 'period_start', report.period.rangeStart)
  add('report', 'period_end', report.period.rangeEnd)
  add('report', 'time_zone', report.period.timeZone)
  add('system', 'ai_engine', report.system.aiEngine)
  for (const n of report.system.honeypotNodes || []) {
    add('honeypot_node', `${n.name}.status`, n.status)
    add('honeypot_node', `${n.name}.sessions_today`, n.sessionsToday)
  }
  add('detections', 'in_period', report.detections.inPeriod)
  add('detections', 'all_time', report.detections.allTime)
  for (const s of report.detections.bySeverity) add('detections_by_severity', s.severity, s.count)
  for (const t of report.detections.byType) add('detections_by_type', t.type, t.count)
  for (const s of report.detections.byStatus) add('detections_by_status', s.status, s.count)
  const c = report.containment
  add('containment', 'blocked_in_period', c.blockedThreatsInPeriod)
  add('containment', 'blocked_all_time', c.blockedThreatsAllTime)
  add('containment', 'block_rate_in_period_pct', c.blockRateInPeriod)
  add('containment', 'deny_list_ips_current', c.deniedIPsCurrent)
  for (const s of c.actionsByStatus) add('containment_actions_by_status', s.status, s.count)
  for (const [k, v] of Object.entries(report.honeypot)) add('honeypot', k, v)
  rows.push([])
  rows.push(['recent_event_time', 'attack_type', 'severity', 'status', 'source_ip', 'ai_score'])
  for (const e of report.recentEvents) rows.push([e.time, e.attackType, e.severity, e.status, e.sourceIP, e.aiScore])
  return Buffer.from('﻿' + rows.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n', 'utf8')
}

module.exports = { buildSecurityReport, renderPdf, renderCsv, reportFileName, ALLOWED_DAYS, csvCell }
