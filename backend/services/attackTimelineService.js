'use strict'
/**
 * Attack Time Machine: read-only evidence bundle for one recorded honeypot session.
 *
 * Only records with a stored reference to this session (or to the threat record the session references) are
 * returned. Nothing is correlated by source IP alone. Every query is bounded and projected, and nothing here writes.
 *
 *  - session: the recorded Cowrie session (credentials never carry passwords; viewers get the existing redaction);
 *  - commands[i].techniques: the existing trusted MITRE mapping applied to that one command (derived, not observed);
 *  - prediction: the stored honeypot classification whose rawFeatures.sessionId is this session;
 *  - threat: the ThreatLog the session references (shared by sessions from the same source, so threat-level);
 *  - alerts: alerts whose sourceRef is this session or that threat, limited to alerts targeted at the caller's role;
 *  - containment / blockedIPs / containment audit transitions: admin and analyst only, like the containment API.
 */
const HoneypotSession = require('../models/HoneypotSession')
const ThreatLog = require('../models/ThreatLog')
const Alert = require('../models/Alert')
const AIPrediction = require('../models/AIPrediction')
const ContainmentAction = require('../models/ContainmentAction')
const ContainmentAuditEvent = require('../models/ContainmentAuditEvent')
const BlockedIP = require('../models/BlockedIP')
const { getMitreTechniquesForSession } = require('../utils/mitreMapping')
const { isPrivilegedRole, redactHoneypotSession, redactThreat, redactAlert } = require('../utils/redact')

const LIMITS = { alerts: 50, predictions: 50, containment: 20, auditPerAction: 100, blocked: 10 }

const SESSION_FIELDS = [
  'sessionId',
  'sourceIP',
  'sourcePort',
  'hassh',
  'clientVersion',
  'ttylog.sha256',
  'ttylog.size',
  'honeypotNode',
  'protocol',
  'credentials',
  'credentialCount',
  'commands',
  'commandCount',
  'startTime',
  'endTime',
  'durationSeconds',
  'malwareDownloaded',
  'filesAccessed',
  'downloadCount',
  'linkedThreatLog',
  'deceptionScore',
  'engagementLevel',
  'status',
  'closureAnalysisState',
  'closureAnalysisCompletedAt',
  'aiClassification',
  'aiThreatScore',
  'aiClassificationMethod',
  'qDeceptionScore',
  'recommendedProfile',
  'servedProfile',
  'mitreTechniques',
  'aiAnalysisPending',
  'deceptionScoringPending',
  'deceptionScoredAt',
  'createdAt',
  'updatedAt',
].join(' ')

const THREAT_FIELDS =
  'severity sourceIP attackType aiScore confidence status mitreTechniques autonomousAction containmentId predictionId eventTime notes createdAt updatedAt'

const ALERT_FIELDS = 'title message severity type sourceRef autonomousAction createdAt'

const PREDICTION_FIELDS =
  'inputSource predictedClass threatScore modelVersion modelType isAnomaly anomalyScore inferenceTimeMs generatedThreat rawFeatures.sessionId createdAt'

const CONTAINMENT_FIELDS =
  'containmentId actionType targetType target policyDecision policyReason enforcementBackend enforcementStatus targetMetadata.originalThreatId targetMetadata.severity requestedByName requestedByRole requestedAt appliedAt expiresAt rolledBackAt failureReason enforcementDetails.adapterName rollbackDetails.reason createdAt updatedAt'

const AUDIT_FIELDS = 'containmentId seq action enforcementStatus enforcementBackend policyDecision occurredAt recordedAt -_id'

/** Credentials without passwords for every role (ingest already masks them; this keeps it true for old records). */
const safeCredentials = (credentials) =>
  (Array.isArray(credentials) ? credentials : []).map((c) => {
    const out = { success: Boolean(c?.success) }
    if (typeof c?.username === 'string') out.username = c.username.slice(0, 100)
    return out
  })

const withCommandTechniques = (commands) =>
  (Array.isArray(commands) ? commands : []).map((c, index) => ({
    index,
    command: c.command,
    timestamp: c.timestamp ?? null,
    output: c.output || '',
    success: Boolean(c.success),
    intent: c.intent || null,
    // Same mapping the session-level mitreTechniques comes from, applied per command.
    techniques: getMitreTechniquesForSession([{ command: c.command, intent: c.intent }]),
  }))

async function getSessionEvidence(id, role = 'viewer') {
  const privileged = isPrivilegedRole(role)
  const raw = await HoneypotSession.findById(id).select(SESSION_FIELDS).lean()
  if (!raw) return null

  // Per-command techniques are computed from the real command text before any role redaction hides it.
  const commands = withCommandTechniques(raw.commands)
  const session = redactHoneypotSession({ ...raw, commands }, role)
  session.credentials = privileged ? safeCredentials(raw.credentials) : safeCredentials(session.credentials)
  if (!privileged) {
    session.commands = session.commands.map((c, i) => ({ ...c, techniques: commands[i].techniques }))
    delete session.hassh
    delete session.clientVersion
  }

  const threatId = raw.linkedThreatLog || null
  const threatDoc = threatId ? await ThreatLog.findById(threatId).select(THREAT_FIELDS).lean() : null
  const threat = threatDoc ? redactThreat(threatDoc, role) : null

  // The honeypot classification stored at closure carries this session's id in rawFeatures.
  const predictions = threatId
    ? await AIPrediction.find({ generatedThreat: threatId, inputSource: 'honeypot_log' })
        .select(PREDICTION_FIELDS)
        .sort({ createdAt: 1, _id: 1 })
        .limit(LIMITS.predictions)
        .lean()
    : []
  const prediction = predictions.filter((p) => p.rawFeatures?.sessionId === raw.sessionId).pop() || null
  if (prediction) delete prediction.rawFeatures

  const refIds = [raw._id, ...(threatId ? [threatId] : [])]
  const alertDocs = await Alert.find({ 'sourceRef.refId': { $in: refIds }, targetRoles: role })
    .select(ALERT_FIELDS)
    .sort({ createdAt: 1, _id: 1 })
    .limit(LIMITS.alerts)
    .lean()
  const alerts = alertDocs.map((a) => ({
    ...redactAlert(a, role),
    linkedVia: String(a.sourceRef?.refId) === String(raw._id) ? 'session' : 'threat',
  }))

  let containment = []
  let blockedIPs = []
  if (privileged && threatId) {
    containment = await ContainmentAction.find({ 'targetMetadata.originalThreatId': threatId })
      .select(CONTAINMENT_FIELDS)
      .sort({ requestedAt: 1, _id: 1 })
      .limit(LIMITS.containment)
      .lean()
    const ids = containment.map((c) => c.containmentId)
    const audit = ids.length
      ? await ContainmentAuditEvent.find({ containmentId: { $in: ids } })
          .select(AUDIT_FIELDS)
          .sort({ seq: 1 })
          .limit(LIMITS.auditPerAction * ids.length)
          .lean()
      : []
    containment = containment.map((c) => ({
      ...c,
      transitions: audit.filter((e) => e.containmentId === c.containmentId).slice(0, LIMITS.auditPerAction),
    }))
    blockedIPs = await BlockedIP.find({ threatRef: threatId })
      .select('ip reason blockedAt threatRef createdAt')
      .limit(LIMITS.blocked)
      .lean()
  }

  return {
    session,
    threat,
    prediction,
    alerts,
    containment,
    blockedIPs,
    access: { role, containmentVisible: privileged, commandsVisible: privileged },
  }
}

module.exports = { getSessionEvidence, LIMITS }
