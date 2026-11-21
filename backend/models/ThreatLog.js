const mongoose = require('mongoose')
const mitreMapping = require('../utils/mitreMapping')
const ThreatLogSchema = new mongoose.Schema(
  {
    severity: { type: String, required: true, enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
    sourceIP: { type: String, required: true },
    destinationIP: { type: String, default: 'INTERNAL' },
    targetService: { type: String, default: 'UNKNOWN' },
    attackType: {
      type: String,
      required: true,
      enum: [
        'SSH Brute Force',
        'SSH Intrusion Attempt',
        'SQL Injection',
        'Port Scan',
        'DDoS',
        'RCE Attempt',
        'XSS Attempt',
        'Malware Beacon',
        'Credential Stuffing',
        'Ransomware',
        'Lateral Movement',
        'Data Exfiltration',
        'Zero-Day Exploit',
        'Unknown',
        'UNINSPECTED_TRAFFIC',
      ],
    },
    aiScore: { type: Number, min: 0, max: 1, default: 0 },
    confidence: { type: Number, min: 0, max: 1, default: 0 },
    status: {
      type: String,
      enum: [
        'DETECTED',
        'INVESTIGATING',
        'CONTAINED',
        'MONITORING',
        'BLOCKED',
        'ESCALATED',
        'RESOLVED',
        'FALSE_POSITIVE',
        'DEGRADED',
      ],
      // Indexed through { status: 1, createdAt: -1 } below (its prefix serves status-only queries).
      default: 'DETECTED',
    },
    triageNotes: { type: String, default: '', maxlength: 1000 },

    preBlockStatus: {
      type: String,
      // Every status a block may start from (all but BLOCKED, RESOLVED, FALSE_POSITIVE), so unblock restores it
      enum: ['DETECTED', 'INVESTIGATING', 'CONTAINED', 'MONITORING', 'ESCALATED', 'DEGRADED', null],
      default: null,
    },
    // L1: the BlockedIP (deny-list entry) document this threat was blocked under. Not the same thing as
    // ContainmentAction.containmentId, which is that action's string id; kept under this name for existing data.
    containmentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'BlockedIP',
      default: null,
      index: true,
    },
    predictionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'AIPrediction',
      default: null,
      index: true,
    },
    // When the event happened according to its source (flow timestamp, manual entry); createdAt is when it was stored.
    eventTime: {
      type: Date,
      default: null,
    },
    autonomousAction: {
      taken: { type: Boolean, default: false },
      actionType: {
        type: String,
        enum: ['IP_BLOCKED', 'SESSION_TERMINATED', 'ALERT_ESCALATED', 'ENDPOINT_ISOLATED', null],
        default: null,
      },
      actionTime: { type: Date },
    },
    geoLocation: {
      country: { type: String, default: 'Unknown' },
      city: { type: String, default: 'Unknown' },
      lat: Number,
      lon: Number,
    },
    mitreAttack: { tactic: String, technique: String },
    mitreTechniques: [{ id: { type: String, required: true }, name: { type: String, required: true }, _id: false }],
    // L4: bounded in the schema as well as in the API, so no writer can grow a threat towards the 16 MB limit.
    rawPayload: { type: String, select: false, maxlength: 65536 },
    handledBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    notes: { type: String, default: '', maxlength: 1000 },
    // L3: analyst labels (PUT /api/threats/:id). Accepted by the API before but missing here, so they were dropped.
    tags: {
      type: [{ type: String, trim: true, maxlength: 40 }],
      default: undefined,
      validate: { validator: (v) => !v || v.length <= 20, message: 'At most 20 tags' },
    },
    // Why automatic containment was or was not requested (services/containmentCorrelationService.js). Auditable
    // record of the decision; absent on threats below the block line and on threats stored before it existed.
    containmentDecision: {
      type: new mongoose.Schema(
        {
          decision: {
            type: String,
            enum: ['AUTO_BLOCK', 'NEEDS_APPROVAL', 'SUPPRESSED_TRUSTED', 'SUPPRESSED_DUPLICATE', 'MONITOR', 'DISABLED'],
          },
          policy: { type: String, enum: ['correlated', 'single_flow'] },
          reasons: [String],
          evidence: { type: mongoose.Schema.Types.Mixed },
          evaluatedAt: Date,
        },
        { _id: false }
      ),
      default: undefined,
    },
    threatIntel: {
      provider: { type: String, default: 'AbuseIPDB' },
      status: {
        type: String,
        enum: ['PENDING', 'SUCCESS', 'FAILED', 'UNAVAILABLE'],
        default: 'PENDING',
      },
      abuseConfidenceScore: { type: Number, min: 0, max: 100, default: null },
      totalReports: { type: Number, default: 0 },
      lastReportedAt: { type: Date, default: null },
      countryCode: { type: String, default: null },
      isp: { type: String, default: null },
      domain: { type: String, default: null },
      lookupAt: { type: Date, default: null },
      cached: { type: Boolean, default: false },
      errorCode: { type: String, default: null },
    },
  },
  { timestamps: true }
)
// M3 / L8: the threat list sorts newest first with _id as the tie-breaker (stable keyset pagination), optionally
// filtered by status, severity or attack type. Each shape has an index ending in { createdAt: -1, _id: -1 }, so
// MongoDB never sorts in memory or walks the whole date index for a rare status. These replace the former
// { createdAt: -1 }, { severity: 1, status: 1 } and { status: 1 } indexes, whose queries their prefixes still serve.
ThreatLogSchema.index({ createdAt: -1, _id: -1 })
ThreatLogSchema.index({ status: 1, createdAt: -1, _id: -1 })
ThreatLogSchema.index({ severity: 1, createdAt: -1, _id: -1 })
ThreatLogSchema.index({ attackType: 1, createdAt: -1, _id: -1 })
ThreatLogSchema.index({ sourceIP: 1, createdAt: -1 })
ThreatLogSchema.index({ 'threatIntel.status': 1 })
ThreatLogSchema.pre('save', function (next) {
  if (this.isModified('attackType') || !this.mitreTechniques || this.mitreTechniques.length === 0) {
    this.mitreTechniques = mitreMapping.storedForm(mitreMapping.getMitreTechniquesForThreat(this.attackType))
  }
  next()
})
const ThreatLog = mongoose.model('ThreatLog', ThreatLogSchema)
ThreatLog.ALLOWED_ATTACK_TYPES = ThreatLogSchema.path('attackType').enumValues
module.exports = ThreatLog
