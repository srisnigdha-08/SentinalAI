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
      default: 'DETECTED',
      index: true,
    },
    triageNotes: { type: String, default: '', maxlength: 1000 },

    preBlockStatus: {
      type: String,
      enum: ['DETECTED', 'MONITORING', 'ESCALATED', 'DEGRADED', null],
      default: null,
    },
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
    rawPayload: { type: String, select: false },
    handledBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    notes: { type: String, default: '' },
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
ThreatLogSchema.index({ createdAt: -1 })
ThreatLogSchema.index({ severity: 1, status: 1 })
ThreatLogSchema.index({ sourceIP: 1, createdAt: -1 })
ThreatLogSchema.index({ 'threatIntel.status': 1 })
ThreatLogSchema.pre('save', function (next) {
  if (this.isModified('attackType') || !this.mitreTechniques || this.mitreTechniques.length === 0) {
    this.mitreTechniques = mitreMapping.getMitreTechniquesForThreat(this.attackType)
  }
  next()
})
const ThreatLog = mongoose.model('ThreatLog', ThreatLogSchema)
ThreatLog.ALLOWED_ATTACK_TYPES = ThreatLogSchema.path('attackType').enumValues
module.exports = ThreatLog
