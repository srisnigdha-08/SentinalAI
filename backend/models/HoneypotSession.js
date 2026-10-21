const mongoose = require('mongoose')
const mitreMapping = require('../utils/mitreMapping')
const CmdSchema = new mongoose.Schema(
  {
    command: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    output: { type: String, default: '' },
    success: { type: Boolean, default: false },
    intent: { type: String, default: null },
  },
  { _id: false }
)
const HoneypotSessionSchema = new mongoose.Schema(
  {
    sessionId: { type: String, required: true, unique: true },
    sourceIP: { type: String, required: true },
    sourcePort: { type: Number },
    hassh: { type: String, default: null },
    geoLocation: {
      country: String,
      countryCode: { type: String, default: 'XX' },
      city: String,
      lat: Number,
      lon: Number,
      isp: String,
    },
    honeypotNode: {
      type: String,
      enum: ['SSH-COWRIE-01', 'HTTP-LURE-02', 'FTP-TRAP-03', 'SMTP-DECOY-04'],
      default: 'SSH-COWRIE-01',
    },
    protocol: { type: String, enum: ['SSH', 'HTTP', 'FTP', 'SMTP', 'TELNET'], default: 'SSH' },
    credentials: [{ username: String, password: String, success: { type: Boolean, default: false }, _id: false }],
    commands: [CmdSchema],
    startTime: { type: Date, default: Date.now },
    endTime: { type: Date },
    durationSeconds: { type: Number, default: 0 },
    malwareDownloaded: [{ type: String }],
    filesAccessed: [{ type: String }],
    iocExtracted: { ips: [String], urls: [String], hashes: [String] },
    linkedThreatLog: { type: mongoose.Schema.Types.ObjectId, ref: 'ThreatLog', default: null },
    deceptionScore: { type: Number, default: 0, min: 0, max: 100 },
    // Cowrie file-download events; each adds 15 to deceptionScore (see honeypotService.recordSessionActivity).
    downloadCount: { type: Number, default: 0 },
    engagementLevel: { type: String, enum: ['minimal', 'low', 'medium', 'high', 'deep'], default: 'minimal' },
    status: { type: String, enum: ['active', 'closed', 'analysed'], default: 'active' },
    closureAnalysisState: { type: String, enum: ['idle', 'processing', 'complete', 'failed'], default: 'idle' },
    closureAttemptId: String,
    closureAnalysisStartedAt: Date,
    closureAnalysisCompletedAt: Date,
    aiClassification: { type: String, default: null },
    aiThreatScore: { type: Number, default: 0 },
    // How aiClassification was produced; for Cowrie sessions 'honeypot_rules' (login outcome and command
    // keywords set class and score), never model inference. Older records may say 'rule_profile_synthetic_flow'.
    aiClassificationMethod: { type: String, default: null },
    qDeceptionScore: { type: Number, default: 0 },
    recommendedProfile: { type: String, default: 'ubuntu_22' },
    // Persona Cowrie actually served for this session: the Q-learner's action for its reward.
    servedProfile: { type: String, default: null },
    mitreTechniques: [{ id: { type: String, required: true }, name: { type: String, required: true }, _id: false }],
    // Ids of Cowrie command/download events already applied (parser/plugin eventId), so a replayed or
    // doubly delivered event is a no-op. Internal: never returned by default.
    ingestEventIds: { type: [String], default: undefined, select: false },
    // Closure finished while the AI engine was unavailable: classification and/or the Q-learner update
    // are retried by the sweep (honeypotSweepService.retryDeferredAnalysis), at most a few times.
    aiAnalysisPending: { type: Boolean, default: false },
    deceptionScoringPending: { type: Boolean, default: false },
    deferredAnalysisAttempts: { type: Number, default: 0 },
  },
  { timestamps: true }
)
HoneypotSessionSchema.index({ sourceIP: 1, createdAt: -1 })
HoneypotSessionSchema.index({ honeypotNode: 1, status: 1 })
HoneypotSessionSchema.index({ createdAt: -1 })
HoneypotSessionSchema.index({ hassh: 1 })
HoneypotSessionSchema.index({ linkedThreatLog: 1 })
// Campaign clustering looks up recent sessions that share a command
HoneypotSessionSchema.index({ 'commands.command': 1, createdAt: -1 })
// Stale-session sweep and deferred-analysis retry
HoneypotSessionSchema.index({ status: 1, updatedAt: 1 })
HoneypotSessionSchema.pre('save', function (next) {
  if (this.isModified('commands') || !this.mitreTechniques || this.mitreTechniques.length === 0) {
    const intents = this.commands.map((c) => c.intent).filter(Boolean)
    this.mitreTechniques = mitreMapping.getMitreTechniquesForIntents(intents)
  }
  next()
})
module.exports = mongoose.model('HoneypotSession', HoneypotSessionSchema)
