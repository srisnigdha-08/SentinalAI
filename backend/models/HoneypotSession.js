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
    engagementLevel: { type: String, enum: ['minimal', 'low', 'medium', 'high', 'deep'], default: 'minimal' },
    status: { type: String, enum: ['active', 'closed', 'analysed'], default: 'active' },
    closureAnalysisState: { type: String, enum: ['idle', 'processing', 'complete', 'failed'], default: 'idle' },
    closureAttemptId: String,
    closureAnalysisStartedAt: Date,
    closureAnalysisCompletedAt: Date,
    aiClassification: { type: String, default: null },
    aiThreatScore: { type: Number, default: 0 },
    qDeceptionScore: { type: Number, default: 0 },
    recommendedProfile: { type: String, default: 'ubuntu_22' },
    mitreTechniques: [{ id: { type: String, required: true }, name: { type: String, required: true }, _id: false }],
  },
  { timestamps: true }
)
HoneypotSessionSchema.index({ sourceIP: 1, createdAt: -1 })
HoneypotSessionSchema.index({ honeypotNode: 1, status: 1 })
HoneypotSessionSchema.index({ createdAt: -1 })
HoneypotSessionSchema.index({ hassh: 1 })
HoneypotSessionSchema.pre('save', function (next) {
  if (this.isModified('commands') || !this.mitreTechniques || this.mitreTechniques.length === 0) {
    const intents = this.commands.map((c) => c.intent).filter(Boolean)
    this.mitreTechniques = mitreMapping.getMitreTechniquesForIntents(intents)
  }
  next()
})
module.exports = mongoose.model('HoneypotSession', HoneypotSessionSchema)
