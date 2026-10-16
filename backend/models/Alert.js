const mongoose = require('mongoose')
const AlertSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, maxlength: 200 },
    message: { type: String, required: true },
    severity: { type: String, enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], default: 'INFO', index: true },
    type: {
      type: String,
      enum: [
        'THREAT_DETECTED',
        'IP_BLOCKED',
        'IP_UNBLOCKED',
        'HONEYPOT_SESSION',
        'AI_PREDICTION',
        'SYSTEM_HEALTH',
        'AUTH_FAILURE',
        'AUTONOMOUS_ACTION',
      ],
      required: true,
    },
    sourceRef: {
      refModel: { type: String, enum: ['ThreatLog', 'HoneypotSession', 'User', 'AIPrediction'] },
      refId: { type: mongoose.Schema.Types.ObjectId },
    },
    targetRoles: { type: [String], default: ['admin', 'analyst'] },
    readBy: [
      {
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        readAt: { type: Date, default: Date.now },
        _id: false,
      },
    ],
    isRead: { type: Boolean, default: false },
    autonomousAction: { taken: { type: Boolean, default: false }, actionType: String, result: String },
    expiresAt: { type: Date, default: () => new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) },
  },
  { timestamps: true }
)
AlertSchema.index({ createdAt: -1 })
AlertSchema.index({ severity: 1, isRead: 1 })
AlertSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })
module.exports = mongoose.model('Alert', AlertSchema)
