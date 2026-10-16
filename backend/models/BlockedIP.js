const mongoose = require('mongoose')

const BlockedIPSchema = new mongoose.Schema(
  {
    ip: { type: String, required: true, unique: true, index: true },
    reason: { type: String, default: 'Manual block' },
    blockedAt: { type: Date, default: Date.now },
    blockedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // null if blocked by AI/system
    threatRef: { type: mongoose.Schema.Types.ObjectId, ref: 'ThreatLog', default: null },
  },
  { timestamps: true }
)

module.exports = mongoose.model('BlockedIP', BlockedIPSchema)
