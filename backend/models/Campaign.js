const mongoose = require('mongoose')

const CampaignSchema = new mongoose.Schema(
  {
    campaignId: {
      type: String,
      required: true,
      unique: true,
    },
    sessions: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'HoneypotSession',
      },
    ],
    firstSeen: {
      type: Date,
      default: Date.now,
    },
    lastSeen: {
      type: Date,
      default: Date.now,
    },
    sourceIPs: [
      {
        type: String,
      },
    ],
    threatLevel: {
      type: String,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      default: 'LOW',
    },
    maxDeceptionScore: {
      type: Number,
      default: 0,
    },
    maxAiThreatScore: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true,
  }
)

CampaignSchema.index({ lastSeen: -1 })

module.exports = mongoose.model('Campaign', CampaignSchema)
