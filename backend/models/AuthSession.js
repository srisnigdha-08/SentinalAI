const mongoose = require('mongoose')
const schema = new mongoose.Schema(
  {
    _id: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    authVersion: { type: Number, required: true, min: 0 },
    generation: { type: Number, required: true, default: 0, min: 0 },
    refreshHash: { type: String, required: true, select: false },
    expiresAt: { type: Date, required: true },
    lastUsedAt: { type: Date, required: true },
    revokedAt: { type: Date, default: null },
    revocationReason: { type: String, default: null },
  },
  { timestamps: true, bufferCommands: false }
)
schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })
schema.index({ revokedAt: 1 }, { expireAfterSeconds: 48 * 3600, sparse: true })
module.exports = mongoose.model('AuthSession', schema)
