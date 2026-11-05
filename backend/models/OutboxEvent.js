const mongoose = require('mongoose')

// Durable record of security events published on the SecurityEventBus (OUTBOX_STORE=mongo).
// Delivered events expire after OUTBOX_RETENTION_DAYS (default 7); pending/failed ones are kept for redrive.
const OutboxEventSchema = new mongoose.Schema(
  {
    eventId: { type: String, required: true, unique: true },
    eventType: { type: String, required: true, index: true },
    envelope: { type: mongoose.Schema.Types.Mixed, required: true },
    status: { type: String, enum: ['PENDING', 'DELIVERED', 'FAILED'], default: 'PENDING', index: true },
    attempts: { type: Number, default: 0 },
    lastError: { type: String, default: null },
    deliveredAt: { type: Date, default: null },
    expiresAt: { type: Date, default: null },
  },
  { timestamps: true }
)
OutboxEventSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })
OutboxEventSchema.index({ status: 1, createdAt: 1 })
module.exports = mongoose.model('OutboxEvent', OutboxEventSchema)
