'use strict'

const mongoose = require('mongoose')

const AuditLogSchema = new mongoose.Schema(
  {
    action: { type: String, required: true },
    eventType: { type: String, default: 'SECURITY_AUDIT', index: true },
    actor: {
      id: { type: String },
      email: { type: String },
      role: { type: String },
    },
    target: {
      type: { type: String },
      id: { type: String },
      identifier: { type: String },
    },
    status: { type: String, enum: ['SUCCESS', 'DENIED', 'FAILED', 'EXECUTED'], default: 'SUCCESS', index: true },
    details: { type: mongoose.Schema.Types.Mixed, default: {} },
    ip: { type: String },
    userAgent: { type: String },
  },
  { timestamps: true }
)

AuditLogSchema.index({ createdAt: -1 })
AuditLogSchema.index({ 'actor.id': 1, createdAt: -1 })
AuditLogSchema.index({ action: 1, createdAt: -1 })
AuditLogSchema.index({ 'target.id': 1 })

const immutableError = () =>
  new Error('AuditLog records are append-only and strictly immutable. Updates and deletions are rejected.')

AuditLogSchema.pre(['updateOne', 'updateMany', 'findOneAndUpdate', 'findOneAndReplace', 'replaceOne'], function (next) {
  next(immutableError())
})

AuditLogSchema.pre(['deleteOne', 'deleteMany', 'findOneAndDelete'], function (next) {
  next(immutableError())
})

AuditLogSchema.pre('bulkWrite', function (next) {
  next(immutableError())
})

AuditLogSchema.pre('save', function (next) {
  if (!this.isNew) {
    return next(immutableError())
  }
  next()
})

module.exports = mongoose.model('AuditLog', AuditLogSchema)
