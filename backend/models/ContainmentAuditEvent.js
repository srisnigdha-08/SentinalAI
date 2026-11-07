'use strict'
/**
 * F-07: durable containment audit trail. Before this, containment audit events (requested, applied, failed,
 * rolled back, recovered, late rule removed, ...) existed only as log lines, so they were lost with log
 * rotation and could not be queried per containment action.
 *
 *  - append-only: updates and deletes through the model are rejected (as for AuditLog);
 *  - no duplicates: eventId is unique; a retried write of the same event is a no-op;
 *  - ordering: seq is a strictly increasing number assigned by the database (gaps are possible when a write is
 *    retried), and recordedAt is the database clock at assignment, not the backend host clock (CONT-R1);
 *    occurredAt is the backend clock when the event happened;
 *  - traceability: containmentId (links to ContainmentAction), correlationId, operator and policy decision.
 */
const mongoose = require('mongoose')

const ContainmentAuditEventSchema = new mongoose.Schema(
  {
    eventId: { type: String, required: true, unique: true },
    seq: { type: Number, required: true, unique: true },
    containmentId: { type: String, required: true, index: true },
    correlationId: { type: String, default: null },
    action: { type: String, required: true },
    target: { type: String, default: null, index: true },
    actionType: { type: String, default: 'block_ip' },
    policyDecision: { type: String, default: null },
    enforcementBackend: { type: String, default: null },
    enforcementStatus: { type: String, default: null },
    operator: {
      id: { type: String, default: null },
      email: { type: String, default: null },
      role: { type: String, default: null },
    },
    details: { type: mongoose.Schema.Types.Mixed, default: {} },
    occurredAt: { type: Date, required: true },
    recordedAt: { type: Date, required: true },
  },
  { versionKey: false, collection: 'containment_audit_events' }
)

ContainmentAuditEventSchema.index({ containmentId: 1, seq: 1 })
ContainmentAuditEventSchema.index({ recordedAt: -1 })

const immutable = () =>
  new Error('Containment audit events are append-only and strictly immutable. Updates and deletions are rejected.')

ContainmentAuditEventSchema.pre(
  ['updateOne', 'updateMany', 'findOneAndUpdate', 'findOneAndReplace', 'replaceOne'],
  function (next) {
    next(immutable())
  }
)
ContainmentAuditEventSchema.pre(['deleteOne', 'deleteMany', 'findOneAndDelete'], function (next) {
  next(immutable())
})
ContainmentAuditEventSchema.pre('save', function (next) {
  if (!this.isNew) return next(immutable())
  next()
})

module.exports = mongoose.model('ContainmentAuditEvent', ContainmentAuditEventSchema)
