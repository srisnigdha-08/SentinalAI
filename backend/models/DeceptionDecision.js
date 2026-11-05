const mongoose = require('mongoose')

// One persona-rotation decision (RL-001, audit/RL001_DESIGN.md): drawn once from the learner, then applied,
// acknowledged as "keep", failed or superseded — never re-drawn while pending.
const DeceptionDecisionSchema = new mongoose.Schema(
  {
    decisionId: { type: String, required: true, unique: true },
    state: { type: String, required: true }, // persona served when the decision was drawn
    action: { type: String, required: true }, // persona the learner chose
    explored: { type: Boolean, default: false },
    policy: { type: String, default: 'q_learning' },
    // Learner provenance at draw time (seed vs scored episodes), shown on Honeypot Analytics
    provenance: { type: mongoose.Schema.Types.Mixed, default: null },
    status: { type: String, enum: ['PENDING', 'APPLIED', 'FAILED', 'SUPERSEDED'], default: 'PENDING', index: true },
    // Set only while PENDING; the unique index makes "one pending decision" a database guarantee
    pendingLock: { type: String },
    appliedProfile: { type: String, default: null },
    appliedBy: { type: String, default: null },
    appliedAt: { type: Date, default: null },
    closedAt: { type: Date, default: null },
    failureReason: { type: String, default: null, maxlength: 500 },
  },
  { timestamps: true }
)
DeceptionDecisionSchema.index({ pendingLock: 1 }, { unique: true, sparse: true })

module.exports = mongoose.model('DeceptionDecision', DeceptionDecisionSchema)
