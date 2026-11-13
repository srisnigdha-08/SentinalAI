'use strict'
const mongoose = require('mongoose')

// Deception Arena: one Static-vs-Adaptive persona experiment. Trials are produced by the local runner
// (ai-engine/demo/deception_arena.py) against an isolated copy of the Q-learner; they are NOT honeypot sessions and
// are never written to HoneypotSession, so normal honeypot analytics and the deployed learner are untouched.

const STATUSES = ['CREATED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED']
const STRATEGIES = ['STATIC', 'ADAPTIVE']
const TERMINATIONS = ['completed', 'attacker_left', 'fingerprinted', 'time_limit', 'login_failed']

const CommandSchema = new mongoose.Schema(
  { command: { type: String, maxlength: 200 }, intent: { type: String, maxlength: 40 } },
  { _id: false }
)
const DecisionSchema = new mongoose.Schema(
  {
    state: String,
    recommendedPersona: String,
    appliedPersona: String,
    explored: Boolean,
    policy: String,
    epsilon: Number,
    qValues: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  { _id: false }
)
const TrialSchema = new mongoose.Schema(
  {
    strategy: { type: String, enum: STRATEGIES, required: true },
    index: { type: Number, required: true },
    pairPosition: { type: Number, default: 0 },
    persona: { type: String, required: true },
    decision: { type: DecisionSchema, default: null },
    durationSeconds: { type: Number, default: null },
    commands: { type: [CommandSchema], default: [] },
    loginSucceeded: { type: Boolean, default: null },
    termination: { type: String, enum: TERMINATIONS, default: null },
    fingerprinted: { type: Boolean, default: false },
    reward: { type: Number, default: null },
    startedAt: { type: Date, default: null },
    endedAt: { type: Date, default: null },
  },
  { _id: false }
)

const DeceptionExperimentSchema = new mongoose.Schema(
  {
    experimentId: { type: String, required: true, unique: true },
    name: { type: String, required: true, maxlength: 80 },
    description: { type: String, default: '', maxlength: 500 },
    mode: { type: String, enum: ['REPRODUCIBLE'], default: 'REPRODUCIBLE' },
    scenario: { type: String, required: true },
    baselinePersona: { type: String, required: true },
    adaptiveEnabled: { type: Boolean, default: true },
    trialsPerStrategy: { type: Number, required: true, min: 1, max: 50 },
    maxTrialSeconds: { type: Number, required: true, min: 30, max: 3600 },
    seed: { type: Number, required: true },
    status: { type: String, enum: STATUSES, default: 'CREATED', index: true },
    cancelRequested: { type: Boolean, default: false },
    createdBy: { email: String, role: String },
    startedAt: { type: Date, default: null },
    completedAt: { type: Date, default: null },
    heartbeatAt: { type: Date, default: null },
    failureReason: { type: String, default: null, maxlength: 500 },
    provenance: { type: mongoose.Schema.Types.Mixed, default: null },
    trials: { type: [TrialSchema], default: [] },
    events: {
      type: [{ type: { type: String }, at: Date, detail: { type: String, maxlength: 300 }, _id: false }],
      default: [],
    },
  },
  { timestamps: true, collection: 'deception_experiments' }
)
DeceptionExperimentSchema.index({ createdAt: -1 })

const DeceptionExperiment = mongoose.model('DeceptionExperiment', DeceptionExperimentSchema)
DeceptionExperiment.STATUSES = STATUSES
DeceptionExperiment.TERMINATIONS = TERMINATIONS
module.exports = DeceptionExperiment
