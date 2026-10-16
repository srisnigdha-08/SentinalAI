'use strict'

const mongoose = require('mongoose')
const { v4: uuidv4 } = require('uuid')

const ENFORCEMENT_STATUSES = [
  'REQUESTED',
  'VALIDATING',
  'APPROVED',
  'APPLYING',
  'ACTIVE',
  'FAILED',
  'REJECTED',
  'EXPIRING',
  'EXPIRED',
  'ROLLING_BACK',
  'ROLLED_BACK',
  'ROLLBACK_FAILED',
]

const TARGET_TYPES = ['ipv4', 'ipv6', 'cidr']
const ACTION_TYPES = ['block_ip', 'isolate_host', 'rate_limit']
const POLICY_DECISIONS = ['ALLOWED', 'DENIED', 'REQUIRES_CONFIRMATION']
const ENFORCEMENT_BACKENDS = ['mock', 'simulated', 'windows-firewall']

const VALID_TRANSITIONS = {
  REQUESTED: ['VALIDATING', 'REJECTED'],
  VALIDATING: ['APPROVED', 'REJECTED'],
  APPROVED: ['APPLYING', 'REJECTED'],
  APPLYING: ['ACTIVE', 'FAILED'],
  ACTIVE: ['EXPIRING', 'ROLLING_BACK', 'FAILED'],
  EXPIRING: ['ROLLING_BACK'],
  EXPIRED: ['ROLLING_BACK'],
  ROLLING_BACK: ['ROLLED_BACK', 'ROLLBACK_FAILED'],
  FAILED: [],
  REJECTED: [],
  ROLLED_BACK: [],
  ROLLBACK_FAILED: ['ROLLING_BACK'], // Retry allowed for rollback failure
}

const ContainmentActionSchema = new mongoose.Schema(
  {
    containmentId: {
      type: String,
      required: true,
      unique: true,
      index: true,
      default: () => uuidv4(),
    },
    idempotencyKey: {
      type: String,
      unique: true,
      sparse: true,
      index: true,
    },
    targetType: {
      type: String,
      enum: TARGET_TYPES,
      required: true,
      default: 'ipv4',
    },
    target: {
      type: String,
      required: true,
      trim: true,
    },
    normalizedTarget: {
      type: String,
      required: true,
      trim: true,
      index: true,
    },
    actionType: {
      type: String,
      enum: ACTION_TYPES,
      required: true,
      default: 'block_ip',
    },
    policyDecision: {
      type: String,
      enum: POLICY_DECISIONS,
      required: true,
      default: 'ALLOWED',
    },
    policyReason: {
      type: String,
      default: '',
    },
    enforcementBackend: {
      type: String,
      enum: ENFORCEMENT_BACKENDS,
      required: true,
      default: 'mock',
    },
    enforcementStatus: {
      type: String,
      enum: ENFORCEMENT_STATUSES,
      required: true,
      default: 'REQUESTED',
      index: true,
    },
    targetMetadata: {
      hostname: { type: String, default: null },
      threatCategory: { type: String, default: null },
      originalThreatId: { type: mongoose.Schema.Types.ObjectId, ref: 'ThreatLog', default: null },
      severity: { type: String, default: null },
    },
    requestedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    requestedByName: {
      type: String,
      default: 'System',
    },
    requestedByRole: {
      type: String,
      default: 'system',
    },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    requestedAt: {
      type: Date,
      default: Date.now,
    },
    appliedAt: {
      type: Date,
      default: null,
    },
    expiresAt: {
      type: Date,
      default: null,
      index: true,
    },
    rolledBackAt: {
      type: Date,
      default: null,
    },
    enforcementDetails: {
      adapterName: { type: String, default: null },
      ruleName: { type: String, default: null },
      ruleId: { type: String, default: null },
      exitCode: { type: Number, default: null },
      stdout: { type: String, default: null },
      stderr: { type: String, default: null },
      executionDurationMs: { type: Number, default: null },
    },
    rollbackDetails: {
      ruleId: { type: String, default: null },
      exitCode: { type: Number, default: null },
      stdout: { type: String, default: null },
      stderr: { type: String, default: null },
      executionDurationMs: { type: Number, default: null },
      reason: { type: String, default: null },
    },
    failureReason: {
      type: String,
      default: null,
    },
    correlationId: {
      type: String,
      index: true,
      default: () => uuidv4(),
    },
    authVersion: {
      type: Number,
      default: 1,
    },
    version: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true,
  }
)

/**
 * Optimistic concurrency check and atomic status transition.
 * Returns true if transition succeeded, throws error if invalid transition.
 */
ContainmentActionSchema.methods.transitionTo = function (newStatus, updates = {}) {
  const currentStatus = this.enforcementStatus
  const allowed = VALID_TRANSITIONS[currentStatus] || []

  if (!allowed.includes(newStatus)) {
    const error = new Error(`Invalid containment transition from '${currentStatus}' to '${newStatus}'`)
    error.statusCode = 400
    error.name = 'InvalidTransitionError'
    throw error
  }

  this.enforcementStatus = newStatus
  this.version = (this.version || 0) + 1

  Object.assign(this, updates)
  return this
}

ContainmentActionSchema.statics.ENFORCEMENT_STATUSES = ENFORCEMENT_STATUSES
ContainmentActionSchema.statics.TARGET_TYPES = TARGET_TYPES
ContainmentActionSchema.statics.ACTION_TYPES = ACTION_TYPES
ContainmentActionSchema.statics.POLICY_DECISIONS = POLICY_DECISIONS
ContainmentActionSchema.statics.ENFORCEMENT_BACKENDS = ENFORCEMENT_BACKENDS
ContainmentActionSchema.statics.VALID_TRANSITIONS = VALID_TRANSITIONS

module.exports = mongoose.model('ContainmentAction', ContainmentActionSchema)
