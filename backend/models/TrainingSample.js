'use strict'

const mongoose = require('mongoose')
const { CANONICAL_CLASSES } = require('../utils/canonicalClasses')

const VALID_STATUSES = Object.freeze(['QUARANTINED', 'VALIDATED', 'ELIGIBLE_FOR_TRAINING', 'REJECTED', 'SUPERSEDED'])

const TrainingSampleSchema = new mongoose.Schema(
  {
    // Provenance Linkage to originating operational inference
    sourcePredictionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'AIPrediction',
      required: true,
      index: true,
    },
    sourceVerificationIndex: {
      type: Number,
      required: true,
      default: 0,
    },

    // Immutable Feature Vector (Strictly Masked from normal API queries)
    featureVector: {
      type: [Number],
      required: true,
      select: false,
      validate: {
        validator: function (v) {
          return Array.isArray(v) && v.length === 53 && v.every((n) => typeof n === 'number' && Number.isFinite(n))
        },
        message: 'featureVector must be an array of exactly 53 finite numbers',
      },
    },
    featureSchemaVersion: {
      type: String,
      required: true,
      default: 'v2.1_53feat',
      trim: true,
    },

    // Deterministic Cryptographic Hash of (featureSchemaVersion | groundTruthLabel | canonicalFeatureString)
    sampleHash: {
      type: String,
      required: true,
      index: true,
    },

    // Ground Truth & Original Classification Context
    groundTruthLabel: {
      type: String,
      required: true,
      enum: CANONICAL_CLASSES,
      index: true,
    },
    predictedClass: {
      type: String,
      required: true,
    },
    threatScore: {
      type: Number,
      required: true,
      min: 0,
      max: 1,
    },
    modelVersion: {
      type: String,
      required: true,
    },
    inputSource: {
      type: String,
      enum: ['network_traffic', 'honeypot_log', 'system_log', 'manual'],
      default: 'network_traffic',
    },
    sourceIP: {
      type: String,
      default: null,
    },
    targetIP: {
      type: String,
      default: null,
    },

    // Quarantine Lifecycle State Machine
    status: {
      type: String,
      enum: VALID_STATUSES,
      default: 'QUARANTINED',
      required: true,
      index: true,
    },
    quarantinedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
    cooldownExpiresAt: {
      type: Date,
      default: null,
    },

    // Ground-Truth Attribution & Dual-Control Audit
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    verifiedAt: {
      type: Date,
      required: true,
    },
    validatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    validatedAt: {
      type: Date,
      default: null,
    },

    // Invalidation Details (Rejection or Supersession)
    rejectionReason: {
      type: String,
      default: null,
    },
    supersededAt: {
      type: Date,
      default: null,
    },
    supersededReason: {
      type: String,
      default: null,
    },

    // Deduplication & Cluster Frequency Tracker
    duplicateCount: {
      type: Number,
      default: 1,
      min: 1,
    },
  },
  {
    timestamps: true,
    toJSON: {
      transform: (doc, ret) => {
        delete ret.featureVector
        return ret
      },
    },
    toObject: {
      transform: (doc, ret) => {
        delete ret.featureVector
        return ret
      },
    },
  }
)

// Compound Indexes for State Queries and Provenance
TrainingSampleSchema.index({ sourcePredictionId: 1, status: 1 })
TrainingSampleSchema.index({ sampleHash: 1, groundTruthLabel: 1 })
TrainingSampleSchema.index({ status: 1, groundTruthLabel: 1 })

module.exports = mongoose.model('TrainingSample', TrainingSampleSchema)
module.exports.VALID_STATUSES = VALID_STATUSES
