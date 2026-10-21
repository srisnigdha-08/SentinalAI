const mongoose = require('mongoose')
const { CANONICAL_CLASSES } = require('../utils/canonicalClasses')

const VerificationHistorySchema = new mongoose.Schema(
  {
    verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    actualClass: { type: String, enum: CANONICAL_CLASSES, required: true },
    verifiedAt: { type: Date, required: true },
  },
  { _id: false }
)

const AIPredictionSchema = new mongoose.Schema(
  {
    inputSource: { type: String, enum: ['network_traffic', 'honeypot_log', 'system_log', 'manual'], required: true },
    sourceIP: { type: String },
    targetIP: String,
    predictedClass: { type: String, required: true },
    classProbabilities: { type: Map, of: Number },
    threatScore: { type: Number, required: true, min: 0, max: 1 },
    modelVersion: { type: String, default: 'rf_classifier_v2.1' },
    modelType: {
      type: String,
      enum: ['isolation_forest', 'random_forest', 'ensemble', 'rules'],
      default: 'random_forest',
    },
    isAnomaly: { type: Boolean, default: false },
    // Classifier said BENIGN but the anomaly tier flagged it strongly (engine action REVIEW): analyst queue,
    // never a threat or a block. Cleared by verification.
    needsReview: { type: Boolean, default: false },
    // More than the engine's allowed number of features were filled with defaults (M2): never auto-blocked
    incompleteInput: { type: Boolean, default: false },
    anomalyScore: { type: Number, min: -1, max: 1 },
    featureImportance: { type: Map, of: Number, select: false },
    inferenceTimeMs: Number,
    verified: { type: Boolean, default: false },
    verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    verifiedAt: { type: Date },
    actualClass: { type: String, enum: CANONICAL_CLASSES },
    verificationHistory: { type: [VerificationHistorySchema], default: [] },
    generatedThreat: { type: mongoose.Schema.Types.ObjectId, ref: 'ThreatLog' },
    rawFeatures: { type: mongoose.Schema.Types.Mixed },
    featureVector: { type: [Number], select: false },
    featureSchemaVersion: { type: String, select: false },
  },
  {
    timestamps: true,
    toJSON: {
      transform: (doc, ret) => {
        delete ret.featureVector
        delete ret.featureSchemaVersion
        return ret
      },
    },
    toObject: {
      transform: (doc, ret) => {
        delete ret.featureVector
        delete ret.featureSchemaVersion
        return ret
      },
    },
  }
)
AIPredictionSchema.index({ createdAt: -1 })
AIPredictionSchema.index({ threatScore: -1 })
AIPredictionSchema.index({ sourceIP: 1 })
// Verified-accuracy aggregate (all-time) reads only analyst-verified predictions
AIPredictionSchema.index({ verified: 1 })
module.exports = mongoose.model('AIPrediction', AIPredictionSchema)
