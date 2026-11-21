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
    // Where a network flow came from (docs/CAPTURE.md). Set by the server from the route that received it, never
    // trusted from an analyst: live_passive / pcap_replay only from the capture service's key, dataset_replay /
    // manual from /api/ai/analyze. Absent on older records, which the Trust Meter reports as unknown.
    captureSource: {
      type: String,
      enum: ['live_passive', 'pcap_replay', 'dataset_replay', 'manual', 'unknown'],
      default: undefined,
    },
    sourceIP: { type: String },
    // Optional sender-chosen id of a network flow (POST /api/honeypot/ingest/flow). A retried or replayed request with
    // the same flowId returns the stored prediction instead of creating a second prediction and threat.
    flowId: { type: String, maxlength: 128, default: undefined },
    targetIP: String,
    predictedClass: { type: String, required: true },
    classProbabilities: { type: Map, of: Number },
    threatScore: { type: Number, required: true, min: 0, max: 1 },
    // Rank 8: the served classifier is XGBoost. 'xgboost' / 'stacking' / 'unknown' are added; 'ensemble' and
    // 'random_forest' stay valid so existing records still validate. A record created without model fields is
    // 'unknown', no longer silently labelled as a Random Forest.
    modelVersion: { type: String, default: 'unknown' },
    modelType: {
      type: String,
      enum: ['isolation_forest', 'random_forest', 'ensemble', 'xgboost', 'stacking', 'rules', 'unknown'],
      default: 'unknown',
    },
    isAnomaly: { type: Boolean, default: false },
    // The pipeline's decision for this flow (aiEngineService.runFullPipeline). Absent on records stored before it was kept.
    action: { type: String, enum: ['ALLOW', 'MONITOR', 'BLOCK', 'REVIEW'], default: undefined },
    // Classifier said BENIGN but the anomaly tier flagged it strongly (engine action REVIEW): analyst queue,
    // never a threat or a block. Cleared by verification.
    needsReview: { type: Boolean, default: false },
    // More than the engine's allowed number of features were filled with defaults (M2): never auto-blocked
    incompleteInput: { type: Boolean, default: false },
    // Source IP attacked the honeypot within HONEYPOT_CORROBORATION_DAYS (U4); BENIGN/Unknown ones are queued
    honeypotCorroborated: { type: Boolean, default: false },
    // Raw features the engine recorded as not sent (scored with serving defaults). Absent on records stored before
    // it was kept: their completeness is unknown, not complete. Metadata only; never read by scoring or blocking.
    defaultedFeatures: { type: [String], default: undefined },
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
// One prediction per flowId; predictions without one (every existing record, other routes) are not indexed.
AIPredictionSchema.index({ flowId: 1 }, { unique: true, partialFilterExpression: { flowId: { $type: 'string' } } })
module.exports = mongoose.model('AIPrediction', AIPredictionSchema)
