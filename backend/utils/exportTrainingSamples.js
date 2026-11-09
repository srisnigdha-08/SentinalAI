'use strict'
/**
 * Exports analyst-approved training samples (status ELIGIBLE_FOR_TRAINING) as JSON Lines for
 * ai-engine/training/retrain_from_samples.py. Read-only: nothing in MongoDB is changed.
 *
 *   node utils/exportTrainingSamples.js --out ../ai-engine/datasets/training_samples.jsonl
 *
 * Each line: {"sampleHash", "label", "featureVector": [53 numbers], "featureSchemaVersion", "sourcePredictionId"}
 */
require('dotenv').config({ path: process.env.DOTENV_CONFIG_PATH || require('path').join(__dirname, '..', '.env') })
const fs = require('fs')
const path = require('path')
const mongoose = require('mongoose')
const TrainingSample = require('../models/TrainingSample')

const EXPORTABLE_STATUS = 'ELIGIBLE_FOR_TRAINING'

const toLine = (s) =>
  JSON.stringify({
    sampleHash: s.sampleHash,
    label: s.groundTruthLabel,
    featureVector: s.featureVector,
    featureSchemaVersion: s.featureSchemaVersion,
    sourcePredictionId: s.sourcePredictionId ? String(s.sourcePredictionId) : null,
  })

/** Streams eligible samples to `outPath`; returns the number written. */
const exportEligibleSamples = async (outPath) => {
  fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true })
  const out = fs.createWriteStream(outPath, { encoding: 'utf8' })
  let count = 0
  const cursor = TrainingSample.find({ status: EXPORTABLE_STATUS }).select('+featureVector').lean().cursor()
  for await (const sample of cursor) {
    out.write(toLine(sample) + '\n')
    count++
  }
  await new Promise((resolve, reject) => out.end((err) => (err ? reject(err) : resolve())))
  return count
}

if (require.main === module) {
  const argIndex = process.argv.indexOf('--out')
  const outPath =
    argIndex > -1
      ? process.argv[argIndex + 1]
      : path.join(__dirname, '..', '..', 'ai-engine', 'datasets', 'training_samples.jsonl')
  mongoose
    .connect(process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db', { serverSelectionTimeoutMS: 5000 })
    .then(() => exportEligibleSamples(outPath))
    .then((count) => {
      console.log(`Exported ${count} ${EXPORTABLE_STATUS} training samples to ${outPath}`)
      return mongoose.disconnect()
    })
    .catch((err) => {
      console.error(`Export failed: ${err.message}`)
      process.exitCode = 1
      return mongoose.disconnect()
    })
}

module.exports = { exportEligibleSamples, EXPORTABLE_STATUS }
