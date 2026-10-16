require('dotenv').config()
const mongoose = require('mongoose')
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db'

async function clean() {
  await mongoose.connect(MONGO_URI)
  const ThreatLog = require('../models/ThreatLog')
  const HoneypotSession = require('../models/HoneypotSession')
  const Alert = require('../models/Alert')
  const AIPrediction = require('../models/AIPrediction')
  const BlockedIP = require('../models/BlockedIP')
  const Campaign = require('../models/Campaign')
  const User = require('../models/User')

  await Promise.all([
    ThreatLog.deleteMany({}),
    HoneypotSession.deleteMany({}),
    Alert.deleteMany({}),
    AIPrediction.deleteMany({}),
    BlockedIP.deleteMany({}),
    Campaign.deleteMany({}),
  ])

  const userCount = await User.countDocuments()
  console.log(`\n=== Clean Complete ===\nSimulated telemetry data removed.\nUsers preserved: ${userCount}\n`)
  process.exit(0)
}

clean().catch((err) => {
  console.error('Clean failed:', err)
  process.exit(1)
})
