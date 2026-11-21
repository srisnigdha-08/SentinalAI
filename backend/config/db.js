const mongoose = require('mongoose')
const logger = require('../utils/logger')
const positiveInt = (value, fallback) => {
  const n = parseInt(value, 10)
  return Number.isInteger(n) && n > 0 ? n : fallback
}
const ensureDefaultAdmin = async () => {
  try {
    const adminPassword = process.env.ADMIN_INITIAL_PASSWORD
    if (!adminPassword || !adminPassword.trim()) {
      logger.info('ADMIN_INITIAL_PASSWORD is not configured. Skipping default administrator auto-provisioning.')
      return
    }
    const adminEmail = (process.env.ADMIN_EMAIL || 'admin@sentinel.io').toLowerCase().trim()
    const User = require('../models/User')
    const count = await User.countDocuments({ email: adminEmail })
    if (count === 0) {
      await User.create({
        name: process.env.ADMIN_NAME || 'Admin User',
        email: adminEmail,
        password: adminPassword.trim(),
        role: 'admin',
        status: 'active',
        department: process.env.ADMIN_DEPARTMENT || 'SOC',
      })
      logger.info(`Administrator account provisioned for: ${adminEmail}`)
    }
  } catch (err) {
    logger.error('Failed to auto-provision default admin: ' + err.message)
  }
}

const nonNegativeInt = (value, fallback) => {
  const n = parseInt(value, 10)
  return Number.isInteger(n) && n >= 0 ? n : fallback
}
// Start-up retry: MongoDB starting a moment after the backend (service restart, container order) is not fatal.
// MONGO_CONNECT_RETRIES extra attempts (default 5; 0 = fail on the first error), backoff 1 s, 2 s, 4 s ... capped at 15 s.
const backoffMs = (attempt) => Math.min(1000 * 2 ** attempt, 15000)

const connectDB = async () => {
  const retries = nonNegativeInt(process.env.MONGO_CONNECT_RETRIES, 5)
  for (let attempt = 0; ; attempt++) {
    try {
      const c = await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db', {
        maxPoolSize: positiveInt(process.env.MONGO_MAX_POOL_SIZE, 10),
        serverSelectionTimeoutMS: positiveInt(process.env.MONGO_SERVER_SELECTION_TIMEOUT_MS, 5000),
      })
      logger.info('MongoDB connected: ' + c.connection.host + '/' + c.connection.name)
      break
    } catch (err) {
      // Only the error class is logged: driver messages can contain the connection string.
      if (attempt >= retries) {
        logger.error('MongoDB connection failed (' + err.name + ') after ' + (attempt + 1) + ' attempt(s)')
        throw err
      }
      const wait = backoffMs(attempt)
      logger.warn(`MongoDB connection failed (${err.name}); retry ${attempt + 1}/${retries} in ${wait} ms`)
      await connectDB.sleep(wait)
    }
  }
  await ensureDefaultAdmin()
}
connectDB.sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
connectDB.backoffMs = backoffMs
mongoose.connection.on('disconnected', () => logger.warn('MongoDB disconnected'))
mongoose.connection.on('reconnected', () => logger.info('MongoDB reconnected'))
connectDB.ensureDefaultAdmin = ensureDefaultAdmin
module.exports = connectDB
