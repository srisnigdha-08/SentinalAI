const mongoose = require('mongoose')
const logger = require('../utils/logger')
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

const connectDB = async () => {
  try {
    const c = await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/sentinel-db', {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
    })
    logger.info('MongoDB connected: ' + c.connection.host + '/' + c.connection.name)
    await ensureDefaultAdmin()
  } catch (err) {
    logger.error('MongoDB connection failed (' + err.name + ')')
    throw err
  }
}
mongoose.connection.on('disconnected', () => logger.warn('MongoDB disconnected'))
mongoose.connection.on('reconnected', () => logger.info('MongoDB reconnected'))
connectDB.ensureDefaultAdmin = ensureDefaultAdmin
module.exports = connectDB
