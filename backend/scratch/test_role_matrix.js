'use strict'

process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-test-jwt-secret-role-matrix'
process.env.JWT_REFRESH_SECRET = 'unit-test-refresh-secret-role-matrix'
process.env.HONEYPOT_API_KEY = 'unit-test-honeypot-key-role-matrix'
process.env.SENTINEL_KEY = 'unit-test-sentinel-key-role-matrix'

const mongoose = require('mongoose')

// Mock models and services
const routerMap = new Map([
  [require('../routes/auth'), '/api/auth'],
  [require('../routes/threats'), '/api/threats'],
  [require('../routes/containment'), '/api/containment'],
  [require('../routes/honeypotIngest'), '/api/honeypot/ingest'],
  [require('../routes/honeypot'), '/api/honeypot'],
  [require('../routes/campaigns'), '/api/campaigns'],
  [require('../routes/alerts'), '/api/alerts'],
  [require('../routes/users'), '/api/users'],
  [require('../routes/aiEngine'), '/api/ai'],
  [require('../routes/trainingSamples'), '/api/training-samples'],
  [require('../routes/systemOutbox'), '/api/system/outbox'],
  [require('../routes/audit'), '/api/audit']
])

const { app } = require('../server')
const User = require('../models/User')
const ThreatLog = require('../models/ThreatLog')
const AuditLog = require('../models/AuditLog')
const SystemSetting = require('../models/SystemSetting')
const HoneypotSession = require('../models/HoneypotSession')
const Alert = require('../models/Alert')
const Campaign = require('../models/Campaign')
const BlockedIP = require('../models/BlockedIP')
const ContainmentAction = require('../models/ContainmentAction')
const TrainingSample = require('../models/TrainingSample')
const { defaultSecurityEventBus } = require('../utils/securityEventBus')
defaultSecurityEventBus.getOutboxStatus = () => Promise.resolve({ pending: 0, failed: 0 })
defaultSecurityEventBus.redriveFailedOutbox = () => Promise.resolve({ redriven: 0 })
const { accessToken } = require('../tests/helpers/accessFixture')
const request = require('supertest')

const adminId = new mongoose.Types.ObjectId().toString()
const analystId = new mongoose.Types.ObjectId().toString()
const viewerId = new mongoose.Types.ObjectId().toString()
const dummyId = new mongoose.Types.ObjectId().toString()

const tokens = {
  admin: accessToken({ _id: adminId, role: 'admin', authVersion: 0 }),
  analyst: accessToken({ _id: analystId, role: 'analyst', authVersion: 0 }),
  viewer: accessToken({ _id: viewerId, role: 'viewer', authVersion: 0 }),
  'no-token': null
}

function createChainableQuery(result) {
  const query = {}
  query.sort = () => query
  query.skip = () => query
  query.limit = () => query
  query.populate = () => query
  query.select = () => query
  query.lean = () => Promise.resolve(result)
  query.then = (resolve, reject) => Promise.resolve(result).then(resolve, reject)
  return query
}

User.findById = (id) => {
  const idStr = String(id)
  let role = 'viewer'
  if (idStr === adminId) role = 'admin'
  else if (idStr === analystId) role = 'analyst'
  return {
    select: () => Promise.resolve({
      _id: idStr,
      name: `${role} User`,
      email: `${role}@sentinel.io`,
      role,
      status: 'active',
      authVersion: 0,
      tokenVersion: 0,
      permissions: [],
    })
  }
}
User.find = () => createChainableQuery([])
User.countDocuments = () => Promise.resolve(0)

ThreatLog.find = () => createChainableQuery([{ _id: dummyId, sourceIP: '198.51.100.24', status: 'DETECTED' }])
ThreatLog.countDocuments = () => Promise.resolve(1)
ThreatLog.findById = () => createChainableQuery({ _id: dummyId, sourceIP: '198.51.100.24', status: 'DETECTED' })
ThreatLog.findByIdAndUpdate = () => Promise.resolve({ _id: dummyId, status: 'INVESTIGATING' })
ThreatLog.findByIdAndDelete = () => Promise.resolve({ _id: dummyId })

SystemSetting.findOne = () => Promise.resolve({ key: 'autoBlockEnabled', value: false })
SystemSetting.findOneAndUpdate = () => Promise.resolve({ key: 'autoBlockEnabled', value: true })

AuditLog.find = () => createChainableQuery([])
AuditLog.countDocuments = () => Promise.resolve(0)
AuditLog.create = () => Promise.resolve({})

HoneypotSession.find = () => createChainableQuery([{ _id: dummyId, sessionId: 's1' }])
HoneypotSession.countDocuments = () => Promise.resolve(1)
HoneypotSession.findById = () => createChainableQuery({ _id: dummyId, sessionId: 's1' })
HoneypotSession.create = () => Promise.resolve({ _id: dummyId })

Alert.find = () => createChainableQuery([{ _id: dummyId, title: 'Alert 1' }])
Alert.countDocuments = () => Promise.resolve(1)
Alert.findByIdAndDelete = () => Promise.resolve({ _id: dummyId })

Campaign.find = () => createChainableQuery([{ _id: dummyId, name: 'C1' }])
Campaign.countDocuments = () => Promise.resolve(1)
Campaign.findById = () => createChainableQuery({ _id: dummyId, name: 'C1' })

BlockedIP.find = () => createChainableQuery([])
BlockedIP.findOne = () => Promise.resolve(null)
BlockedIP.create = () => Promise.resolve({ ip: '198.51.100.99' })
BlockedIP.deleteOne = () => Promise.resolve({ deletedCount: 1 })

ContainmentAction.find = () => createChainableQuery([])
ContainmentAction.countDocuments = () => Promise.resolve(0)
ContainmentAction.findById = () => createChainableQuery({ _id: dummyId, status: 'ACTIVE' })

TrainingSample.find = () => createChainableQuery([])
TrainingSample.countDocuments = () => Promise.resolve(0)
TrainingSample.findById = () => createChainableQuery({ _id: dummyId, status: 'PENDING' })

OutboxMessage.find = () => createChainableQuery([])
OutboxMessage.countDocuments = () => Promise.resolve(0)

// Extract all endpoints
const endpoints = []
for (const layer of app.router.stack) {
  if (layer.route) {
    const methods = Object.keys(layer.route.methods)
    for (const m of methods) {
      endpoints.push({ method: m.toLowerCase(), path: layer.route.path })
    }
  } else if (layer.handle && routerMap.has(layer.handle)) {
    const prefix = routerMap.get(layer.handle)
    for (const sub of layer.handle.stack) {
      if (sub.route) {
        const methods = Object.keys(sub.route.methods)
        for (const m of methods) {
          const subPath = sub.route.path === '/' ? '' : sub.route.path
          endpoints.push({ method: m.toLowerCase(), path: `${prefix}${subPath}` })
        }
      }
    }
  }
}

console.log(`Testing ${endpoints.length} endpoints...`)

async function run() {
  const results = []
  for (const ep of endpoints) {
    const row = { method: ep.method, path: ep.path }
    const testUrl = ep.path.replace(':id', dummyId)
    for (const role of ['no-token', 'viewer', 'analyst', 'admin']) {
      try {
        let req = request(app)[ep.method](testUrl)
        if (tokens[role]) req = req.set('Authorization', `Bearer ${tokens[role]}`)
        const res = await req
        row[role] = res.status
      } catch (err) {
        row[role] = `ERR: ${err.message}`
      }
    }
    results.push(row)
  }
  console.log(JSON.stringify(results, null, 2))
  process.exit(0)
}

run().catch(err => {
  console.error(err)
  process.exit(1)
})
