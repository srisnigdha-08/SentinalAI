require('dotenv').config({ path: process.env.DOTENV_CONFIG_PATH || require('path').join(__dirname, '.env') })

const { validateEnv } = require('./config/validateEnv')
validateEnv()
const express = require('express')
const http = require('http')
const { Server } = require('socket.io')
const cors = require('cors')
const helmet = require('helmet')
const morgan = require('morgan')
const rateLimit = require('express-rate-limit')
const compression = require('compression')
const mongoSanitize = require('express-mongo-sanitize')
const connectDB = require('./config/db')
const logger = require('./utils/logger')
const socketManager = require('./websocket/socketManager')
const { errorHandler, notFound } = require('./middleware/errorHandler')
const app = express()
// Preserve Express 4's nested query parsing semantics during the v5 migration.
app.set('query parser', 'extended')
const securityTopology = require('./config/securityTopology')
const authTopology = securityTopology.topology()
app.set('trust proxy', securityTopology.trustedProxy())
const server = http.createServer(app)
const io = new Server(server, {
  allowRequest: (req, callback) =>
    callback(
      null,
      securityTopology.secureTransport(req, app.get('trust proxy fn')) &&
        (!req.headers.origin || require('./middleware/authCookies').allowedOrigins().includes(req.headers.origin))
    ),
  cors: { origin: require('./middleware/authCookies').allowedOrigins(), methods: ['GET', 'POST'], credentials: true },
  pingTimeout: 60000,
  pingInterval: 25000,
})

require('./websocket/auth').install(io)
const authSessions = require('./services/authSessionService')
const revocationDelivery = require('./services/revocationDelivery').createRevocationDelivery({
  mode: authTopology.mode,
  connection: require('mongoose').connection,
  disconnectSession: authSessions.disconnectSession,
  disconnectUser: authSessions.disconnectUser,
  disconnectAll: () => io.disconnectSockets(true),
  logger,
})
authSessions.setAvailability(revocationDelivery.available)
app.set('io', io)
socketManager.init(io)
app.use(helmet({ crossOriginEmbedderPolicy: false, contentSecurityPolicy: false }))
app.use(
  cors({
    origin: require('./middleware/authCookies').allowedOrigins(),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-CSRF-Token'],
  })
)
app.use('/api', securityTopology.requireSecureApi)
const lim = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 10000,
  message: { success: false, error: 'Too many requests' },
  skip: (req) => {
    const key = req.headers['x-api-key']
    return Boolean(
      key &&
      ((process.env.HONEYPOT_API_KEY && key === process.env.HONEYPOT_API_KEY) ||
        (process.env.SENTINEL_KEY && key === process.env.SENTINEL_KEY))
    )
  },
})
const { defaultShutdownManager } = require('./utils/gracefulShutdown')
app.use(defaultShutdownManager.middleware())
const authLim = rateLimit({ windowMs: 900000, max: 100, message: { success: false, error: 'Too many auth attempts' } })
app.use('/api', lim)
app.use('/api/auth/login', authLim)
app.use('/api/auth/register', authLim)
app.use('/api/auth/provision', authLim)
app.use('/api/auth/refresh-token', authLim)
app.use('/api/auth/logout', authLim)
app.use('/api/auth/logout-all', authLim)
require('./middleware/authCookies').policy()
logger.info(
  'Session-auth cutover: sign-in required; access tokens expire in 15 minutes. Legacy JWT_EXPIRES_IN does not control session tokens.'
)
app.use(compression())
app.use(express.json({ limit: '10kb' }))
app.use(express.urlencoded({ extended: true, limit: '10kb' }))
const mongoSanitizeMiddleware = mongoSanitize()
app.use((req, res, next) => {
  // Express 5 exposes req.query as a getter. The sanitizer rewrites req.query,
  // so snapshot it as a writable, request-local property before sanitizing.
  Object.defineProperty(req, 'query', {
    configurable: true,
    enumerable: true,
    writable: true,
    value: req.query,
  })
  mongoSanitizeMiddleware(req, res, next)
})
if (process.env.NODE_ENV === 'development') app.use(morgan('dev'))
else app.use(morgan('combined', { stream: { write: (msg) => logger.info(msg.trim()) } }))
app.get('/', (_, res) =>
  res.status(200).json({
    status: 'ok',
    service: 'SentinelAI API',
    message: 'SentinelAI Backend is running. Access endpoints under /api',
    health: '/health',
    timestamp: new Date().toISOString(),
  })
)
app.get('/health', async (_, res) => {
  const mongoose = require('mongoose')
  const aiSvc = require('./services/aiEngineService')

  let aiHealth = { status: 'unknown' }
  try {
    aiHealth = await aiSvc.getHealth()
  } catch (e) {
    aiHealth = { status: 'unreachable', error: e.message }
  }

  const ready = mongoose.connection.readyState === 1 && aiHealth?.status === 'ok' && revocationDelivery.available()
  res.status(ready ? 200 : 503).json({
    status: ready ? 'ok' : 'unavailable',
  })
})
const { protect: authProtect, requirePermission: authRequirePermission } = require('./middleware/auth')

app.get('/api/system/health', authProtect, authRequirePermission('system:telemetry_full'), async (_, res) => {
  const mongoose = require('mongoose')
  const aiSvc = require('./services/aiEngineService')
  const honeypotSvc = require('./services/honeypotService')
  const mem = process.memoryUsage()

  let aiHealth = { status: 'unknown' }
  try {
    aiHealth = await aiSvc.getHealth()
  } catch (e) {
    aiHealth = { status: 'unreachable', error: e.message }
  }

  let nodes = []
  try {
    nodes = await honeypotSvc.getNodeStatus()
  } catch {
    nodes = []
  }

  res.json({
    success: true,
    data: {
      mode: 'REAL_MODE',
      environment: process.env.NODE_ENV || 'development',
      uptime: Math.floor(process.uptime()),
      memory: {
        heapUsedMB: Math.round(mem.heapUsed / 1024 / 1024),
        heapTotalMB: Math.round(mem.heapTotal / 1024 / 1024),
        rssMB: Math.round(mem.rss / 1024 / 1024),
        pct: Math.round((mem.heapUsed / mem.heapTotal) * 100),
      },
      database: {
        status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        name: mongoose.connection.name || 'sentinel-db',
      },
      aiEngine: {
        status: aiHealth?.status === 'ok' ? 'connected' : 'unreachable',
      },
      honeypot: {
        activeNodes: nodes.filter((n) => n.status === 'active').length,
        totalNodes: nodes.length,
        nodes,
      },
      websocket: {
        connectedClients: io.engine.clientsCount,
      },
      timestamp: new Date().toISOString(),
    },
  })
})
app.get('/api/ws/stats', authProtect, authRequirePermission('system:telemetry_full'), (_, res) =>
  res.json({ success: true, data: socketManager.getStats() })
)


if (process.env.NODE_ENV !== 'production') {
  try {
    const { swaggerUi, swaggerSpec } = require('./config/swagger')
    app.get('/api/docs.json', (_, res) => res.status(200).json(swaggerSpec))
    app.use(
      '/api/docs',
      swaggerUi.serve,
      swaggerUi.setup(swaggerSpec, {
        customCss: '.swagger-ui .topbar { display: none }',
        customSiteTitle: 'SentinelAI API Documentation',
      })
    )
  } catch (e) {
    logger.debug('[Swagger] Swagger docs not initialized: ' + e.message)
  }
} else {
  app.use('/api/docs', (req, res) => res.status(404).json({ success: false, error: 'Documentation disabled in production' }))
  app.get('/api/docs.json', (req, res) => res.status(404).json({ success: false, error: 'Documentation disabled in production' }))
}

app.use('/api/auth', require('./routes/auth'))
app.use('/api/threats', require('./routes/threats'))
app.use('/api/containment', require('./routes/containment'))
app.use('/api/honeypot/ingest', require('./routes/honeypotIngest'))
app.use('/api/honeypot', require('./routes/honeypot'))
app.use('/api/campaigns', require('./routes/campaigns'))
app.use('/api/alerts', require('./routes/alerts'))
app.use('/api/users', require('./routes/users'))
app.use('/api/ai', require('./routes/aiEngine'))
app.use('/api/training-samples', require('./routes/trainingSamples'))
app.use('/api/system/outbox', require('./routes/systemOutbox'))
app.use('/api/audit', require('./routes/audit'))
app.use(notFound)

app.use(errorHandler)
const PORT = process.env.PORT || 5000
if (process.env.NODE_ENV !== 'test') {
  connectDB()
    .then(async () => {
      await revocationDelivery.start()
      logger.info('Authentication revocation mode: ' + authTopology.mode)
      try {
        const { defaultReconciliationService } = require('./services/containmentReconciliationService')
        defaultReconciliationService.start()
      } catch (recErr) {
        logger.warn('[ContainmentReconciliation] Failed to start reconciliation service: ' + recErr.message)
      }
      server.listen(PORT, process.env.HOST || '127.0.0.1', () => {
        logger.info('SentinelAI Backend ready on port ' + PORT)
      })
    })
    .catch(() => process.exit(1))
}
defaultShutdownManager.setServer(server)
defaultShutdownManager.setIO(io)
defaultShutdownManager.setMongoose(require('mongoose'))
defaultShutdownManager.registerService({
  name: 'healthBroadcast',
  stop: () => socketManager.stopHealthBroadcast(),
})
defaultShutdownManager.registerService({
  name: 'revocationDelivery',
  stop: () => revocationDelivery.stop().catch(() => {}),
})
defaultShutdownManager.registerService({
  name: 'containmentReconciliation',
  stop: () => {
    try {
      const { defaultReconciliationService } = require('./services/containmentReconciliationService')
      defaultReconciliationService.stop()
    } catch {}
  },
})

if (process.env.NODE_ENV !== 'test') {
  defaultShutdownManager.attachSignalHandlers()
}

module.exports = { app, server, io, revocationDelivery, defaultShutdownManager }
