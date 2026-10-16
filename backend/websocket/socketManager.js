const reportTime = require('../utils/reportingTime')
const logger = require('../utils/logger')
const ThreatLog = require('../models/ThreatLog')
const clients = new Map()
let _io = null

const init = (io) => {
  _io = io
  io.on('connection', (socket) => {
    const verifiedRole = socket.role || socket.user?.role || 'viewer'
    const verifiedUserId = socket.user?._id?.toString() || socket.user?.id || null
    logger.info(`[WS] Connected: ${socket.id} (User: ${socket.user?.email || 'authenticated'}, Role: ${verifiedRole})`)

    socket.on('join_room', ({ role: claimedRole, userId } = {}) => {
      // Security: Bind strictly to the server-verified role from the JWT, ignore client claim
      socket.join(verifiedRole)
      socket.join('all')
      socket.join('threat_subscribers')
      clients.set(socket.id, {
        userId: verifiedUserId || userId,
        role: verifiedRole,
        rooms: [verifiedRole, 'all', 'threat_subscribers'],
        connectedAt: new Date(),
      })
      if (claimedRole && claimedRole !== verifiedRole) {
        logger.warn(
          `[WS] ${socket.id} claimed role '${claimedRole}' but was overridden to verified role '${verifiedRole}'`
        )
      }
      logger.info(`[WS] ${socket.id} joined: ${verifiedRole}`)
      socket.emit('connected', { socketId: socket.id, room: verifiedRole, timestamp: new Date().toISOString() })
    })
    socket.on('subscribe_threats', () => {
      socket.join('threat_subscribers')
      socket.emit('subscribed', { channel: 'threats' })
    })
    socket.on('request_stats', async () => {
      try {
        const now = new Date()
        const today = reportTime.filter(1, now)
        const [total, critical, blocked] = await Promise.all([
          ThreatLog.countDocuments({ createdAt: today }),
          ThreatLog.countDocuments({ severity: 'CRITICAL', createdAt: today }),
          ThreatLog.countDocuments({ status: 'BLOCKED' }),
        ])
        socket.emit('stats_snapshot', {
          totalToday: total,
          critical,
          blocked,
          reporting: reportTime.metadata(1, now),
          timestamp: new Date().toISOString(),
        })
      } catch (e) {
        logger.debug('[WS] stats err: ' + e.message)
      }
    })
    socket.on('ping_sentinel', () => socket.emit('pong_sentinel', { timestamp: new Date().toISOString() }))
    socket.on('disconnect', (reason) => {
      clients.delete(socket.id)
      logger.info('[WS] Disconnected: ' + socket.id + ' (' + reason + ')')
    })
    socket.on('error', (e) => logger.error('[WS] Error ' + socket.id + ': ' + e.message))
  })
  startHealthBroadcast(io)
  logger.info('[WS] Socket.IO initialized')
}

const emitNewThreat = (threat) => {
  if (!_io) return
  const p = {
    _id: threat._id?.toString(),
    id: threat._id?.toString(),
    severity: threat.severity,
    sourceIP: threat.sourceIP,
    attackType: threat.attackType,
    aiScore: threat.aiScore,
    status: threat.status,
    targetService: threat.targetService || 'INTERNAL',
    createdAt: threat.createdAt || new Date(),
    timestamp: threat.createdAt || new Date(),
  }
  _io.to(['threat_subscribers', 'all']).emit('new_threat', p)
  _io.to('all').emit('live_feed_event', {
    type: 'threat',
    sev: threat.severity,
    ip: threat.sourceIP,
    msg: threat.attackType + ' detected - score ' + Math.round((threat.aiScore || 0) * 100) + '%',
    timestamp: new Date().toISOString(),
  })
  if (threat.severity === 'CRITICAL') _io.to('admin').emit('critical_alert', { ...p, urgency: 'IMMEDIATE' })
}
const emitThreatUpdated = (threat) => {
  if (!_io) return
  _io.to('all').emit('threat_updated', {
    id: threat._id?.toString(),
    status: threat.status,
    sourceIP: threat.sourceIP,
    timestamp: new Date().toISOString(),
  })
}
const emitThreatIntelUpdated = ({ threatId, sourceIP, threatIntel }) => {
  if (!_io) return
  _io.to('all').emit('threat_intel_updated', {
    threatId: threatId?.toString(),
    sourceIP,
    threatIntel,
    timestamp: new Date().toISOString(),
  })
}
const emitIPBlocked = (ip, by, threatId) => {
  if (!_io) return
  _io.to('all').emit('ip_blocked', { ip, blockedBy: by, threatId, timestamp: new Date().toISOString() })
  _io.to('all').emit('live_feed_event', {
    type: 'block',
    sev: 'HIGH',
    ip,
    msg: 'IP ' + ip + ' blocked',
    timestamp: new Date().toISOString(),
  })
}
const emitIPUnblocked = (ip, by) => {
  if (!_io) return
  _io.to('all').emit('ip_unblocked', { ip, unblockedBy: by, timestamp: new Date().toISOString() })
  _io.to('all').emit('live_feed_event', {
    type: 'unblock',
    sev: 'INFO',
    ip,
    msg: 'IP ' + ip + ' unblocked',
    timestamp: new Date().toISOString(),
  })
}
const emitNewAlert = (alert) => {
  if (!_io) return
  const p = {
    id: alert._id?.toString(),
    title: alert.title,
    message: alert.message,
    severity: alert.severity,
    type: alert.type,
    timestamp: alert.createdAt || new Date(),
  }
  const rooms = alert.targetRoles || ['analyst']
  _io.to(alert.severity === 'CRITICAL' ? [...rooms, 'all'] : rooms).emit('new_alert', p)
}
const emitAIPrediction = (p) => {
  if (!_io) return
  _io.to('all').emit('ai_prediction', {
    _id: p._id?.toString(),
    id: p._id?.toString(),
    sourceIP: p.sourceIP,
    predictedClass: p.predictedClass,
    threatScore: p.threatScore,
    severity:
      p.severity ||
      (p.threatScore >= 0.85 ? 'CRITICAL' : p.threatScore >= 0.7 ? 'HIGH' : p.threatScore >= 0.4 ? 'MEDIUM' : 'LOW'),
    action: p.action || (p.threatScore >= 0.92 ? 'BLOCK' : p.threatScore >= 0.7 ? 'MONITOR' : 'ALLOW'),
    modelType: p.modelType || 'random_forest',
    modelVersion: p.modelVersion || 'v2.1',
    isAnomaly: p.isAnomaly || false,
    anomalyScore: p.anomalyScore || 0,
    inferenceTimeMs: p.inferenceTimeMs ?? null,
    createdAt: (p.createdAt || new Date()).toISOString(),
    timestamp: (p.createdAt || new Date()).toISOString(),
  })
}
const emitHoneypotEvent = (eventType, data) => {
  if (!_io) return
  _io.to('all').emit(eventType, { ...data, timestamp: new Date().toISOString() })
  const msgs = {
    honeypot_session_opened: 'Honeypot session from ' + data.sourceIP + ' on ' + data.honeypotNode,
    honeypot_command: 'Command: ' + (data.command || '').slice(0, 60),
    honeypot_session_closed: 'Session closed: ' + data.sourceIP + ' (' + data.durationSeconds + 's)',
    malware_download: 'Malware: ' + data.sourceIP + ' -> ' + data.url,
  }
  if (msgs[eventType])
    _io.to('all').emit('live_feed_event', {
      type: 'honeypot',
      sev: eventType === 'malware_download' ? 'CRITICAL' : 'HIGH',
      ip: data.sourceIP,
      msg: msgs[eventType],
      timestamp: new Date().toISOString(),
    })
}
const emitToRoom = (room, event, data) => {
  if (_io) _io.to(room).emit(event, { ...data, timestamp: new Date().toISOString() })
}

let healthTimer = null
const startHealthBroadcast = (io) => {
  if (healthTimer) clearInterval(healthTimer)
  healthTimer = setInterval(async () => {
    if (io.engine.clientsCount === 0) return
    try {
      const mem = process.memoryUsage()
      const now = new Date()
      const today = reportTime.filter(1, now)
      const [td] = await Promise.all([ThreatLog.countDocuments({ createdAt: today })])
      io.to('all').emit('system_health', {
        memory: {
          heapUsed: Math.round(mem.heapUsed / 1024 / 1024),
          heapTotal: Math.round(mem.heapTotal / 1024 / 1024),
          rss: Math.round(mem.rss / 1024 / 1024),
          heapPercent: Math.round((mem.heapUsed / mem.heapTotal) * 100),
        },
        uptime: Math.floor(process.uptime()),
        connectedClients: io.engine.clientsCount,
        threatsToday: td,
        reporting: reportTime.metadata(1, now),
        timestamp: new Date().toISOString(),
      })
    } catch (e) {
      logger.debug('[WS] health err: ' + e.message)
    }
  }, 15000)
}

const stopHealthBroadcast = () => {
  if (healthTimer) {
    clearInterval(healthTimer)
    healthTimer = null
  }
}

const getStats = () => ({
  connectedClients: clients.size,
  clients: Array.from(clients.entries()).map(([id, m]) => ({ socketId: id, role: m.role, connectedAt: m.connectedAt })),
})
module.exports = {
  init,
  emitNewThreat,
  emitThreatUpdated,
  emitThreatIntelUpdated,
  emitIPBlocked,
  emitIPUnblocked,
  emitNewAlert,
  emitAIPrediction,
  emitHoneypotEvent,
  emitToRoom,
  startHealthBroadcast,
  stopHealthBroadcast,
  getStats,
}
